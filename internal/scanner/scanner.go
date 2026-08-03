package scanner

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	licenses "github.com/git-pkgs/licenses"
	"github.com/git-pkgs/magic"

	archivepkg "github.com/ecosyste-ms/licenses/internal/archive"
)

const maxScannerWorkers = 16

var defaultSkippedDirectories = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".bundle":      true,
	".venv":        true,
	"venv":         true,
	"target":       true,
	"build":        true,
	"dist":         true,
	"out":          true,
	"_build":       true,
	"deps":         true,
	"Pods":         true,
	"third_party":  true,
	"thirdparty":   true,
	"external":     true,
	"testdata":     true,
	"tmp":          true,
	"temp":         true,
	"cache":        true,
	"coverage":     true,
}

// Limits bounds the text scan and attribution response.
type Limits struct {
	MaxDepth            int
	MaxFiles            int
	MaxFileBytes        int64
	Workers             int
	MaxAttributionFiles int
	MaxAttributionBytes int64
}

// DefaultLimits returns the same project-scan limits as the scanner CLI plus
// explicit bounds for returned attribution text.
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:            32,
		MaxFiles:            10_000,
		MaxFileBytes:        1 << 20,
		Workers:             min(runtime.GOMAXPROCS(0), maxScannerWorkers),
		MaxAttributionFiles: 64,
		MaxAttributionBytes: 4 << 20,
	}
}

// Scanner downloads, extracts, and scans package archives.
type Scanner struct {
	Matcher       *licenses.Matcher
	ArchiveClient *archivepkg.Client
	ExtractLimits archivepkg.ExtractLimits
	Limits        Limits
}

// New initializes the embedded matcher once and returns a production scanner.
func New() (*Scanner, error) {
	matcher, err := licenses.New()
	if err != nil {
		return nil, fmt.Errorf("initialize license matcher: %w", err)
	}
	downloadLimits := archivepkg.DefaultDownloadLimits()
	return &Scanner{
		Matcher:       matcher,
		ArchiveClient: archivepkg.NewClient(downloadLimits),
		ExtractLimits: archivepkg.DefaultExtractLimits(),
		Limits:        DefaultLimits(),
	}, nil
}

// ScanURL performs a bounded synchronous scan of rawURL.
func (s *Scanner) ScanURL(ctx context.Context, rawURL string) (Report, error) {
	if err := s.validate(); err != nil {
		return Report{}, err
	}
	temporary, err := os.MkdirTemp("", "licenses-v2-*")
	if err != nil {
		return Report{}, fmt.Errorf("create scan workspace: %w", err)
	}
	defer os.RemoveAll(temporary)

	archivePath := filepath.Join(temporary, "archive")
	digest, err := s.ArchiveClient.Download(ctx, rawURL, archivePath)
	if err != nil {
		return Report{}, err
	}
	extracted, err := archivepkg.Extract(ctx, archivePath, filepath.Join(temporary, "extracted"), s.ExtractLimits)
	if err != nil {
		return Report{}, err
	}
	report, err := s.ScanDirectory(ctx, rawURL, digest, extracted.Root)
	if err != nil {
		return Report{}, err
	}
	for _, skipped := range extracted.Skipped {
		report.Skipped = append(report.Skipped, Skip{Path: skipped.Path, Reason: skipped.Reason})
	}
	sortReport(&report)
	return report, nil
}

func (s *Scanner) validate() error {
	if s == nil || s.Matcher == nil {
		return errors.New("license matcher is not configured")
	}
	if s.ArchiveClient == nil {
		return errors.New("archive client is not configured")
	}
	limits := s.Limits
	if limits.MaxDepth <= 0 || limits.MaxFiles <= 0 || limits.MaxFileBytes <= 0 ||
		limits.Workers <= 0 || limits.MaxAttributionFiles <= 0 || limits.MaxAttributionBytes <= 0 {
		return errors.New("all scanner limits must be positive")
	}
	return nil
}

// ScanDirectory scans an already extracted root. It is exported to support
// fixture comparison and downstream integration tests without networking.
func (s *Scanner) ScanDirectory(ctx context.Context, rawURL, archiveSHA, root string) (Report, error) {
	if err := s.validate(); err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	corpus := s.Matcher.Corpus()
	report := Report{
		Schema: ReportSchemaVersion,
		URL:    rawURL,
		SHA256: archiveSHA,
		Scanner: ScannerInfo{
			Name:    ScannerName,
			Version: ScannerVersion,
			Corpus: CorpusInfo{
				Version:      corpus.Version,
				SourceCommit: corpus.SourceCommit,
				RuleCount:    corpus.RuleCount,
			},
		},
		Summary: Summary{
			Complete:         true,
			RootExpressions:  make([]Expression, 0),
			OtherExpressions: make([]Expression, 0),
		},
		Declared:         make([]DeclaredLicense, 0),
		Files:            make([]File, 0),
		AttributionFiles: make([]AttributionFile, 0),
		Skipped:          make([]Skip, 0),
		Errors:           make([]ScanError, 0),
	}

	tasks, discoverySkipped, discoveryErrors, truncated, err := discoverFiles(ctx, root, s.Limits, &report.Summary)
	if err != nil {
		return Report{}, err
	}
	report.Skipped = append(report.Skipped, discoverySkipped...)
	report.Errors = append(report.Errors, discoveryErrors...)
	if len(discoveryErrors) > 0 {
		report.Summary.Complete = false
	}
	if truncated {
		report.Summary.Complete = false
	}

	outcomes := scanFiles(ctx, s.Matcher, tasks, s.Limits)
	rootExpressions := make(map[string]Expression)
	otherExpressions := make(map[string]Expression)
	var attribution []attributionCandidate
	for outcome := range outcomes {
		if outcome.scanned {
			report.Summary.FilesScanned++
			report.Summary.BytesScanned += outcome.bytes
		}
		switch {
		case outcome.err != nil:
			report.Summary.Complete = false
			report.Errors = append(report.Errors, ScanError{Path: outcome.task.display, Error: safeErrorMessage(outcome.err)})
		case outcome.binary:
			report.Skipped = append(report.Skipped, Skip{Path: outcome.task.display, Reason: "binary"})
		case outcome.tooLarge:
			report.Skipped = append(report.Skipped, Skip{Path: outcome.task.display, Reason: "size"})
		case outcome.file != nil:
			report.Files = append(report.Files, *outcome.file)
			addExpressions(outcome.task.display, outcome.file.Detections, rootExpressions, otherExpressions)
		}
		if outcome.attribution != nil {
			attribution = append(attribution, *outcome.attribution)
		}
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	report.Summary.RootExpressions = expressionValues(rootExpressions)
	report.Summary.OtherExpressions = expressionValues(otherExpressions)
	populateAttribution(&report, attribution, s.Limits)
	sortReport(&report)
	return report, nil
}

type fileTask struct {
	path    string
	display string
}

type fileOutcome struct {
	task        fileTask
	file        *File
	attribution *attributionCandidate
	bytes       int64
	scanned     bool
	binary      bool
	tooLarge    bool
	err         error
}

type attributionCandidate struct {
	path     string
	display  string
	roles    []string
	sha256   string
	encoding string
	size     int64
}

func discoverFiles(
	ctx context.Context,
	root string,
	limits Limits,
	summary *Summary,
) ([]fileTask, []Skip, []ScanError, bool, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("resolve scan root: %w", err)
	}
	var tasks []fileTask
	var skipped []Skip
	var scanErrors []ScanError
	truncated := false
	err = filepath.WalkDir(resolved, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, relErr := filepath.Rel(resolved, filePath)
		if relErr != nil {
			return relErr
		}
		display := filepath.ToSlash(relative)
		if walkErr != nil {
			if display == "." {
				return walkErr
			}
			scanErrors = append(scanErrors, ScanError{Path: display, Error: safeErrorMessage(walkErr)})
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if display == "." {
				return nil
			}
			if reason := skippedDirectoryReason(entry.Name()); reason != "" {
				skipped = append(skipped, Skip{Path: display, Reason: reason})
				return filepath.SkipDir
			}
			if pathDepth(display) > limits.MaxDepth {
				skipped = append(skipped, Skip{Path: display, Reason: "depth"})
				return filepath.SkipDir
			}
			return nil
		}
		if summary.FilesVisited >= limits.MaxFiles {
			truncated = true
			skipped = append(skipped, Skip{Path: display, Reason: "file-limit"})
			return fs.SkipAll
		}
		summary.FilesVisited++
		if entry.Type()&os.ModeSymlink != 0 {
			skipped = append(skipped, Skip{Path: display, Reason: "symlink"})
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			scanErrors = append(scanErrors, ScanError{Path: display, Error: safeErrorMessage(err)})
			return nil
		}
		if !info.Mode().IsRegular() {
			skipped = append(skipped, Skip{Path: display, Reason: "non-regular"})
			return nil
		}
		if pathDepth(display) > limits.MaxDepth {
			skipped = append(skipped, Skip{Path: display, Reason: "depth"})
			return nil
		}
		if info.Size() > limits.MaxFileBytes {
			skipped = append(skipped, Skip{Path: display, Reason: "size"})
			return nil
		}
		tasks = append(tasks, fileTask{path: filePath, display: display})
		return nil
	})
	if err != nil {
		return nil, nil, nil, false, fmt.Errorf("discover files: %w", err)
	}
	return tasks, skipped, scanErrors, truncated, nil
}

func safeErrorMessage(err error) string {
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return pathError.Err.Error()
	}
	return err.Error()
}

func skippedDirectoryReason(name string) string {
	if name == ".git" {
		return "version-control"
	}
	if strings.HasPrefix(name, ".") {
		return "hidden-directory"
	}
	if defaultSkippedDirectories[name] {
		return "project-scope"
	}
	return ""
}

func pathDepth(filePath string) int {
	if filePath == "" || filePath == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(filepath.Clean(filePath)), "/") + 1
}

func scanFiles(
	ctx context.Context,
	matcher *licenses.Matcher,
	tasks []fileTask,
	limits Limits,
) <-chan fileOutcome {
	outcomes := make(chan fileOutcome)
	if len(tasks) == 0 {
		close(outcomes)
		return outcomes
	}
	jobs := make(chan fileTask)
	workerCount := min(limits.Workers, maxScannerWorkers, len(tasks))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for task := range jobs {
				outcome := scanFile(ctx, matcher, task, limits.MaxFileBytes)
				select {
				case outcomes <- outcome:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, task := range tasks {
			select {
			case jobs <- task:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(outcomes)
	}()
	return outcomes
}

func scanFile(ctx context.Context, matcher *licenses.Matcher, task fileTask, maxBytes int64) fileOutcome {
	data, tooLarge, err := readFile(task.path, maxBytes)
	if err != nil {
		return fileOutcome{task: task, err: err}
	}
	if tooLarge {
		return fileOutcome{task: task, tooLarge: true}
	}
	detection := magic.Detect(data)
	if detection.Kind == magic.KindBinary {
		return fileOutcome{task: task, binary: true}
	}
	decoded := decodeText(data, detection)
	result, err := matcher.Match(ctx, decoded.data)
	if err != nil {
		return fileOutcome{task: task, bytes: int64(len(data)), scanned: true, err: err}
	}
	applyScanPolicy(task.display, decoded.data, &result)
	coverage := licenseTextCoverage(result, len(decoded.data))
	roles := attributionRoles(task.display, result)
	remapResultOffsets(&result, decoded)
	digest := sha256.Sum256(data)
	fileDigest := hex.EncodeToString(digest[:])
	outcome := fileOutcome{task: task, bytes: int64(len(data)), scanned: true}
	if len(result.Detections) > 0 || len(result.Clues) > 0 {
		file := makeFile(task.display, int64(len(data)), fileDigest, decoded.encoding, coverage, result)
		outcome.file = &file
	}
	if len(roles) > 0 {
		outcome.attribution = &attributionCandidate{
			path: task.path, display: task.display, roles: roles, sha256: fileDigest,
			encoding: decoded.encoding, size: int64(len(data)),
		}
	}
	return outcome
}

func readFile(filePath string, maximum int64) ([]byte, bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maximum {
		return nil, true, nil
	}
	return data, false, nil
}

func makeFile(
	filePath string,
	size int64,
	digest string,
	encoding string,
	coverage float64,
	result licenses.Result,
) File {
	file := File{
		Path: filePath, Size: size, SHA256: digest, Encoding: encoding,
		LicenseTextCoverage: coverage, Detections: make([]Detection, 0, len(result.Detections)),
		Clues: make([]Match, 0, len(result.Clues)),
	}
	for _, detection := range result.Detections {
		record := Detection{
			Expression: detection.Expression, Identification: detection.Identification,
			Matches: make([]Match, 0, len(detection.Matches)),
		}
		for _, match := range detection.Matches {
			record.Matches = append(record.Matches, makeMatch(match))
		}
		file.Detections = append(file.Detections, record)
	}
	for _, clue := range result.Clues {
		file.Clues = append(file.Clues, makeMatch(clue))
	}
	sortFile(&file)
	return file
}

func sortFile(file *File) {
	for index := range file.Detections {
		slices.SortFunc(file.Detections[index].Matches, compareMatches)
	}
	slices.SortFunc(file.Clues, compareMatches)
	slices.SortFunc(file.Detections, func(a, b Detection) int {
		if compared := compareMatches(a.Matches[0], b.Matches[0]); compared != 0 {
			return compared
		}
		return strings.Compare(a.Expression, b.Expression)
	})
}

func compareMatches(a, b Match) int {
	if compared := cmp.Compare(a.Start, b.Start); compared != 0 {
		return compared
	}
	if compared := cmp.Compare(a.End, b.End); compared != 0 {
		return compared
	}
	if compared := strings.Compare(a.RuleID, b.RuleID); compared != 0 {
		return compared
	}
	return strings.Compare(string(a.Method), string(b.Method))
}

func makeMatch(match licenses.Match) Match {
	ids := slices.Clone(match.LicenseIDs)
	if ids == nil {
		ids = make([]string, 0)
	}
	return Match{
		RuleID: match.RuleID, LicenseIDs: ids, Kind: match.Kind, Method: match.Method,
		Score: match.Score, Coverage: match.Coverage, Start: match.Start, End: match.End,
	}
}

type byteRange struct{ start, end int }

func licenseTextCoverage(result licenses.Result, length int) float64 {
	if length == 0 {
		return 0
	}
	var ranges []byteRange
	for _, detection := range result.Detections {
		for _, match := range detection.Matches {
			if match.Kind == licenses.KindText || match.Kind == licenses.KindNotice {
				ranges = append(ranges, byteRange{start: max(0, match.Start), end: min(length, match.End)})
			}
		}
	}
	if len(ranges) == 0 {
		return 0
	}
	slices.SortFunc(ranges, func(a, b byteRange) int {
		if compared := cmp.Compare(a.start, b.start); compared != 0 {
			return compared
		}
		return cmp.Compare(a.end, b.end)
	})
	covered := 0
	current := ranges[0]
	for _, candidate := range ranges[1:] {
		if candidate.start <= current.end {
			current.end = max(current.end, candidate.end)
			continue
		}
		covered += max(0, current.end-current.start)
		current = candidate
	}
	covered += max(0, current.end-current.start)
	return math.Round((float64(covered)/float64(length)*100)*100) / 100
}

func attributionRoles(filePath string, result licenses.Result) []string {
	licenseRole := isLegalFile(filePath) && !isNoticeFile(filePath)
	noticeRole := isNoticeFile(filePath)
	for _, detection := range result.Detections {
		for _, match := range detection.Matches {
			switch match.Kind {
			case licenses.KindText:
				licenseRole = true
			case licenses.KindNotice:
				noticeRole = true
			}
		}
	}
	roles := make([]string, 0, 2)
	if licenseRole {
		roles = append(roles, "license")
	}
	if noticeRole {
		roles = append(roles, "notice")
	}
	return roles
}

func addExpressions(
	filePath string,
	detections []Detection,
	rootExpressions map[string]Expression,
	otherExpressions map[string]Expression,
) {
	destination := otherExpressions
	if !strings.Contains(filepathSlash(filePath), "/") && (isLegalFile(filePath) || isReadmeFile(filePath)) {
		destination = rootExpressions
	}
	for _, detection := range detections {
		key := detection.Expression + "\x00" + string(detection.Identification)
		destination[key] = Expression{
			Expression: detection.Expression, Identification: detection.Identification,
		}
	}
}

func expressionValues(values map[string]Expression) []Expression {
	result := make([]Expression, 0, len(values))
	for _, expression := range values {
		result = append(result, expression)
	}
	slices.SortFunc(result, func(a, b Expression) int {
		if compared := strings.Compare(a.Expression, b.Expression); compared != 0 {
			return compared
		}
		return strings.Compare(string(a.Identification), string(b.Identification))
	})
	return result
}

func populateAttribution(report *Report, candidates []attributionCandidate, limits Limits) {
	slices.SortFunc(candidates, func(a, b attributionCandidate) int {
		return strings.Compare(a.display, b.display)
	})
	var total int64
	for _, candidate := range candidates {
		if len(report.AttributionFiles) >= limits.MaxAttributionFiles ||
			candidate.size > limits.MaxAttributionBytes-total {
			report.Skipped = append(report.Skipped, Skip{Path: candidate.display, Reason: "attribution-limit"})
			continue
		}
		data, err := os.ReadFile(candidate.path)
		if err != nil {
			report.Summary.Complete = false
			report.Errors = append(report.Errors, ScanError{Path: candidate.display, Error: "read attribution file"})
			continue
		}
		decoded := decodeText(data, magic.Detect(data))
		report.AttributionFiles = append(report.AttributionFiles, AttributionFile{
			Path: candidate.display, Roles: slices.Clone(candidate.roles), SHA256: candidate.sha256,
			Encoding: candidate.encoding, Content: string(decoded.data),
		})
		total += int64(len(data))
	}
}

func sortReport(report *Report) {
	slices.SortFunc(report.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	slices.SortFunc(report.AttributionFiles, func(a, b AttributionFile) int {
		return strings.Compare(a.Path, b.Path)
	})
	slices.SortFunc(report.Skipped, func(a, b Skip) int {
		if compared := strings.Compare(a.Path, b.Path); compared != 0 {
			return compared
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	slices.SortFunc(report.Errors, func(a, b ScanError) int {
		if compared := strings.Compare(a.Path, b.Path); compared != 0 {
			return compared
		}
		return strings.Compare(a.Error, b.Error)
	})
}
