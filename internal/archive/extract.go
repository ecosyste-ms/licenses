package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	archives "github.com/git-pkgs/archives"
)

// ExtractLimits bounds archive expansion before scanning begins.
type ExtractLimits struct {
	MaxEntries       int
	MaxDepth         int
	MaxEntryBytes    int64
	MaxExpandedBytes int64
}

// DefaultExtractLimits returns production extraction limits.
func DefaultExtractLimits() ExtractLimits {
	return ExtractLimits{
		MaxEntries:       10_000,
		MaxDepth:         64,
		MaxEntryBytes:    32 << 20,
		MaxExpandedBytes: 512 << 20,
	}
}

// Skip records an archive member deliberately excluded from extraction.
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ExtractResult describes a safe extraction root and excluded entries.
type ExtractResult struct {
	Root    string
	Skipped []Skip
}

type extractBudget struct {
	limits   ExtractLimits
	entries  int
	expanded int64
}

// Extract expands archivePath beneath destination and returns the scan root.
// ZIP/JAR, tar, tar.gz, tar.xz, and Ruby gem containers are supported.
func Extract(ctx context.Context, archivePath, destination string, limits ExtractLimits) (ExtractResult, error) {
	if err := validateExtractLimits(limits); err != nil {
		return ExtractResult{}, wrap(KindInvalid, "validate extraction limits", err)
	}
	if err := ctx.Err(); err != nil {
		return ExtractResult{}, err
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return ExtractResult{}, wrap(KindExtract, "create extraction root", err)
	}
	reader, members, err := openArchive(ctx, archivePath, filepath.Base(archivePath))
	if err != nil {
		return ExtractResult{}, err
	}
	defer func() { _ = reader.Close() }()

	// A Ruby gem is a tar envelope containing data.tar.gz. The downloaded
	// temporary file has no useful extension, so reopen that envelope with the
	// semantic name expected by git-pkgs/archives after inspecting its listing.
	if isGemEnvelope(members) {
		_ = reader.Close()
		reader, members, err = openArchive(ctx, archivePath, "archive.gem")
		if err != nil {
			return ExtractResult{}, err
		}
	}

	budget := &extractBudget{limits: limits}
	root := filepath.Join(destination, "contents")
	if err := os.Mkdir(root, 0o700); err != nil {
		return ExtractResult{}, wrap(KindExtract, "create contents directory", err)
	}

	var files []string
	var skipped []Skip
	for _, member := range members {
		if err := ctx.Err(); err != nil {
			return ExtractResult{}, err
		}
		if err := budget.nextEntry(); err != nil {
			return ExtractResult{}, err
		}
		name, err := safeMemberName(member.Path, limits.MaxDepth)
		if err != nil {
			return ExtractResult{}, err
		}
		if name == "" || member.IsDir {
			continue
		}

		mode := os.FileMode(member.Mode)
		switch {
		case mode&os.ModeSymlink != 0:
			skipped = append(skipped, Skip{Path: name, Reason: "symlink"})
			continue
		case !mode.IsRegular():
			skipped = append(skipped, Skip{Path: name, Reason: "non-regular"})
			continue
		case member.Size == 0:
			// Empty files cannot contain license evidence. This also prevents
			// tar link and device records, whose type is intentionally not
			// materialized by git-pkgs/archives, from becoming filesystem files.
			skipped = append(skipped, Skip{Path: name, Reason: "empty"})
			continue
		case member.Size < 0 || member.Size > limits.MaxEntryBytes:
			return ExtractResult{}, wrap(
				KindLimit,
				"extract archive member",
				fmt.Errorf("%s exceeds the per-entry limit", name),
			)
		}

		source, err := reader.Extract(member.Path)
		if err != nil {
			return ExtractResult{}, wrap(KindInvalid, "open archive member", err)
		}
		extractErr := extractRegularFile(ctx, source, root, name, budget)
		closeErr := source.Close()
		if extractErr != nil {
			return ExtractResult{}, extractErr
		}
		if closeErr != nil {
			return ExtractResult{}, wrap(KindExtract, "close archive member", closeErr)
		}
		files = append(files, name)
	}

	if len(files) == 0 {
		return ExtractResult{}, wrap(KindInvalid, "extract archive", errors.New("archive contains no regular files"))
	}
	root = commonRoot(root, files)
	slices.SortFunc(skipped, func(a, b Skip) int {
		if compared := strings.Compare(a.Path, b.Path); compared != 0 {
			return compared
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	return ExtractResult{Root: root, Skipped: skipped}, nil
}

func openArchive(
	ctx context.Context,
	archivePath string,
	name string,
) (archives.Reader, []archives.FileInfo, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, nil, wrap(KindExtract, "open archive", err)
	}
	reader, err := archives.Open(name, &contextReader{ctx: ctx, source: file})
	_ = file.Close()
	if err != nil {
		return nil, nil, archiveOpenError(err)
	}
	members, err := reader.List()
	if err != nil {
		_ = reader.Close()
		return nil, nil, archiveOpenError(err)
	}
	return reader, members, nil
}

func archiveOpenError(err error) error {
	if errors.Is(err, archives.ErrDecompressLimit) {
		return wrap(KindLimit, "open archive", err)
	}
	if strings.Contains(err.Error(), "unsupported archive format") ||
		strings.Contains(err.Error(), "unsupported format") {
		return wrap(KindUnsupported, "open archive", err)
	}
	return wrap(KindInvalid, "open archive", err)
}

func isGemEnvelope(members []archives.FileInfo) bool {
	metadata := false
	payload := false
	for _, member := range members {
		switch path.Clean(strings.ReplaceAll(member.Path, "\\", "/")) {
		case "metadata.gz":
			metadata = true
		case "data.tar.gz":
			payload = true
		}
	}
	return metadata && payload
}

func validateExtractLimits(limits ExtractLimits) error {
	if limits.MaxEntries <= 0 || limits.MaxDepth <= 0 ||
		limits.MaxEntryBytes <= 0 || limits.MaxExpandedBytes <= 0 {
		return errors.New("all extraction limits must be positive")
	}
	if limits.MaxEntryBytes > limits.MaxExpandedBytes {
		return errors.New("entry limit must not exceed expanded-byte limit")
	}
	return nil
}

func (b *extractBudget) nextEntry() error {
	b.entries++
	if b.entries > b.limits.MaxEntries {
		return wrap(KindLimit, "extract archive", fmt.Errorf("archive exceeds %d entries", b.limits.MaxEntries))
	}
	return nil
}

func safeMemberName(raw string, maxDepth int) (string, error) {
	if strings.ContainsRune(raw, 0) {
		return "", wrap(KindInvalid, "validate archive path", errors.New("member path contains NUL"))
	}
	raw = strings.ReplaceAll(raw, "\\", "/")
	if strings.HasPrefix(raw, "/") {
		return "", wrap(KindInvalid, "validate archive path", fmt.Errorf("absolute member path %q", raw))
	}
	if len(raw) >= 2 && ((raw[0] >= 'a' && raw[0] <= 'z') || (raw[0] >= 'A' && raw[0] <= 'Z')) && raw[1] == ':' {
		return "", wrap(KindInvalid, "validate archive path", fmt.Errorf("drive-qualified member path %q", raw))
	}
	cleaned := path.Clean(raw)
	if cleaned == "." {
		return "", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", wrap(KindInvalid, "validate archive path", fmt.Errorf("traversal member path %q", raw))
	}
	if depth := strings.Count(cleaned, "/") + 1; depth > maxDepth {
		return "", wrap(KindLimit, "validate archive path", fmt.Errorf("member path exceeds depth %d", maxDepth))
	}
	return cleaned, nil
}

func destinationPath(root, name string) (string, error) {
	target := filepath.Join(root, filepath.FromSlash(name))
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", wrap(KindInvalid, "validate extraction target", fmt.Errorf("member escapes extraction root: %s", name))
	}
	return target, nil
}

func extractRegularFile(
	ctx context.Context,
	source io.Reader,
	root string,
	name string,
	budget *extractBudget,
) error {
	target, err := destinationPath(root, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return wrap(KindExtract, "create member directory", err)
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return wrap(KindInvalid, "create archive member", err)
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(target)
		}
	}()

	writer := &budgetWriter{target: file, budget: budget}
	read := &contextReader{ctx: ctx, source: io.LimitReader(source, budget.limits.MaxEntryBytes+1)}
	written, err := io.Copy(writer, read)
	if err != nil {
		return err
	}
	if written > budget.limits.MaxEntryBytes {
		return wrap(KindLimit, "extract archive member", fmt.Errorf("%s exceeds the per-entry limit", name))
	}
	if err := file.Close(); err != nil {
		return wrap(KindExtract, "close archive member", err)
	}
	keep = true
	return nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(buffer)
}

type budgetWriter struct {
	target io.Writer
	budget *extractBudget
}

func (w *budgetWriter) Write(buffer []byte) (int, error) {
	if int64(len(buffer)) > w.budget.limits.MaxExpandedBytes-w.budget.expanded {
		return 0, wrap(KindLimit, "extract archive", fmt.Errorf("expanded data exceeds %d bytes", w.budget.limits.MaxExpandedBytes))
	}
	n, err := w.target.Write(buffer)
	w.budget.expanded += int64(n)
	return n, err
}

func commonRoot(root string, files []string) string {
	if len(files) == 0 {
		return root
	}
	var common string
	for _, name := range files {
		parts := strings.Split(name, "/")
		if len(parts) < 2 {
			return root
		}
		if common == "" {
			common = parts[0]
			continue
		}
		if parts[0] != common {
			return root
		}
	}
	return filepath.Join(root, filepath.FromSlash(common))
}
