package archive

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ulikunitz/xz"
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
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return ExtractResult{}, wrap(KindExtract, "create extraction root", err)
	}
	format, err := detectFormat(archivePath)
	if err != nil {
		return ExtractResult{}, err
	}
	budget := &extractBudget{limits: limits}
	root := filepath.Join(destination, "contents")
	if err := os.Mkdir(root, 0o700); err != nil {
		return ExtractResult{}, wrap(KindExtract, "create contents directory", err)
	}

	var files []string
	var skipped []Skip
	switch format {
	case "zip":
		files, skipped, err = extractZIP(ctx, archivePath, root, budget)
	case "tar":
		files, skipped, err = extractTarFile(ctx, archivePath, root, budget, "tar")
	case "tar.gz":
		files, skipped, err = extractTarFile(ctx, archivePath, root, budget, "gzip")
	case "tar.xz":
		files, skipped, err = extractTarFile(ctx, archivePath, root, budget, "xz")
	default:
		panic("unreachable archive format")
	}
	if err != nil {
		return ExtractResult{}, err
	}

	// Ruby gems are tar files containing metadata.gz and data.tar.gz. Scan the
	// package payload rather than the gem container metadata.
	if format == "tar" && slices.Contains(files, "data.tar.gz") && slices.Contains(files, "metadata.gz") {
		gemRoot := filepath.Join(destination, "gem-contents")
		if err := os.Mkdir(gemRoot, 0o700); err != nil {
			return ExtractResult{}, wrap(KindExtract, "create gem contents directory", err)
		}
		innerFiles, innerSkipped, innerErr := extractTarFile(
			ctx,
			filepath.Join(root, filepath.FromSlash("data.tar.gz")),
			gemRoot,
			budget,
			"gzip",
		)
		if innerErr != nil {
			return ExtractResult{}, innerErr
		}
		files = innerFiles
		skipped = append(skipped, innerSkipped...)
		root = gemRoot
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

func detectFormat(archivePath string) (string, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return "", wrap(KindExtract, "open archive", err)
	}
	defer file.Close()
	header := make([]byte, 512)
	n, err := io.ReadFull(file, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", wrap(KindExtract, "read archive header", err)
	}
	header = header[:n]
	switch {
	case bytes.HasPrefix(header, []byte{'P', 'K', 3, 4}),
		bytes.HasPrefix(header, []byte{'P', 'K', 5, 6}),
		bytes.HasPrefix(header, []byte{'P', 'K', 7, 8}):
		return "zip", nil
	case bytes.HasPrefix(header, []byte{0x1f, 0x8b}):
		return "tar.gz", nil
	case bytes.HasPrefix(header, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		return "tar.xz", nil
	case len(header) >= 265 && bytes.Equal(header[257:262], []byte("ustar")):
		return "tar", nil
	default:
		if len(header) == 512 {
			if _, tarErr := tar.NewReader(bytes.NewReader(header)).Next(); tarErr == nil {
				return "tar", nil
			}
		}
		return "", wrap(KindUnsupported, "detect archive", errors.New("unsupported archive format"))
	}
}

func extractZIP(
	ctx context.Context,
	archivePath string,
	destination string,
	budget *extractBudget,
) ([]string, []Skip, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, nil, wrap(KindInvalid, "open ZIP archive", err)
	}
	defer reader.Close()
	var files []string
	var skipped []Skip
	for _, member := range reader.File {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := budget.nextEntry(); err != nil {
			return nil, nil, err
		}
		name, err := safeMemberName(member.Name, budget.limits.MaxDepth)
		if err != nil {
			return nil, nil, err
		}
		if name == "" {
			continue
		}
		mode := member.Mode()
		switch {
		case member.FileInfo().IsDir():
			if err := makeDirectory(destination, name); err != nil {
				return nil, nil, err
			}
		case mode&os.ModeSymlink != 0:
			skipped = append(skipped, Skip{Path: name, Reason: "symlink"})
		case !mode.IsRegular():
			skipped = append(skipped, Skip{Path: name, Reason: "non-regular"})
		default:
			if member.UncompressedSize64 > uint64(budget.limits.MaxEntryBytes) {
				return nil, nil, wrap(KindLimit, "extract ZIP member", fmt.Errorf("%s exceeds the per-entry limit", name))
			}
			source, err := member.Open()
			if err != nil {
				return nil, nil, wrap(KindInvalid, "open ZIP member", err)
			}
			err = extractRegularFile(ctx, source, destination, name, budget)
			_ = source.Close()
			if err != nil {
				return nil, nil, err
			}
			files = append(files, name)
		}
	}
	return files, skipped, nil
}

func extractTarFile(
	ctx context.Context,
	archivePath string,
	destination string,
	budget *extractBudget,
	compression string,
) ([]string, []Skip, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, nil, wrap(KindExtract, "open tar archive", err)
	}
	defer file.Close()
	var source io.Reader = bufio.NewReader(file)
	var gzipReader *gzip.Reader
	switch compression {
	case "gzip":
		gzipReader, err = gzip.NewReader(source)
		if err != nil {
			return nil, nil, wrap(KindInvalid, "open gzip stream", err)
		}
		defer gzipReader.Close()
		source = gzipReader
	case "xz":
		xzReader, xzErr := xz.NewReader(source)
		if xzErr != nil {
			return nil, nil, wrap(KindInvalid, "open xz stream", xzErr)
		}
		source = xzReader
	case "tar":
	default:
		panic("unknown tar compression")
	}
	source = &contextReader{ctx: ctx, source: source}
	return extractTarReader(ctx, tar.NewReader(source), destination, budget)
}

func extractTarReader(
	ctx context.Context,
	reader *tar.Reader,
	destination string,
	budget *extractBudget,
) ([]string, []Skip, error) {
	var files []string
	var skipped []Skip
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, wrap(KindInvalid, "read tar header", err)
		}
		if err := budget.nextEntry(); err != nil {
			return nil, nil, err
		}
		name, err := safeMemberName(header.Name, budget.limits.MaxDepth)
		if err != nil {
			return nil, nil, err
		}
		if name == "" {
			continue
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := makeDirectory(destination, name); err != nil {
				return nil, nil, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > budget.limits.MaxEntryBytes {
				return nil, nil, wrap(KindLimit, "extract tar member", fmt.Errorf("%s exceeds the per-entry limit", name))
			}
			if err := extractRegularFile(ctx, reader, destination, name, budget); err != nil {
				return nil, nil, err
			}
			files = append(files, name)
		case tar.TypeSymlink:
			skipped = append(skipped, Skip{Path: name, Reason: "symlink"})
		case tar.TypeLink:
			skipped = append(skipped, Skip{Path: name, Reason: "hard-link"})
		default:
			skipped = append(skipped, Skip{Path: name, Reason: "non-regular"})
		}
	}
	return files, skipped, nil
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

func makeDirectory(root, name string) error {
	target, err := destinationPath(root, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0o700); err != nil {
		return wrap(KindExtract, "create archive directory", err)
	}
	return nil
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
