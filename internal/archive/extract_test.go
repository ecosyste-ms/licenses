package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulikunitz/xz"
)

type testEntry struct {
	name     string
	body     []byte
	mode     os.FileMode
	typeflag byte
	linkname string
}

func TestExtractSupportedFormatsAndCommonRoot(t *testing.T) {
	t.Parallel()
	payload := []testEntry{{name: "wrapper/LICENSE", body: []byte("license")}}
	innerTarGz := makeTar(t, []testEntry{{name: "LICENSE", body: []byte("gem license")}}, "gzip")
	formats := map[string][]byte{
		"zip":    makeZIP(t, payload),
		"jar":    makeZIP(t, payload),
		"tar":    makeTar(t, payload, "tar"),
		"tar.gz": makeTar(t, payload, "gzip"),
		"tar.xz": makeTar(t, payload, "xz"),
		"gem": makeTar(t, []testEntry{
			{name: "metadata.gz", body: []byte("metadata")},
			{name: "data.tar.gz", body: innerTarGz},
		}, "tar"),
	}
	for name, data := range formats {
		t.Run(name, func(t *testing.T) {
			archivePath := writeArchive(t, data)
			result, err := Extract(context.Background(), archivePath, t.TempDir(), DefaultExtractLimits())
			if err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(filepath.Join(result.Root, "LICENSE"))
			if err != nil {
				t.Fatal(err)
			}
			if len(contents) == 0 {
				t.Fatal("LICENSE is empty")
			}
		})
	}
}

func TestExtractDoesNotStripMixedRoots(t *testing.T) {
	t.Parallel()
	data := makeZIP(t, []testEntry{
		{name: "wrapper/LICENSE", body: []byte("license")},
		{name: "README", body: []byte("readme")},
	})
	result, err := Extract(context.Background(), writeArchive(t, data), t.TempDir(), DefaultExtractLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(result.Root, "wrapper", "LICENSE")); err != nil {
		t.Fatal(err)
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"../escape", "/absolute", "..\\escape", "C:\\escape"} {
		t.Run(name, func(t *testing.T) {
			data := makeZIP(t, []testEntry{{name: name, body: []byte("bad")}})
			_, err := Extract(context.Background(), writeArchive(t, data), t.TempDir(), DefaultExtractLimits())
			if KindOf(err) != KindInvalid {
				t.Fatalf("error = %v, kind = %q", err, KindOf(err))
			}
		})
	}
}

func TestExtractRejectsTarTraversal(t *testing.T) {
	t.Parallel()
	data := makeTar(t, []testEntry{{name: "../escape", body: []byte("bad")}}, "tar")
	_, err := Extract(context.Background(), writeArchive(t, data), t.TempDir(), DefaultExtractLimits())
	if KindOf(err) != KindInvalid {
		t.Fatalf("error = %v, kind = %q", err, KindOf(err))
	}
}

func TestExtractLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []testEntry
		limits  func(ExtractLimits) ExtractLimits
	}{
		{
			name: "entry bytes", entries: []testEntry{{name: "large", body: []byte("12345")}},
			limits: func(limits ExtractLimits) ExtractLimits { limits.MaxEntryBytes = 4; return limits },
		},
		{
			name: "expanded bytes", entries: []testEntry{{name: "one", body: []byte("123")}, {name: "two", body: []byte("456")}},
			limits: func(limits ExtractLimits) ExtractLimits {
				limits.MaxEntryBytes = 5
				limits.MaxExpandedBytes = 5
				return limits
			},
		},
		{
			name: "entries", entries: []testEntry{{name: "one", body: []byte("1")}, {name: "two", body: []byte("2")}},
			limits: func(limits ExtractLimits) ExtractLimits { limits.MaxEntries = 1; return limits },
		},
		{
			name: "depth", entries: []testEntry{{name: "one/two/file", body: []byte("1")}},
			limits: func(limits ExtractLimits) ExtractLimits { limits.MaxDepth = 2; return limits },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := test.limits(DefaultExtractLimits())
			_, err := Extract(context.Background(), writeArchive(t, makeZIP(t, test.entries)), t.TempDir(), limits)
			if KindOf(err) != KindLimit {
				t.Fatalf("error = %v, kind = %q", err, KindOf(err))
			}
		})
	}
}

func TestExtractSkipsLinksAndSpecialEntries(t *testing.T) {
	t.Parallel()
	data := makeTar(t, []testEntry{
		{name: "LICENSE", body: []byte("license")},
		{name: "soft", typeflag: tar.TypeSymlink, linkname: "LICENSE"},
		{name: "hard", typeflag: tar.TypeLink, linkname: "LICENSE"},
		{name: "device", typeflag: tar.TypeChar},
		{name: "socket", typeflag: tar.TypeFifo},
	}, "tar")
	result, err := Extract(context.Background(), writeArchive(t, data), t.TempDir(), DefaultExtractLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Skipped) != 4 {
		t.Fatalf("skipped = %#v", result.Skipped)
	}
	for _, name := range []string{"soft", "hard", "device", "socket"} {
		if _, err := os.Lstat(filepath.Join(result.Root, name)); !os.IsNotExist(err) {
			t.Fatalf("special entry %q exists: %v", name, err)
		}
	}
}

func TestExtractUnsupported(t *testing.T) {
	t.Parallel()
	_, err := Extract(context.Background(), writeArchive(t, []byte("not an archive")), t.TempDir(), DefaultExtractLimits())
	if KindOf(err) != KindUnsupported {
		t.Fatalf("error = %v, kind = %q", err, KindOf(err))
	}
}

func makeZIP(t *testing.T, entries []testEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		if entry.mode != 0 {
			header.SetMode(entry.mode)
		}
		member, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func makeTar(t *testing.T, entries []testEntry, compression string) []byte {
	t.Helper()
	var output bytes.Buffer
	var destination io.Writer = &output
	var closeCompression func() error
	switch compression {
	case "gzip":
		writer := gzip.NewWriter(&output)
		destination = writer
		closeCompression = writer.Close
	case "xz":
		writer, err := xz.NewWriter(&output)
		if err != nil {
			t.Fatal(err)
		}
		destination = writer
		closeCompression = writer.Close
	case "tar":
		closeCompression = func() error { return nil }
	default:
		t.Fatalf("unknown compression %q", compression)
	}
	writer := tar.NewWriter(destination)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name: entry.name, Mode: 0o600, Size: int64(len(entry.body)),
			Typeflag: typeflag, Linkname: entry.linkname,
		}
		if typeflag != tar.TypeReg && typeflag != tar.TypeRegA {
			header.Size = 0
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closeCompression(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeArchive(t *testing.T, data []byte) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "archive")
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}
