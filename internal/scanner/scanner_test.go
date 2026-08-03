package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"unicode/utf16"

	licenses "github.com/git-pkgs/licenses"
	"github.com/git-pkgs/magic"

	archivepkg "github.com/ecosyste-ms/licenses/internal/archive"
)

const mitLicense = `MIT License

Copyright (c) 2026 Ecosyste.ms

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`

func TestScanDirectoryEvidenceAndAttribution(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "LICENSE", []byte(mitLicense))
	writeTestFile(t, root, "NOTICE", []byte("Project notice\nSPDX-License-Identifier: MIT\n"))
	writeTestFile(t, root, "nested/LICENSE", []byte("SPDX-License-Identifier: Apache-2.0\n"))
	writeTestFile(t, root, "src/partial.go", []byte("// SPDX-License-Identifier: MIT AND LicenseRef-local\n"))
	writeTestFile(t, root, "src/unknown.go", []byte("// SPDX-License-Identifier: LicenseRef-local\n"))
	writeTestFile(t, root, "src/binary", []byte{0, 1, 2, 3})

	scanService := newTestScanner(t)
	report, err := scanService.ScanDirectory(context.Background(), "https://example.test/package.zip", "archive-sha", root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != 1 || report.SHA256 != "archive-sha" || !report.Summary.Complete {
		t.Fatalf("unexpected report header: %#v", report)
	}
	if report.Summary.FilesVisited != 6 || report.Summary.FilesScanned != 5 {
		t.Fatalf("summary = %#v", report.Summary)
	}
	if !hasExpression(report.Summary.RootExpressions, "mit", licenses.Identified) {
		t.Fatalf("root expressions = %#v", report.Summary.RootExpressions)
	}
	if !hasExpression(report.Summary.OtherExpressions, "apache-2.0", licenses.Identified) ||
		!hasIdentification(report.Summary.OtherExpressions, licenses.Partial) ||
		!hasIdentification(report.Summary.OtherExpressions, licenses.NoAssertion) {
		t.Fatalf("other expressions = %#v", report.Summary.OtherExpressions)
	}
	if len(report.AttributionFiles) != 3 {
		t.Fatalf("attribution files = %#v", report.AttributionFiles)
	}
	license := findAttribution(t, report, "LICENSE")
	if license.Content != mitLicense || !slices.Equal(license.Roles, []string{"license"}) {
		t.Fatalf("LICENSE attribution = %#v", license)
	}
	if file := findFile(t, report, "LICENSE"); file.LicenseTextCoverage <= 0 {
		t.Fatalf("LICENSE coverage = %v", file.LicenseTextCoverage)
	}
	notice := findAttribution(t, report, "NOTICE")
	if !slices.Equal(notice.Roles, []string{"notice"}) {
		t.Fatalf("NOTICE roles = %#v", notice.Roles)
	}
	if len(report.Skipped) != 1 || report.Skipped[0].Reason != "binary" {
		t.Fatalf("skipped = %#v", report.Skipped)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("errors = %#v", report.Errors)
	}
}

func TestScanDirectoryNoDetectionsWithWarningsIsComplete(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "plain.txt", []byte("There is no licensing statement here."))
	writeTestFile(t, root, "binary", []byte{0, 1})
	scanService := newTestScanner(t)
	report, err := scanService.ScanDirectory(context.Background(), "https://example.test/empty.zip", "sha", root)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Summary.Complete || len(report.Files) != 0 || len(report.Errors) != 0 {
		t.Fatalf("report = %#v", report)
	}
	if len(report.Skipped) != 1 || report.Skipped[0].Reason != "binary" {
		t.Fatalf("skipped = %#v", report.Skipped)
	}
}

func TestScanDirectoryTwoRootLicenseTexts(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "LICENSE", []byte(mitLicense))
	writeTestFile(t, root, "COPYING", []byte("SPDX-License-Identifier: Apache-2.0\n"))
	report, err := newTestScanner(t).ScanDirectory(
		context.Background(), "https://example.test/two.zip", "sha", root,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !hasExpression(report.Summary.RootExpressions, "mit", licenses.Identified) ||
		!hasExpression(report.Summary.RootExpressions, "apache-2.0", licenses.Identified) {
		t.Fatalf("root expressions = %#v", report.Summary.RootExpressions)
	}
}

func TestScanDirectoryEncodedSPDXOffsets(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		encoding string
		needle   []byte
	}{
		{
			name: "utf8-bom", data: append([]byte{0xef, 0xbb, 0xbf}, []byte("// SPDX-License-Identifier: MIT\n")...),
			encoding: "utf-8", needle: []byte("SPDX-License-Identifier: MIT"),
		},
		{
			name: "utf16le", data: encodeUTF16([]rune("// SPDX-License-Identifier: MIT\n"), binary.LittleEndian),
			encoding: "utf-16le", needle: encodeUTF16([]rune("SPDX-License-Identifier: MIT"), binary.LittleEndian)[2:],
		},
		{
			name: "utf16be", data: encodeUTF16([]rune("// SPDX-License-Identifier: MIT\n"), binary.BigEndian),
			encoding: "utf-16be", needle: encodeUTF16([]rune("SPDX-License-Identifier: MIT"), binary.BigEndian)[2:],
		},
		{
			name: "latin1", data: append([]byte{'/', '/', ' ', 'c', 'a', 'f', 0xe9, '\n'}, []byte("// SPDX-License-Identifier: MIT\n")...),
			encoding: "iso-8859-1", needle: []byte("SPDX-License-Identifier: MIT"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeTestFile(t, root, test.name+".txt", test.data)
			report, err := newTestScanner(t).ScanDirectory(
				context.Background(), "https://example.test/encoded.zip", "sha", root,
			)
			if err != nil {
				t.Fatal(err)
			}
			file := findFile(t, report, test.name+".txt")
			match := findMethodMatch(t, file, licenses.SpdxID)
			start := bytes.Index(test.data, test.needle)
			if file.Encoding != test.encoding || match.Start != start || match.End != start+len(test.needle) {
				t.Fatalf("encoding=%q range=[%d,%d), want %q [%d,%d)", file.Encoding, match.Start, match.End, test.encoding, start, start+len(test.needle))
			}
		})
	}
}

func TestScanDirectoryStableUnderConcurrency(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "LICENSE", []byte(mitLicense))
	writeTestFile(t, root, "src/main.go", []byte("// SPDX-License-Identifier: MIT\n"))
	scanService := newTestScanner(t)
	const count = 4
	results := make(chan []byte, count)
	errors := make(chan error, count)
	var workers sync.WaitGroup
	for range count {
		workers.Add(1)
		go func() {
			defer workers.Done()
			report, err := scanService.ScanDirectory(context.Background(), "https://example.test/stable.zip", "sha", root)
			if err != nil {
				errors <- err
				return
			}
			encoded, err := json.Marshal(report)
			if err != nil {
				errors <- err
				return
			}
			results <- encoded
		}()
	}
	workers.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var first []byte
	for result := range results {
		if first == nil {
			first = result
			continue
		}
		if !bytes.Equal(first, result) {
			t.Fatalf("non-deterministic JSON:\n%s\n%s", first, result)
		}
	}
}

func TestScanURLExistingFixtures(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "test", "fixtures", "files")
	server := httptest.NewServer(http.FileServer(http.Dir(fixtureRoot)))
	defer server.Close()
	scanService := newTestScanner(t)
	scanService.ArchiveClient = &archivepkg.Client{
		HTTPClient: server.Client(), Limits: archivepkg.DefaultDownloadLimits(), AllowPrivateHosts: true,
	}
	fixtures := map[string]string{
		"main.zip":                   "agpl-3.0",
		"pkg-1.0.0.tgz":              "mit",
		"clj-data-adapter-0.2.1.jar": "",
	}
	for fixture, legacyExpression := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			report, err := scanService.ScanURL(context.Background(), server.URL+"/"+fixture)
			if err != nil {
				t.Fatal(err)
			}
			if report.SHA256 == "" || report.Summary.FilesVisited == 0 {
				t.Fatalf("report = %#v", report)
			}
			if legacyExpression != "" && !hasExpression(report.Summary.RootExpressions, legacyExpression, licenses.Identified) {
				t.Fatalf("v1 detected %q; v2 root expressions = %#v", legacyExpression, report.Summary.RootExpressions)
			}
			if legacyExpression == "" && len(report.Summary.RootExpressions) != 0 {
				t.Fatalf("v1 had no detection; v2 root expressions = %#v", report.Summary.RootExpressions)
			}
		})
	}
}

func TestScanURLFixtureArchive(t *testing.T) {
	data := makeScannerZIP(t, map[string][]byte{
		"wrapper/LICENSE": []byte(mitLicense),
		"wrapper/NOTICE":  []byte("notice"),
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()
	scanService := newTestScanner(t)
	scanService.ArchiveClient = &archivepkg.Client{
		HTTPClient: server.Client(), Limits: archivepkg.DefaultDownloadLimits(), AllowPrivateHosts: true,
	}
	report, err := scanService.ScanURL(context.Background(), server.URL+"/package.zip")
	if err != nil {
		t.Fatal(err)
	}
	if !hasExpression(report.Summary.RootExpressions, "mit", licenses.Identified) {
		t.Fatalf("root expressions = %#v", report.Summary.RootExpressions)
	}
	if findAttribution(t, report, "LICENSE").Content != mitLicense {
		t.Fatal("complete LICENSE content was not returned")
	}
}

func TestTextOffsetRemapping(t *testing.T) {
	t.Parallel()
	utf8BOM := append([]byte{0xef, 0xbb, 0xbf}, []byte("MIT")...)
	assertRemappedRange(t, utf8BOM, 0, 3, 3, 6, "utf-8")

	utf16LE := encodeUTF16([]rune("MIT"), binary.LittleEndian)
	assertRemappedRange(t, utf16LE, 0, 3, 2, 8, "utf-16le")
	utf16BE := encodeUTF16([]rune("MIT"), binary.BigEndian)
	assertRemappedRange(t, utf16BE, 0, 3, 2, 8, "utf-16be")

	latin1 := []byte{'c', 'a', 'f', 0xe9}
	assertRemappedRange(t, latin1, 3, 5, 3, 4, "iso-8859-1")
}

func TestDiscoveryLimitsAndPolicy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, root, "one.txt", []byte("one"))
	writeTestFile(t, root, "two.txt", []byte("two"))
	writeTestFile(t, root, ".git/config", []byte("ignored"))
	writeTestFile(t, root, "vendor/LICENSE", []byte(mitLicense))
	limits := DefaultLimits()
	limits.MaxFiles = 1
	summary := Summary{}
	tasks, skipped, scanErrors, truncated, err := discoverFiles(context.Background(), root, limits, &summary)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || !truncated || len(skipped) < 2 {
		t.Fatalf("tasks=%#v skipped=%#v truncated=%v", tasks, skipped, truncated)
	}
	if len(scanErrors) != 0 {
		t.Fatalf("scan errors = %#v", scanErrors)
	}
}

func TestLicenseTextCoverageMergesOverlappingRanges(t *testing.T) {
	t.Parallel()
	result := licenses.Result{Detections: []licenses.Detection{{Matches: []licenses.Match{
		{Kind: licenses.KindText, Start: 0, End: 5},
		{Kind: licenses.KindNotice, Start: 3, End: 8},
		{Kind: licenses.KindReference, Start: 8, End: 10},
	}}}}
	if got := licenseTextCoverage(result, 10); got != 80 {
		t.Fatalf("coverage = %v, want 80", got)
	}
}

func TestAttributionLimitListsOmittedFiles(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "LICENSE", []byte(mitLicense))
	writeTestFile(t, root, "NOTICE", []byte("notice"))
	scanService := newTestScanner(t)
	scanService.Limits.MaxAttributionFiles = 1
	report, err := scanService.ScanDirectory(context.Background(), "https://example.test/package.zip", "sha", root)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.AttributionFiles) != 1 || !slices.ContainsFunc(report.Skipped, func(skip Skip) bool {
		return skip.Path == "NOTICE" && skip.Reason == "attribution-limit"
	}) {
		t.Fatalf("attribution=%#v skipped=%#v", report.AttributionFiles, report.Skipped)
	}
}

func newTestScanner(t *testing.T) *Scanner {
	t.Helper()
	scanService, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return scanService
}

func writeTestFile(t *testing.T, root, name string, data []byte) {
	t.Helper()
	filePath := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasExpression(expressions []Expression, expression string, identification licenses.Identification) bool {
	return slices.ContainsFunc(expressions, func(candidate Expression) bool {
		return candidate.Expression == expression && candidate.Identification == identification
	})
}

func hasIdentification(expressions []Expression, identification licenses.Identification) bool {
	return slices.ContainsFunc(expressions, func(candidate Expression) bool {
		return candidate.Identification == identification
	})
}

func findAttribution(t *testing.T, report Report, name string) AttributionFile {
	t.Helper()
	for _, file := range report.AttributionFiles {
		if file.Path == name {
			return file
		}
	}
	t.Fatalf("attribution file %q not found in %#v", name, report.AttributionFiles)
	return AttributionFile{}
}

func findFile(t *testing.T, report Report, name string) File {
	t.Helper()
	for _, file := range report.Files {
		if file.Path == name {
			return file
		}
	}
	t.Fatalf("file %q not found in %#v", name, report.Files)
	return File{}
}

func findMethodMatch(t *testing.T, file File, method licenses.Method) Match {
	t.Helper()
	for _, detection := range file.Detections {
		for _, match := range detection.Matches {
			if match.Method == method {
				return match
			}
		}
	}
	t.Fatalf("method %q not found in %#v", method, file)
	return Match{}
}

func assertRemappedRange(
	t *testing.T,
	raw []byte,
	decodedStart, decodedEnd, rawStart, rawEnd int,
	encoding string,
) {
	t.Helper()
	decoded := decodeText(raw, magic.Detect(raw))
	result := licenses.Result{Detections: []licenses.Detection{{
		Matches: []licenses.Match{{Start: decodedStart, End: decodedEnd}},
	}}}
	remapResultOffsets(&result, decoded)
	match := result.Detections[0].Matches[0]
	if decoded.encoding != encoding || match.Start != rawStart || match.End != rawEnd {
		t.Fatalf("encoding=%q range=[%d,%d), want %q [%d,%d)", decoded.encoding, match.Start, match.End, encoding, rawStart, rawEnd)
	}
}

func encodeUTF16(input []rune, order binary.ByteOrder) []byte {
	words := utf16.Encode(input)
	result := make([]byte, 2+len(words)*2)
	if order == binary.LittleEndian {
		result[0], result[1] = 0xff, 0xfe
	} else {
		result[0], result[1] = 0xfe, 0xff
	}
	for index, word := range words {
		order.PutUint16(result[2+index*2:], word)
	}
	return result
}

func makeScannerZIP(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, data := range files {
		member, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func BenchmarkScanDirectory(b *testing.B) {
	root := b.TempDir()
	filePath := filepath.Join(root, "LICENSE")
	if err := os.WriteFile(filePath, []byte(mitLicense), 0o600); err != nil {
		b.Fatal(err)
	}
	scanService, err := New()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := scanService.ScanDirectory(context.Background(), "benchmark", "sha", root); err != nil {
			b.Fatal(err)
		}
	}
}
