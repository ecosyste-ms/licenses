package scanner

import (
	"bytes"
	pathpkg "path"
	"strings"

	licenses "github.com/git-pkgs/licenses"
)

const minimumMarkerLength = 2

func applyScanPolicy(filePath string, input []byte, result *licenses.Result) {
	if isLegalFile(filePath) {
		return
	}
	documentMarkers := usesDocumentMarkers(filePath)
	detections := result.Detections[:0]
	for _, detection := range result.Detections {
		matches := detection.Matches[:0]
		for _, match := range detection.Matches {
			if match.Kind == licenses.KindReference && crossesBlockBoundary(
				input, match.Start, match.End, documentMarkers,
			) {
				result.Clues = append(result.Clues, match)
				continue
			}
			matches = append(matches, match)
		}
		if len(matches) > 0 {
			detection.Matches = matches
			detections = append(detections, detection)
		}
	}
	result.Detections = detections
}

func crossesBlockBoundary(input []byte, start, end int, documentMarkers bool) bool {
	if start < 0 || start >= end || end > len(input) {
		return false
	}
	for searchStart := start; searchStart < end; {
		relative := bytes.IndexByte(input[searchStart:end], '\n')
		if relative < 0 {
			return false
		}
		newline := searchStart + relative
		leftStart := bytes.LastIndexByte(input[:newline], '\n') + 1
		rightEnd := len(input)
		if next := bytes.IndexByte(input[newline+1:], '\n'); next >= 0 {
			rightEnd = newline + 1 + next
		}
		left := bytes.TrimSpace(input[leftStart:newline])
		right := bytes.TrimSpace(input[newline+1 : rightEnd])
		paragraphLeft, paragraphRight := stripCommonCommentLeader(left, right)
		if len(paragraphLeft) == 0 || len(paragraphRight) == 0 {
			return true
		}
		if documentMarkers && isDocumentBoundary(left, right) {
			return true
		}
		searchStart = newline + 1
	}
	return false
}

func stripCommonCommentLeader(left, right []byte) ([]byte, []byte) {
	for _, leader := range [][]byte{[]byte("//"), []byte("--"), []byte("#"), []byte("*"), []byte(";"), []byte("%")} {
		strippedLeft, leftHasLeader := stripCommentLeader(left, leader)
		strippedRight, rightHasLeader := stripCommentLeader(right, leader)
		if leftHasLeader && rightHasLeader {
			return strippedLeft, strippedRight
		}
	}
	return left, right
}

func stripCommentLeader(line, leader []byte) ([]byte, bool) {
	if !bytes.HasPrefix(line, leader) {
		return line, false
	}
	for bytes.HasPrefix(line, leader) {
		line = line[len(leader):]
	}
	return bytes.TrimSpace(line), true
}

func usesDocumentMarkers(filePath string) bool {
	switch strings.ToLower(pathpkg.Ext(filepathSlash(filePath))) {
	case ".md", ".markdown", ".mdown", ".mdx", ".mkd":
		return true
	}
	return strings.EqualFold(pathpkg.Base(filepathSlash(filePath)), "readme")
}

func isDocumentBoundary(left, right []byte) bool {
	return isHeadingLine(left) || isHeadingLine(right) || isTableLine(left) ||
		isTableLine(right) || isListItem(right)
}

func isHeadingLine(line []byte) bool { return line[0] == '#' || line[0] == '=' }

func isTableLine(line []byte) bool { return line[0] == '|' || line[len(line)-1] == '|' }

func isListItem(line []byte) bool {
	if len(line) < minimumMarkerLength {
		return false
	}
	switch line[0] {
	case '-', '*', '+', '>':
		return line[1] == ' ' || line[1] == '\t'
	}
	index := 0
	for index < len(line) && line[index] >= '0' && line[index] <= '9' {
		index++
	}
	if index == 0 || index+1 >= len(line) || (line[index] != '.' && line[index] != ')') {
		return false
	}
	return line[index+1] == ' ' || line[index+1] == '\t'
}

func isLegalFile(filePath string) bool {
	cleaned := filepathSlash(filePath)
	parts := strings.Split(cleaned, "/")
	for _, directory := range parts[:len(parts)-1] {
		switch strings.ToLower(directory) {
		case "license", "licenses", "licence", "licences":
			return true
		}
	}
	name := strings.ToLower(pathpkg.Base(cleaned))
	for _, prefix := range []string{
		"licenses", "license", "licences", "licence", "copying", "mit-license",
		"notices", "notice", "copyright", "unlicense",
	} {
		if hasLegalNamePrefix(name, prefix) {
			return true
		}
	}
	return false
}

func isNoticeFile(filePath string) bool {
	name := strings.ToLower(pathpkg.Base(filepathSlash(filePath)))
	return hasLegalNamePrefix(name, "notice") || hasLegalNamePrefix(name, "notices")
}

func isReadmeFile(filePath string) bool {
	name := strings.ToLower(pathpkg.Base(filepathSlash(filePath)))
	return name == "readme" || strings.HasPrefix(name, "readme.")
}

func hasLegalNamePrefix(name, prefix string) bool {
	if name == prefix {
		return true
	}
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return false
	}
	switch name[len(prefix)] {
	case '.', '-', '_':
		return true
	default:
		return false
	}
}

func filepathSlash(value string) string { return strings.ReplaceAll(value, "\\", "/") }
