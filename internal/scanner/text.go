package scanner

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"

	licenses "github.com/git-pkgs/licenses"
)

const (
	binaryProbeSize = 8 << 10
	utf8BOMSize     = 3
)

type decodedText struct {
	data       []byte
	offsets    []int
	offsetBase int
	encoding   string
}

func isBinary(data []byte) bool {
	probe := data[:min(len(data), binaryProbeSize)]
	if bytes.HasPrefix(probe, []byte{0xff, 0xfe}) || bytes.HasPrefix(probe, []byte{0xfe, 0xff}) {
		return false
	}
	return bytes.IndexByte(probe, 0) >= 0
}

func decodeText(data []byte) decodedText {
	switch {
	case bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}):
		return decodedText{data: data[utf8BOMSize:], offsetBase: utf8BOMSize, encoding: "utf-8"}
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		return decodeUTF16(data, binary.LittleEndian, "utf-16le")
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		return decodeUTF16(data, binary.BigEndian, "utf-16be")
	case utf8.Valid(data):
		return decodedText{data: data, encoding: "utf-8"}
	default:
		return decodeLatin1(data)
	}
}

func decodeUTF16(data []byte, order binary.ByteOrder, encoding string) decodedText {
	decoded := decodedText{data: make([]byte, 0, len(data)), offsets: []int{2}, encoding: encoding}
	for position := 2; position < len(data); {
		start := position
		var character rune
		if position+1 >= len(data) {
			character = utf8.RuneError
			position++
		} else {
			first := order.Uint16(data[position : position+2])
			position += 2
			character = rune(first)
			if utf16.IsSurrogate(character) {
				if position+1 < len(data) {
					second := rune(order.Uint16(data[position : position+2]))
					if decodedRune := utf16.DecodeRune(character, second); decodedRune != utf8.RuneError {
						character = decodedRune
						position += 2
					} else {
						character = utf8.RuneError
					}
				} else {
					character = utf8.RuneError
				}
			}
		}
		decoded.appendRune(character, start, position)
	}
	return decoded
}

func decodeLatin1(data []byte) decodedText {
	decoded := decodedText{data: make([]byte, 0, len(data)), offsets: []int{0}, encoding: "iso-8859-1"}
	for position, value := range data {
		decoded.appendRune(rune(value), position, position+1)
	}
	return decoded
}

func (decoded *decodedText) appendRune(character rune, rawStart, rawEnd int) {
	start := len(decoded.data)
	decoded.data = utf8.AppendRune(decoded.data, character)
	for position := start; position < len(decoded.data); position++ {
		if position == len(decoded.data)-1 {
			decoded.offsets = append(decoded.offsets, rawEnd)
		} else {
			decoded.offsets = append(decoded.offsets, rawStart)
		}
	}
}

func (decoded decodedText) rawOffset(offset int) int {
	if decoded.offsets != nil {
		return decoded.offsets[offset]
	}
	return offset + decoded.offsetBase
}

func remapResultOffsets(result *licenses.Result, decoded decodedText) {
	if decoded.offsets == nil && decoded.offsetBase == 0 {
		return
	}
	for detectionIndex := range result.Detections {
		for matchIndex := range result.Detections[detectionIndex].Matches {
			match := &result.Detections[detectionIndex].Matches[matchIndex]
			match.Start = decoded.rawOffset(match.Start)
			match.End = decoded.rawOffset(match.End)
		}
	}
	for matchIndex := range result.Clues {
		match := &result.Clues[matchIndex]
		match.Start = decoded.rawOffset(match.Start)
		match.End = decoded.rawOffset(match.End)
	}
}
