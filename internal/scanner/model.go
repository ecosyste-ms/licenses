package scanner

import licenses "github.com/git-pkgs/licenses"

const (
	ReportSchemaVersion = 1
	ScannerName         = "git-pkgs/licenses"
	ScannerVersion      = "0.2.0"
)

// Report is the v2 response contract.
type Report struct {
	Schema           int               `json:"schema"`
	URL              string            `json:"url"`
	SHA256           string            `json:"sha256"`
	Scanner          ScannerInfo       `json:"scanner"`
	Summary          Summary           `json:"summary"`
	Declared         []DeclaredLicense `json:"declared"`
	Files            []File            `json:"files"`
	AttributionFiles []AttributionFile `json:"attribution_files"`
	Skipped          []Skip            `json:"skipped"`
	Errors           []ScanError       `json:"errors"`
}

type ScannerInfo struct {
	Name    string     `json:"name"`
	Version string     `json:"version"`
	Corpus  CorpusInfo `json:"corpus"`
}

type CorpusInfo struct {
	Version      string `json:"version"`
	SourceCommit string `json:"source_commit"`
	RuleCount    int    `json:"rule_count"`
}

type Summary struct {
	Complete         bool         `json:"complete"`
	FilesVisited     int          `json:"files_visited"`
	FilesScanned     int          `json:"files_scanned"`
	BytesScanned     int64        `json:"bytes_scanned"`
	RootExpressions  []Expression `json:"root_expressions"`
	OtherExpressions []Expression `json:"other_expressions"`
}

type Expression struct {
	Expression     string                  `json:"expression"`
	Identification licenses.Identification `json:"identification"`
}

type DeclaredLicense struct {
	Path                 string `json:"path"`
	Raw                  string `json:"raw"`
	NormalizedExpression string `json:"normalized_expression,omitempty"`
}

type File struct {
	Path                string      `json:"path"`
	Size                int64       `json:"size"`
	SHA256              string      `json:"sha256"`
	Encoding            string      `json:"encoding"`
	LicenseTextCoverage float64     `json:"license_text_coverage"`
	Detections          []Detection `json:"detections"`
	Clues               []Match     `json:"clues"`
}

type Detection struct {
	Expression     string                  `json:"expression"`
	Identification licenses.Identification `json:"identification"`
	Matches        []Match                 `json:"matches"`
}

type Match struct {
	RuleID     string          `json:"rule_id"`
	LicenseIDs []string        `json:"license_ids"`
	Kind       licenses.Kind   `json:"kind"`
	Method     licenses.Method `json:"method"`
	Score      float64         `json:"score"`
	Coverage   float64         `json:"coverage"`
	Start      int             `json:"start"`
	End        int             `json:"end"`
}

type AttributionFile struct {
	Path     string   `json:"path"`
	Roles    []string `json:"roles"`
	SHA256   string   `json:"sha256"`
	Encoding string   `json:"encoding"`
	Content  string   `json:"content"`
}

type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type ScanError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}
