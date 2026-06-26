package cmd

// Output formats
const (
	formatText     = "text"
	formatJSON     = "json"
	formatCSV      = "csv"
	formatXML      = "xml"
	formatSARIF    = "sarif"
	formatSQL      = "sql"
	formatMarkdown = "markdown"
)

// Git refs
const refHEAD = "HEAD"

// Dependency types
const depTypeRuntime = "runtime"

// Change types
const (
	changeTypeAdded    = "added"
	changeTypeModified = "modified"
	changeTypeRemoved  = "removed"
)

// Manifest kinds
const manifestKindLockfile = "lockfile"

// Update severity levels
const (
	updateMajor = "major"
	updateMinor = "minor"
	updatePatch = "patch"
)

// OS names
const osWindows = "windows"

// Version info defaults
const versionUnknown = "unknown"

// Ecosystem names
const ecosystemNPM = "npm"

// Table display values
const displayYes = "yes"
