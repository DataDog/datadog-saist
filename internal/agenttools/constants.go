package agenttools

const (
	ToolSearchCode    = "search_code"
	ToolReadFile      = "read_file"
	ToolListDirectory = "list_directory"

	StopReasonInvalidArguments = "invalid_arguments"
	StopReasonPathGlobRequired = "path_glob_required"
	StopReasonTimeout          = "timeout"
	StopReasonCanceled         = "canceled"

	SymbolSearchDefinition SymbolSearchKind = "definition"
	SymbolSearchReference  SymbolSearchKind = "reference"

	maxReadFileLines      = 400
	maxReadFileBytes      = 64 * 1024
	maxReadFileInputBytes = 1 << 20
	defaultSearchResults  = 50
	maxSearchResults      = 200
	maxSearchFilesScanned = 5000
	maxScanFileBytes      = 1 << 20
	binarySniffBytes      = 8000
	snippetMaxRunes       = 200
	defaultListEntries    = 200
	maxListEntries        = 500
	maxListEntriesScanned = 5000
	darwinPathMax         = 1024

	// Adaptive default-scope widening for search_code. When a call omits path_glob
	// and the context carries a search anchor (see WithSearchAnchor, typically the
	// flagged file's directory), the search starts at the anchor's own subtree and
	// widens toward the scan root one ancestor at a time. It stops at the narrowest
	// scope that yields at least adaptiveSearchMinMatches matches, preferring local
	// evidence and only scanning the whole root when nearby scopes are too sparse.
	//
	// adaptiveSearchMaxLocalScopes bounds how many nested anchor-relative scopes are
	// tried before jumping straight to the whole root, so a deep flagged path never
	// re-walks every ancestor level. These are deterministic given the checkout and
	// query, and the effective scope is always reported in SearchScope.PathGlob.
	adaptiveSearchMinMatches     = 3
	adaptiveSearchMaxLocalScopes = 3
)
