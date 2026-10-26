package endpoint

// macOS telemetry adapters: eslogger (Endpoint Security) JSON and the
// unified log (`log show --style ndjson|json`). See eslogger.go and
// unifiedlog.go.

const macOSFormatList = "eslogger|unifiedlog"

func loadMacOS(path string, f Format) (*LoadResult, bool, error) {
	var res *LoadResult
	var err error
	switch f {
	case FormatESLogger:
		res, err = loadESLogger(path)
	case FormatUnifiedLog:
		res, err = loadUnifiedLog(path)
	default:
		return nil, false, nil
	}
	return res, true, err
}

// sniffMacOS recognizes the macOS formats by content. It runs before the
// generic JSON fallback, which used to take eslogger lines by field alias.
func sniffMacOS(head []byte) Format {
	switch {
	case sniffESLogger(head):
		return FormatESLogger
	case sniffUnifiedLog(head):
		return FormatUnifiedLog
	}
	return ""
}
