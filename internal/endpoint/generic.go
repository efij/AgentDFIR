package endpoint

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Generic process/network/file event exports: JSON lines (Velociraptor,
// osquery, evtx_dump, macOS eslogger) or CSV (Velociraptor/EDR exports).
// Nested JSON is flattened to dot paths and matched against field aliases,
// so a vendor's naming rarely needs a hand-written adapter.

var aliases = map[string][]string{
	"time":       {"time", "ts", "timestamp", "Timestamp", "UtcTime", "EventTime", "event_time", "unixTime", "@timestamp", "System.TimeCreated.SystemTime", "Event.System.TimeCreated.#attributes.SystemTime", "datetime", "created_utc", "StartTime", "start_time"},
	"pid":        {"event.exec.target.audit_token.pid", "pid", "Pid", "ProcessId", "ProcessID", "process_id", "process.pid", "process.audit_token.pid", "Event.EventData.ProcessId"},
	"ppid":       {"event.exec.target.ppid", "ppid", "Ppid", "ParentProcessId", "parent_pid", "parent", "process.ppid", "process.parent_audit_token.pid", "Event.EventData.ParentProcessId"},
	"exe":        {"event.exec.target.executable.path", "exe", "Exe", "Image", "path", "Path", "executable", "process.executable.path", "Event.EventData.Image", "ImagePath", "image"},
	"cmdline":    {"cmdline", "Cmdline", "CommandLine", "command_line", "commandline", "argv", "args", "event.exec.args", "Event.EventData.CommandLine", "Command", "cmd"},
	"parent_exe": {"ParentImage", "parent_path", "parent_exe", "ParentPath", "process.parent.executable.path", "Event.EventData.ParentImage", "parent_image"},
	"user":       {"user", "User", "Username", "username", "uid", "process.audit_token.euid", "Event.EventData.User"},
	"dest_ip":    {"DestinationIp", "dest_ip", "remote_address", "daddr", "dst_ip", "destination.ip", "Event.EventData.DestinationIp", "raddr"},
	"dest_port":  {"DestinationPort", "dest_port", "remote_port", "dport", "dst_port", "destination.port", "Event.EventData.DestinationPort", "rport"},
	"dest_host":  {"DestinationHostname", "dest_host", "hostname", "destination.domain", "Event.EventData.DestinationHostname", "domain"},
	"file_path":  {"TargetFilename", "target_path", "file_path", "filename", "FileName", "file.path", "event.create.destination.existing_file.path", "event.create.destination.new_path.filename", "event.unlink.target.path", "event.open.file.path", "Event.EventData.TargetFilename"},
	"event_id":   {"EventID", "event_id", "System.EventID", "Event.System.EventID", "EventId"},
	"event_type": {"event_type", "type", "action", "kind", "Type", "Action", "Operation", "operation"},
}

func loadJSONL(path string) (*LoadResult, error) {
	res := &LoadResult{}
	// A JSON array export is also accepted (evtx_dump -o json, log show --style json).
	head := make([]byte, 1)
	if f, err := os.Open(path); err == nil {
		_, _ = io.ReadFull(f, head)
		f.Close()
	}
	if head[0] == '[' {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var arr []map[string]any
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, fmt.Errorf("json array: %w", err)
		}
		for i, doc := range arr {
			res.add(flatten(doc), fmt.Sprintf("%s[%d]", baseName(path), i))
		}
		return res, nil
	}
	err := scanLines(path, func(line string, n int) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			res.problem(fmt.Sprintf("line %d: %v", n, err))
			return
		}
		res.add(flatten(doc), fmt.Sprintf("%s:%d", baseName(path), n))
	})
	return res, err
}

func loadCSV(path string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &LoadResult{}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("csv header: %w", err)
	}
	for i := range header {
		header[i] = strings.TrimSpace(strings.TrimPrefix(header[i], "\xef\xbb\xbf"))
	}
	n := 1
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		n++
		if err != nil {
			res.problem(fmt.Sprintf("row %d: %v", n, err))
			continue
		}
		flat := map[string]string{}
		for i, v := range row {
			if i < len(header) {
				flat[header[i]] = v
			}
		}
		res.add(flat, fmt.Sprintf("%s:%d", baseName(path), n))
	}
	return res, nil
}

// add builds a Record from a flat field map, if it has a time and a kind.
func (res *LoadResult) add(flat map[string]string, ref string) {
	get := func(key string) string {
		for _, a := range aliases[key] {
			if v, ok := flat[a]; ok && v != "" {
				return v
			}
		}
		return ""
	}
	ts, ok := parseTime(get("time"))
	if !ok {
		res.problem(ref + ": no recognizable timestamp")
		return
	}
	rec := Record{Time: ts, Source: "export", Ref: ref, Exe: get("exe"), Cmdline: get("cmdline"), ParentExe: get("parent_exe"), User: get("user")}
	rec.PID, _ = strconv.Atoi(get("pid"))
	rec.PPID, _ = strconv.Atoi(get("ppid"))
	// macOS Endpoint Security exec events: `process` is the parent that
	// called exec, `event.exec.target` is the new image.
	if flat["event.exec.target.executable.path"] != "" {
		rec.ParentExe = flat["process.executable.path"]
		if rec.PPID == 0 {
			rec.PPID, _ = strconv.Atoi(flat["process.audit_token.pid"])
		}
	}
	// eslogger args arrive as a JSON array string after flattening.
	if strings.HasPrefix(rec.Cmdline, "[") {
		var parts []string
		if json.Unmarshal([]byte(rec.Cmdline), &parts) == nil {
			rec.Cmdline = strings.Join(parts, " ")
		}
	}
	evID, evType := get("event_id"), strings.ToLower(get("event_type"))
	switch {
	case get("dest_ip") != "" || get("dest_host") != "" || evID == "3" || strings.Contains(evType, "network") || strings.Contains(evType, "connect") || strings.Contains(evType, "socket"):
		rec.Kind = "network"
		rec.DestIP = get("dest_ip")
		rec.DestPort, _ = strconv.Atoi(get("dest_port"))
		rec.DestHost = get("dest_host")
		if rec.DestIP == "" && rec.DestHost == "" {
			res.problem(ref + ": network event without destination")
			return
		}
	case get("file_path") != "" || evID == "11" || evID == "23" || strings.Contains(evType, "file") || strings.Contains(evType, "unlink"):
		rec.Kind = "file"
		rec.FilePath = get("file_path")
		switch {
		case evID == "23" || strings.Contains(evType, "delete") || strings.Contains(evType, "unlink"):
			rec.FileOp = "delete"
		case evID == "11" || strings.Contains(evType, "create"):
			rec.FileOp = "create"
		default:
			rec.FileOp = "modify"
		}
		if rec.FilePath == "" {
			res.problem(ref + ": file event without path")
			return
		}
	case rec.Cmdline != "" || rec.Exe != "":
		rec.Kind = "process"
		if rec.Cmdline == "" {
			rec.Cmdline = rec.Exe
		}
	default:
		res.problem(ref + ": not a process/network/file event")
		return
	}
	res.Records = append(res.Records, rec)
}

// flatten turns nested JSON into dot-path keys with stringified leaves.
// Arrays of scalars are kept as JSON text (cmdline arrays are re-joined).
func flatten(doc map[string]any) map[string]string {
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, val := range t {
				key := k
				if prefix != "" {
					key = prefix + "." + k
				}
				walk(key, val)
			}
		case []any:
			b, _ := json.Marshal(t)
			out[prefix] = string(b)
		case nil:
		case float64:
			if t == float64(int64(t)) {
				out[prefix] = strconv.FormatInt(int64(t), 10)
			} else {
				out[prefix] = strconv.FormatFloat(t, 'f', -1, 64)
			}
		case bool:
			out[prefix] = strconv.FormatBool(t)
		case string:
			out[prefix] = t
		}
	}
	walk("", doc)
	return out
}
