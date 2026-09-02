package endpoint

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Sysmon operational log exported as XML (wevtutil qe
// Microsoft-Windows-Sysmon/Operational /f:xml, or Event Viewer "Save as
// XML"). Raw .evtx is not parsed; export first. Events used:
//
//	1  ProcessCreate   3  NetworkConnect   11 FileCreate   23 FileDelete   2 FileCreateTime
type xmlEvent struct {
	System struct {
		EventID     string `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		EventRecordID string `xml:"EventRecordID"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func loadSysmonXML(path string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &LoadResult{}
	// Exports are often a bare sequence of <Event> elements; wrap them.
	rd := io.MultiReader(strings.NewReader("<Events>"), stripXMLDecl(f), strings.NewReader("</Events>"))
	dec := xml.NewDecoder(rd)
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			res.problem("xml: " + err.Error())
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var ev xmlEvent
		if err := dec.DecodeElement(&ev, &se); err != nil {
			res.problem("event: " + err.Error())
			continue
		}
		d := map[string]string{}
		for _, x := range ev.EventData.Data {
			d[x.Name] = strings.TrimSpace(x.Value)
		}
		ts, ok := parseTime(firstOf(d["UtcTime"], ev.System.TimeCreated.SystemTime))
		if !ok {
			res.problem("event " + ev.System.EventRecordID + ": no timestamp")
			continue
		}
		ref := fmt.Sprintf("sysmon:%s (record %s)", ev.System.EventID, ev.System.EventRecordID)
		pid, _ := strconv.Atoi(d["ProcessId"])
		base := Record{Time: ts, PID: pid, Exe: d["Image"], User: d["User"], Source: "sysmon", Ref: ref}
		switch ev.System.EventID {
		case "1":
			base.Kind = "process"
			base.Cmdline = d["CommandLine"]
			base.PPID, _ = strconv.Atoi(d["ParentProcessId"])
			base.ParentExe = d["ParentImage"]
			res.Records = append(res.Records, base)
		case "3":
			base.Kind = "network"
			base.DestIP = d["DestinationIp"]
			base.DestPort, _ = strconv.Atoi(d["DestinationPort"])
			base.DestHost = d["DestinationHostname"]
			res.Records = append(res.Records, base)
		case "11", "2", "23", "26":
			base.Kind = "file"
			base.FilePath = d["TargetFilename"]
			switch ev.System.EventID {
			case "11":
				base.FileOp = "create"
			case "23", "26":
				base.FileOp = "delete"
			default:
				base.FileOp = "modify"
			}
			res.Records = append(res.Records, base)
		}
	}
	return res, nil
}

// stripXMLDecl removes a leading <?xml …?> declaration so the wrapper
// root can precede the content.
func stripXMLDecl(r io.Reader) io.Reader {
	head := make([]byte, 256)
	n, _ := io.ReadFull(r, head)
	head = head[:n]
	s := string(head)
	s = strings.TrimLeft(s, "\xef\xbb\xbf \t\r\n")
	if strings.HasPrefix(s, "<?xml") {
		if i := strings.Index(s, "?>"); i >= 0 {
			s = s[i+2:]
		}
	}
	return io.MultiReader(strings.NewReader(s), r)
}

func firstOf(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
