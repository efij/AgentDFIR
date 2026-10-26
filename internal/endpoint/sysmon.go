package endpoint

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/endpoint/evtx"
)

// Sysmon operational log exported as XML (wevtutil qe
// Microsoft-Windows-Sysmon/Operational /f:xml, or Event Viewer "Save as
// XML"); raw .evtx files go through the native reader in evtx.go and
// share the same mapping. Events used:
//
//	1  ProcessCreate   3  NetworkConnect   11 FileCreate   23 FileDelete   2 FileCreateTime
//
// The Windows context events (Sysmon 5, 12-14 and the Security,
// PowerShell 4103, TaskScheduler and WMI-Activity events in evtxkinds.go)
// are read from the same export, from any channel; an event without a
// Provider is taken as Sysmon, as this adapter always did.
type xmlEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		Channel   string `xml:"Channel"`
		Execution struct {
			ProcessID string `xml:"ProcessID,attr"`
		} `xml:"Execution"`
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
	// UserData holds one provider element whose children are the fields
	// (WMI-Activity, Eventlog).
	UserData struct {
		Inner struct {
			Fields []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:",any"`
	} `xml:"UserData"`
}

func loadSysmonXML(path string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &LoadResult{}
	base := baseName(path)
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
		for _, x := range ev.UserData.Inner.Fields {
			if _, dup := d[x.XMLName.Local]; !dup {
				d[x.XMLName.Local] = strings.TrimSpace(x.Value)
			}
		}
		wev := &evtx.Event{Data: d, System: evtx.System{Provider: firstOf(ev.System.Provider.Name, "Microsoft-Windows-Sysmon"),
			EventID: strings.TrimSpace(ev.System.EventID), TimeCreated: ev.System.TimeCreated.SystemTime, EventRecordID: strings.TrimSpace(ev.System.EventRecordID),
			Channel: ev.System.Channel, ProcessID: ev.System.Execution.ProcessID}}
		if res.addWinContext(wev, "file "+base) {
			continue
		}
		res.addSysmon(ev.System.EventID, ev.System.EventRecordID, ev.System.TimeCreated.SystemTime, d)
	}
	return res, nil
}

// addSysmon maps one Sysmon event (EventData name → value) to a Record.
// The XML export and native .evtx adapters share it so both inputs
// corroborate and contradict identically.
func (res *LoadResult) addSysmon(eventID, recordID, systemTime string, d map[string]string) {
	ts, ok := parseTime(firstOf(d["UtcTime"], systemTime))
	if !ok {
		res.problem("event " + recordID + ": no timestamp")
		return
	}
	ref := fmt.Sprintf("sysmon:%s (record %s)", eventID, recordID)
	pid, _ := strconv.Atoi(d["ProcessId"])
	base := Record{Time: ts, PID: pid, Exe: d["Image"], User: d["User"], Source: "sysmon", Ref: ref}
	switch eventID {
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
	case "22":
		// DNS query. It stays kind "network", not the resolver-log kind
		// "dns": Sysmon names the process that resolved the name, so the
		// record carries process identity, can raise UNLOGGED_AGENT_NETWORK
		// for a lookup made by the agent, and corroborates like event 3
		// (see docs/endpoint-corroboration.md).
		if d["QueryName"] == "" {
			res.problem(ref + ": DNS query without a name")
			return
		}
		base.Kind = "network"
		base.DestHost = d["QueryName"]
		base.Ref = fmt.Sprintf("sysmon:%s (record %s, dns)", eventID, recordID)
		res.Records = append(res.Records, base)
	case "11", "2", "23", "26":
		base.Kind = "file"
		base.FilePath = d["TargetFilename"]
		switch eventID {
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
