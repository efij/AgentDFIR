package plaso

import (
	"strings"
	"testing"
)

func TestReadFormats(t *testing.T) {
	jl := `{"data_type": "chrome:history:page_visited", "timestamp": 1740734100000000, "timestamp_desc": "Last Visited Time", "parser": "sqlite/chrome_27_history", "url": "https://claude.ai/chat/x", "title": "T"}` + "\n" +
		`{"data_type": "fs:stat", "timestamp": 0, "parser": "filestat"}` + "\n" + "[1,2]\n"
	if Sniff([]byte(jl)) != FormatJSONLine {
		t.Fatal("sniff json_line")
	}
	var got []Entry
	st, err := Read(strings.NewReader(jl), FormatJSONLine, func(e Entry) error { got = append(got, e); return nil })
	if err != nil || st.Entries != 2 || st.Malformed != 1 || st.Undated != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	if got[0].Time.Format("2006-01-02T15:04:05Z") != "2025-02-28T09:15:00Z" || got[0].URL != "https://claude.ai/chat/x" || got[0].Source != "chrome" || got[0].Line != 1 {
		t.Fatalf("%+v", got[0])
	}
	csv := L2TCSVHeader + "\n" + `02/28/2025,09:15:00,UTC,.A..,WEBHIST,Chrome History,Last Visited Time,u,h,s,https://chatgpt.com/c/abc (x),2,f,-,-,sqlite/chrome_27_history,-` + "\n"
	if Sniff([]byte(csv)) != FormatL2TCSV {
		t.Fatal("sniff l2tcsv")
	}
	got = nil
	if _, err := Read(strings.NewReader(csv), FormatL2TCSV, func(e Entry) error { got = append(got, e); return nil }); err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	if got[0].URL != "https://chatgpt.com/c/abc" || got[0].Time.IsZero() || got[0].Parser != "sqlite/chrome_27_history" {
		t.Fatalf("%+v", got[0])
	}
	if Sniff([]byte(`{"a": 1}`)) != "" || Sniff([]byte("a,b,c\n")) != "" {
		t.Fatal("false positive")
	}
}
