package report

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

// Validator bounds: RSMF files are inputs too when validated on their own.
const (
	maxRSMFBytes     = 512 << 20
	maxRSMFZipBytes  = 512 << 20
	maxRSMFEntries   = 100000
	maxManifestBytes = 256 << 20
	maxRSMFProblems  = 200
)

// rsmfEventTypes are the event types of the RSMF 2.0 manifest.
var rsmfEventTypes = map[string]bool{
	"message": true, "disclaimer": true, "join": true, "leave": true,
	"history": true, "unknown": true, "call": true,
}

// ValidateRSMF checks one .rsmf message against the rules this
// implementation enforces from the RSMF 2.0 structure: the RFC 5322
// envelope and X-RSMF headers, an rsmf.zip attachment holding
// rsmf_manifest.json, and the manifest itself (see ValidateRSMFManifest).
// It returns human-readable problems; none means valid. Structural
// validation only — it does not prove a review platform will accept the
// file.
func ValidateRSMF(data []byte) []string {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	if len(data) > maxRSMFBytes {
		return []string{"file larger than validator bound"}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return []string{"not an RFC 5322 message: " + err.Error()}
	}
	hv := func(k string) string { return msg.Header.Get(k) }
	if hv("X-RSMF-Version") != RSMFVersion {
		add("X-RSMF-Version is %q, want %s", hv("X-RSMF-Version"), RSMFVersion)
	}
	for _, k := range []string{"X-RSMF-Generator", "X-RSMF-BeginDate", "X-RSMF-EndDate", "X-RSMF-EventCount", "From", "Date"} {
		if strings.TrimSpace(hv(k)) == "" {
			add("missing header %s", k)
		}
	}
	mt, params, err := mime.ParseMediaType(hv("Content-Type"))
	if err != nil || mt != "multipart/mixed" || params["boundary"] == "" {
		add("Content-Type must be multipart/mixed with a boundary")
		return probs
	}
	var zipData []byte
	sawText := false
	mr := multipart.NewReader(io.LimitReader(msg.Body, maxRSMFBytes), params["boundary"])
	for i := 0; ; i++ {
		if i > 64 {
			add("too many MIME parts")
			break
		}
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			add("MIME structure: %v", err)
			break
		}
		pt, _, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
		_, dp, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if pt == "text/plain" && dp["filename"] == "" {
			sawText = true
		}
		if dp["filename"] == "rsmf.zip" {
			if zipData != nil {
				add("more than one rsmf.zip attachment")
				continue
			}
			var r io.Reader = part
			if strings.EqualFold(part.Header.Get("Content-Transfer-Encoding"), "base64") {
				r = base64.NewDecoder(base64.StdEncoding, part)
			}
			zipData, err = io.ReadAll(io.LimitReader(r, maxRSMFZipBytes+1))
			if err != nil {
				add("rsmf.zip attachment unreadable: %v", err)
				zipData = nil
			} else if len(zipData) > maxRSMFZipBytes {
				add("rsmf.zip larger than validator bound")
				zipData = nil
			}
		}
	}
	if !sawText {
		add("no text/plain body part")
	}
	if zipData == nil {
		add("no rsmf.zip attachment")
		return probs
	}
	man, files, zprobs := readRSMFZip(zipData)
	probs = append(probs, zprobs...)
	if man == nil {
		return probs
	}
	probs = append(probs, ValidateRSMFManifest(man, files)...)

	// Headers must agree with the manifest.
	if n, err := strconv.Atoi(hv("X-RSMF-EventCount")); err != nil || n != len(man.Events) {
		add("X-RSMF-EventCount %q does not match %d manifest events", hv("X-RSMF-EventCount"), len(man.Events))
	}
	if ac := hv("X-RSMF-AttachmentCount"); ac != "" {
		natt := 0
		for _, e := range man.Events {
			natt += len(e.Attachments)
		}
		if n, err := strconv.Atoi(ac); err != nil || n != natt {
			add("X-RSMF-AttachmentCount %q does not match %d manifest attachments", ac, natt)
		}
	}
	var lo, hi time.Time
	for _, e := range man.Events {
		if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
			if lo.IsZero() || t.Before(lo) {
				lo = t
			}
			if t.After(hi) {
				hi = t
			}
		}
	}
	if !lo.IsZero() {
		if t, err := time.Parse(time.RFC3339Nano, hv("X-RSMF-BeginDate")); err != nil || !t.Equal(lo) {
			add("X-RSMF-BeginDate %q is not the earliest event time %s", hv("X-RSMF-BeginDate"), rsmfTime(lo))
		}
		if t, err := time.Parse(time.RFC3339Nano, hv("X-RSMF-EndDate")); err != nil || !t.Equal(hi) {
			add("X-RSMF-EndDate %q is not the latest event time %s", hv("X-RSMF-EndDate"), rsmfTime(hi))
		}
	}
	return capProblems(probs)
}

// readRSMFZip opens rsmf.zip and decodes rsmf_manifest.json, returning the
// size of every other entry by name.
func readRSMFZip(data []byte) (*RSMFManifest, map[string]int64, []string) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, nil, []string{"rsmf.zip is not a zip archive: " + err.Error()}
	}
	if len(zr.File) > maxRSMFEntries {
		return nil, nil, []string{"rsmf.zip has too many entries"}
	}
	files := map[string]int64{}
	var man *RSMFManifest
	var probs []string
	for _, f := range zr.File {
		if _, dup := files[f.Name]; dup || (f.Name == "rsmf_manifest.json" && man != nil) {
			probs = append(probs, "duplicate zip entry "+strconv.Quote(f.Name))
			continue
		}
		if f.Name != "rsmf_manifest.json" {
			files[f.Name] = int64(f.UncompressedSize64)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			probs = append(probs, "rsmf_manifest.json unreadable: "+err.Error())
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxManifestBytes+1))
		rc.Close()
		if err != nil || len(b) > maxManifestBytes {
			probs = append(probs, "rsmf_manifest.json unreadable or too large")
			continue
		}
		var m RSMFManifest
		if err := json.Unmarshal(b, &m); err != nil {
			probs = append(probs, "rsmf_manifest.json is not valid JSON: "+err.Error())
			continue
		}
		man = &m
	}
	if man == nil && len(probs) == 0 {
		probs = append(probs, "rsmf.zip has no rsmf_manifest.json")
	}
	return man, files, probs
}

// ValidateRSMFManifest checks the manifest rules this writer implements:
// version, required fields, unique ids per kind, referential integrity
// (conversation and event participants, event conversations, parents),
// ISO-8601 UTC timestamps, known event types, and that every attachment is
// present in the archive (files: entry name → size) with the stated size.
// files may be nil to skip the archive checks.
func ValidateRSMFManifest(m *RSMFManifest, files map[string]int64) []string {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	if m.Version != RSMFVersion {
		add("manifest version %q, want %s", m.Version, RSMFVersion)
	}
	parts := map[string]bool{}
	for i, p := range m.Participants {
		switch {
		case p.ID == "":
			add("participants[%d]: missing id", i)
		case parts[p.ID]:
			add("participants[%d]: duplicate id %q", i, p.ID)
		}
		parts[p.ID] = true
		if strings.TrimSpace(p.Display) == "" {
			add("participant %q: missing display", p.ID)
		}
		checkCustom(p.Custom, "participant "+p.ID, add)
	}
	convs := map[string]bool{}
	if len(m.Conversations) == 0 {
		add("no conversations")
	}
	for i, c := range m.Conversations {
		switch {
		case c.ID == "":
			add("conversations[%d]: missing id", i)
		case convs[c.ID]:
			add("conversations[%d]: duplicate id %q", i, c.ID)
		}
		convs[c.ID] = true
		if strings.TrimSpace(c.Display) == "" {
			add("conversation %q: missing display", c.ID)
		}
		if c.Type != "" && c.Type != "direct" && c.Type != "channel" {
			add("conversation %q: type %q is not direct or channel", c.ID, c.Type)
		}
		for _, pid := range c.Participants {
			if !parts[pid] {
				add("conversation %q: participant %q is not in participants", c.ID, pid)
			}
		}
		checkCustom(c.Custom, "conversation "+c.ID, add)
	}
	events := map[string]bool{}
	for _, e := range m.Events {
		if e.ID != "" {
			if events[e.ID] {
				add("duplicate event id %q", e.ID)
			}
			events[e.ID] = true
		}
	}
	atts := map[string]bool{}
	for i, e := range m.Events {
		where := fmt.Sprintf("events[%d] %q", i, e.ID)
		if e.ID == "" {
			add("events[%d]: missing id", i)
		}
		if !rsmfEventTypes[e.Type] {
			add("%s: unknown type %q", where, e.Type)
		}
		if !convs[e.Conversation] {
			add("%s: conversation %q is not in conversations", where, e.Conversation)
		}
		switch {
		case e.Participant != "" && !parts[e.Participant]:
			add("%s: participant %q is not in participants", where, e.Participant)
		case e.Participant == "" && (e.Type == "message" || e.Type == "join" || e.Type == "leave"):
			add("%s: %s event without a participant", where, e.Type)
		}
		if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err != nil {
			add("%s: timestamp %q is not ISO-8601", where, e.Timestamp)
		} else if _, off := t.Zone(); off != 0 {
			add("%s: timestamp %q is not UTC", where, e.Timestamp)
		}
		if e.Parent != "" && (!events[e.Parent] || e.Parent == e.ID) {
			add("%s: parent %q is not another event", where, e.Parent)
		}
		for _, a := range e.Attachments {
			if a.ID == "" {
				add("%s: attachment without id", where)
				continue
			}
			if atts[a.ID] {
				add("%s: duplicate attachment id %q", where, a.ID)
			}
			atts[a.ID] = true
			if strings.TrimSpace(a.Display) == "" {
				add("%s: attachment %q without display", where, a.ID)
			}
			if files != nil {
				if sz, ok := files[a.ID]; !ok {
					add("%s: attachment %q missing from rsmf.zip", where, a.ID)
				} else if sz != a.Size {
					add("%s: attachment %q size %d, archive has %d", where, a.ID, a.Size, sz)
				}
			}
		}
		checkCustom(e.Custom, where, add)
	}
	return capProblems(probs)
}

func checkCustom(cs []RSMFCustom, where string, add func(string, ...any)) {
	for _, c := range cs {
		if strings.TrimSpace(c.Name) == "" {
			add("%s: custom field without a name", where)
		}
	}
}

func capProblems(p []string) []string {
	if len(p) > maxRSMFProblems {
		n := len(p) - maxRSMFProblems
		p = append(p[:maxRSMFProblems:maxRSMFProblems], fmt.Sprintf("… and %d more problem(s)", n))
	}
	return p
}
