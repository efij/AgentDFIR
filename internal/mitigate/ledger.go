package mitigate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/hashchain"
)

// The ledger answers "who changed this machine's agent config, when, and
// how do I undo it". One hash-chained record per file written, the same
// construction as the custody log and the case notes, so an edited or
// deleted record breaks every record after it. It lives beside the
// backups, outside every case: mitigations are the machine's state, not a
// case's, and one machine has one ledger however many cases it has.

// Record is one ledger line (hashchain adds seq, ts_utc and prev).
type Record struct {
	Seq         int      `json:"seq"`
	TS          string   `json:"ts_utc"`
	Prev        string   `json:"prev"`
	ID          string   `json:"id"`
	Action      string   `json:"action"` // apply | revert
	Operator    string   `json:"operator"`
	Product     string   `json:"product"`
	Kind        string   `json:"kind"`
	Target      string   `json:"target"`
	Items       []Item   `json:"items,omitempty"`
	Packs       []string `json:"packs,omitempty"`
	Rules       []string `json:"rules,omitempty"`
	PackVersion int      `json:"pack_version,omitempty"`
	Created     bool     `json:"created,omitempty"` // the file did not exist before
	SHABefore   string   `json:"sha_before,omitempty"`
	SHAAfter    string   `json:"sha_after"`
	Backup      string   `json:"backup,omitempty"`
	Reverts     string   `json:"reverts,omitempty"` // id of the apply record a revert undoes
}

func (e Env) ledgerPath() string { return filepath.Join(e.StateDir, "ledger.jsonl") }

// Ledger reads every record. A broken chain is returned as an error along
// with the records read, never hidden.
func Ledger(env Env) ([]Record, error) {
	p := env.ledgerPath()
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return out, fmt.Errorf("ledger record %d: %v", len(out), err)
		}
		out = append(out, r)
	}
	if _, err := hashchain.VerifyFile(p); err != nil {
		return out, fmt.Errorf("ledger chain broken: %v", err)
	}
	return out, sc.Err()
}

func appendLedger(env Env, rec map[string]any) error {
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		return err
	}
	p := env.ledgerPath()
	var w *hashchain.Writer
	var err error
	if _, statErr := os.Stat(p); statErr == nil {
		w, err = hashchain.NewAppender(p)
	} else {
		w, err = hashchain.NewWriter(p)
	}
	if err != nil {
		return err
	}
	if err := w.Append(rec); err != nil {
		w.Close()
		return err
	}
	return w.Close()
}

func operator() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func toMap(r Record) map[string]any {
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	delete(m, "seq")
	delete(m, "ts_utc")
	delete(m, "prev")
	return m
}

// writeAtomic replaces target with data: temp file in the same directory,
// fsync, rename. The file keeps its mode; a new file is 0600.
func writeAtomic(target string, data []byte) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(target); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".agentdfir-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, target)
}

// Result of applying one change.
type Result struct {
	Target string
	ID     string
	Err    error
	Note   string
}

// Apply makes the planned changes. Each file is re-read immediately
// before it is written and the change is recomputed on those bytes, so an
// agent that rewrote ~/.claude.json between the plan and the apply does
// not lose its edit. Every write is preceded by a byte-exact backup and
// followed by a ledger record.
func Apply(env Env, pl *Plan) []Result {
	var out []Result
	for _, c := range pl.Changes {
		out = append(out, applyOne(env, c))
	}
	return out
}

func applyOne(env Env, c *Change) Result {
	res := Result{Target: c.Target}
	if why := refuse(c.Target); why != "" {
		res.Err = errors.New(why)
		return res
	}
	cur, err := os.ReadFile(c.Target)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Err = err
		return res
	}
	after, err := Render(c.Kind, cur, c.Items)
	if err != nil {
		res.Err = err
		return res
	}
	if bytes.Equal(after, cur) && existed {
		res.Note = "already in place"
		return res
	}
	if existed && !bytes.Equal(cur, c.Before) {
		res.Note = "the file changed after the plan was printed; the same guardrails were applied to its current contents"
	}
	ts := time.Now().UTC()
	rec := Record{Action: "apply", Operator: operator(), Product: c.Product, Kind: c.Kind, Target: c.Target,
		Items: c.Items, PackVersion: PackVersion, SHAAfter: SHA256(after)}
	rec.Packs, rec.Rules = coverage(c.Items)
	if existed {
		rec.SHABefore = SHA256(cur)
		bdir := filepath.Join(env.StateDir, "backups", ts.Format("20060102T150405Z"), rec.SHABefore[:16])
		if err := os.MkdirAll(bdir, 0o700); err != nil {
			res.Err = err
			return res
		}
		rec.Backup = filepath.Join(bdir, filepath.Base(c.Target))
		if err := os.WriteFile(rec.Backup, cur, 0o400); err != nil {
			res.Err = fmt.Errorf("backup failed, nothing changed: %v", err)
			return res
		}
	} else {
		rec.Created = true
	}
	rec.ID = rec.SHAAfter[:12]
	if err := writeAtomic(c.Target, after); err != nil {
		res.Err = err
		return res
	}
	if err := appendLedger(env, toMap(rec)); err != nil {
		res.Err = fmt.Errorf("file written but the ledger could not be updated: %v (backup: %s)", err, rec.Backup)
		return res
	}
	res.ID = rec.ID
	return res
}

func coverage(items []Item) (packs, rules []string) {
	seenP, seenR := map[string]bool{}, map[string]bool{}
	for _, it := range items {
		if it.Pack != "" && !seenP[it.Pack] {
			seenP[it.Pack] = true
			packs = append(packs, it.Pack)
			if p, ok := PackByID(it.Pack); ok {
				for _, r := range p.Rules {
					if !seenR[r] {
						seenR[r] = true
						rules = append(rules, r)
					}
				}
			}
		}
		if it.Kind == "pin" || it.Kind == "noauto" {
			for r, ctl := range fixRules {
				if (ctl == "mcp-pin" && it.Kind == "pin") || (ctl == "mcp-autoapprove" && it.Kind == "noauto") {
					if !seenR[r] {
						seenR[r] = true
						rules = append(rules, r)
					}
				}
			}
		}
	}
	return
}

// State of one applied change, as found now.
type State struct {
	Record  Record   `json:"record"`
	State   string   `json:"state"` // in_place | drifted | missing | reverted
	Missing []string `json:"missing,omitempty"`
}

// Status verifies every apply record against the file as it is now.
// Drifted means something (or an agent: that is AGENT_SELF_MODIFICATION)
// removed a guardrail after it went in.
func Status(env Env) ([]State, error) {
	recs, err := Ledger(env)
	reverted := map[string]bool{}
	for _, r := range recs {
		if r.Action == "revert" {
			reverted[r.Reverts] = true
		}
	}
	var out []State
	for _, r := range recs {
		if r.Action != "apply" {
			continue
		}
		st := State{Record: r}
		switch {
		case reverted[r.ID]:
			st.State = "reverted"
		default:
			cur, rerr := os.ReadFile(r.Target)
			if rerr != nil {
				st.State = "missing"
				break
			}
			miss := Missing(r.Kind, cur, r.Items)
			if len(miss) == 0 {
				st.State = "in_place"
			} else {
				st.State = "drifted"
				for _, m := range miss {
					st.Missing = append(st.Missing, strings.ReplaceAll(m.Key, "\x1f", " "))
				}
			}
		}
		out = append(out, st)
	}
	return out, err
}

// Revert restores the file an apply record changed. It refuses when the
// file has changed since, unless force: restoring the backup would then
// throw away someone's later edit.
func Revert(env Env, id string, force bool) error {
	recs, err := Ledger(env)
	if err != nil {
		return err
	}
	var target *Record
	for i := range recs {
		if recs[i].Action == "revert" && recs[i].Reverts == id {
			return fmt.Errorf("%s was already reverted", id)
		}
	}
	for i := range recs {
		if recs[i].Action == "apply" && (recs[i].ID == id || strings.HasPrefix(recs[i].ID, id) && len(id) >= 6) {
			target = &recs[i]
		}
	}
	if target == nil {
		return fmt.Errorf("no applied change %q in the ledger (agentdfir mitigate --status lists them)", id)
	}
	if why := refuse(target.Target); why != "" {
		return errors.New(target.Target + ": " + why)
	}
	cur, err := os.ReadFile(target.Target)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && SHA256(cur) != target.SHAAfter && !force {
		return fmt.Errorf("%s changed after agentdfir wrote it; restoring the backup would discard that change. Re-run with --force to restore anyway", target.Target)
	}
	if target.Created {
		if err == nil {
			if rmErr := os.Remove(target.Target); rmErr != nil {
				return rmErr
			}
		}
	} else {
		data, rerr := os.ReadFile(target.Backup)
		if rerr != nil {
			return fmt.Errorf("backup missing (%v); nothing restored", rerr)
		}
		if SHA256(data) != target.SHABefore {
			return fmt.Errorf("backup %s does not match its recorded hash; nothing restored", target.Backup)
		}
		if err := writeAtomic(target.Target, data); err != nil {
			return err
		}
	}
	rec := Record{Action: "revert", ID: "r-" + target.ID, Reverts: target.ID, Operator: operator(), Product: target.Product,
		Kind: target.Kind, Target: target.Target, SHABefore: SHA256(cur), SHAAfter: target.SHABefore}
	return appendLedger(env, toMap(rec))
}

// RevertAll reverts every applied change, newest first.
func RevertAll(env Env, force bool) (int, []error) {
	st, err := Status(env)
	if err != nil {
		return 0, []error{err}
	}
	var errs []error
	n := 0
	for i := len(st) - 1; i >= 0; i-- {
		if st[i].State == "reverted" {
			continue
		}
		if err := Revert(env, st[i].Record.ID, force); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errs
}
