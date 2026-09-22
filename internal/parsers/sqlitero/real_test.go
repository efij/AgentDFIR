package sqlitero

import (
	"fmt"
	"os"
	"sort"
	"testing"
)

// TestRealDatabase walks every table of a database named by
// AGENTDFIR_SQLITE (plus AGENTDFIR_SQLITE_WAL) and prints row counts, for
// checking the reader against the sqlite3 CLI on a real product store.
// Skipped unless the variable is set; it is a local tool, not a CI test.
func TestRealDatabase(t *testing.T) {
	path := os.Getenv("AGENTDFIR_SQLITE")
	if path == "" {
		t.Skip("set AGENTDFIR_SQLITE to a database to walk it")
	}
	db, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wal []byte
	if w := os.Getenv("AGENTDFIR_SQLITE_WAL"); w != "" {
		wal, _ = os.ReadFile(w)
	}
	d, err := Open(db, wal)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := d.Tables()
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Name < ts[j].Name })
	for i := range ts {
		tb := &ts[i]
		n := 0
		types := map[string]int{}
		ti := tb.Index("item_type")
		err := d.Each(tb, func(_ int64, v []any) error {
			n++
			if ti >= 0 {
				types[Str(v[ti])]++
			}
			return nil
		})
		fmt.Printf("%s|%d|%v\n", tb.Name, n, err)
		keys := make([]string, 0, len(types))
		for k := range types {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %s|%d\n", k, types[k])
		}
	}
}
