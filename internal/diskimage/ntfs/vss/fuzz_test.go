package vss

import (
	"bytes"
	"testing"
)

// template returns a small volume with a two-snapshot store and the
// offsets of its catalog and first block list.
func template(f *testing.F) ([]byte, int64, int64) {
	vol, alloc := memVolume()
	size := int64(len(vol))
	writeStore(vol, alloc, []synthSnap{
		{id: 1, created: created1, volSize: size, blocks: []synthBlock{{orig: BlockSize, data: filled('1')}, {orig: 3 * BlockSize, data: filled('o'), flags: flagOverlay, bitmap: 3}}},
		{id: 2, created: created2, volSize: size, blocks: []synthBlock{{orig: 2 * BlockSize, flags: flagForwarder, rel: 5 * BlockSize}}},
	})
	st, err := Open(bytes.NewReader(vol), size)
	if err != nil {
		f.Fatal(err)
	}
	return vol, st.Catalog, st.Snapshots[0].blockList
}

func readAllSnapshots(st *Store) {
	buf := make([]byte, BlockSize)
	for i := range st.Snapshots {
		r, n, err := st.Volume(i + 1)
		if err != nil {
			continue
		}
		for off := int64(0); off < n && off < 8*BlockSize; off += BlockSize {
			r.ReadAt(buf, off)
		}
	}
}

// FuzzCatalogAndBlockList replaces the catalog block and the first block
// list with fuzz data inside an otherwise valid store.
func FuzzCatalogAndBlockList(f *testing.F) {
	vol, cat, list := template(f)
	f.Add(bytes.Clone(vol[cat:cat+BlockSize]), bytes.Clone(vol[list:list+BlockSize]))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, catalog, blockList []byte) {
		v := bytes.Clone(vol)
		copy(v[cat:cat+BlockSize], catalog)
		copy(v[list:list+BlockSize], blockList)
		st, err := Open(bytes.NewReader(v), int64(len(v)))
		if err != nil {
			return
		}
		readAllSnapshots(st)
	})
}

// FuzzOpen parses arbitrary volumes that carry the VSS identifier.
func FuzzOpen(f *testing.F) {
	vol, _, _ := template(f)
	f.Add(vol[:HeaderOffset+512])
	f.Fuzz(func(t *testing.T, data []byte) {
		v := make([]byte, max(len(data), HeaderOffset+512))
		copy(v, data)
		copy(v[HeaderOffset:], Identifier)
		st, err := Open(bytes.NewReader(v), int64(len(v)))
		if err != nil {
			return
		}
		readAllSnapshots(st)
	})
}
