package diskimage

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/diskimage/lvm"
)

// LVM2 as a volume source. After the partition table is read, every volume
// (or the whole disk) carrying an LVM2 label is a physical volume. The
// newest volume group metadata found on those PVs is parsed, and each
// visible logical volume is appended to the table:
//
//   - linear LVs (striped segments with stripe_count 1, one or more
//     segments, on PVs present in this image) become readable volumes; the
//     filesystem probe runs on them like on any partition
//   - every other LV (thin, thin-pool, snapshot, raid*, mirror, striped
//     over several devices, a PV missing from the image …) is listed with
//     its name and an Unsupported reason
//
// LV volumes are numbered from lvIndexBase upward (Scheme "lvm", Name
// "vg/lv"). The PV volumes stay in the table with LVM set, so it is clear
// they were expanded rather than skipped. Hidden component LVs (raid
// images, pool data/metadata, snapshot exception stores) are not volumes;
// they are counted in the table's problems.

const lvIndexBase = 1000

// Extent is one contiguous byte range of the disk that a volume maps onto.
type Extent struct {
	Offset int64 `json:"offset"`
	Size   int64 `json:"size"`
}

type pvFound struct {
	vol  *Volume
	info *lvm.PV
	text string
	seq  int64
	vg   *lvm.VG
}

// expandLVM appends the logical volumes of any LVM2 physical volumes found
// among t.Volumes.
func (t *PartitionTable) expandLVM(r io.ReaderAt) {
	var pvs []*pvFound
	for i := range t.Volumes {
		v := &t.Volumes[i]
		sec := v.Section(r)
		pv, err := lvm.ReadLabel(sec, v.Size)
		if errors.Is(err, lvm.ErrNoLabel) {
			continue
		}
		if err != nil {
			t.Problems = append(t.Problems, fmt.Sprintf("volume #%d: LVM2 label: %v", v.Index, err))
			continue
		}
		f := &pvFound{vol: v, info: pv}
		text, err := lvm.ReadMetadata(sec, v.Size, pv)
		if err != nil {
			t.Problems = append(t.Problems, fmt.Sprintf("volume #%d: LVM2 PV %s: %v", v.Index, pv.UUID, err))
		} else if top, err := lvm.Parse(text); err != nil {
			t.Problems = append(t.Problems, fmt.Sprintf("volume #%d: LVM2 metadata: %v", v.Index, err))
		} else if vg, err := lvm.Model(top); err != nil {
			t.Problems = append(t.Problems, fmt.Sprintf("volume #%d: LVM2 metadata: %v", v.Index, err))
		} else {
			f.vg, f.seq = vg, vg.Seqno
		}
		pvs = append(pvs, f)
	}
	if len(pvs) == 0 {
		return
	}
	// One VG per VG id; the PV holding the highest seqno wins.
	byVG := map[string]*pvFound{}
	var order []string
	for _, p := range pvs {
		if p.vg == nil {
			continue
		}
		id := p.vg.ID + "/" + p.vg.Name
		if cur, ok := byVG[id]; !ok {
			byVG[id] = p
			order = append(order, id)
		} else if p.seq > cur.seq {
			byVG[id] = p
		}
	}
	byUUID := map[string]*pvFound{}
	for _, p := range pvs {
		byUUID[p.info.UUID] = p
	}
	next := lvIndexBase + 1
	for _, id := range order {
		vg := byVG[id].vg
		hidden := 0
		first := next
		var lvVols []Volume
		for _, lv := range vg.LVs {
			if !lv.Visible {
				hidden++
				continue
			}
			v := Volume{Index: next, Scheme: "lvm", Name: vg.Name + "/" + lv.Name, Type: "lvm2-" + lvType(lv), Size: int64(lv.Extents * vg.ExtentSize)}
			next++
			if lv.Unsupported != "" {
				v.Unsupported = "LVM2 LV " + v.Name + ": " + lv.Unsupported
				lvVols = append(lvVols, v)
				continue
			}
			segs, reason := mapLinear(vg, lv, byUUID)
			if reason != "" {
				v.Unsupported = "LVM2 LV " + v.Name + ": " + reason
			} else {
				v.Offset, v.Segments = segs[0].Offset, segs
				if len(segs) == 1 {
					v.Segments = nil // plain contiguous range
				}
			}
			lvVols = append(lvVols, v)
		}
		for _, p := range pvs {
			if p.vg != nil && p.vg.ID+"/"+p.vg.Name == id {
				pn := pvName(vg, p.info.UUID)
				p.vol.LVM = fmt.Sprintf("LVM2 physical volume %s of volume group %s (metadata seqno %d)", pn, vg.Name, p.seq)
				if len(lvVols) > 0 {
					p.vol.LVM += fmt.Sprintf("; its logical volumes are listed as volumes #%d-#%d", first, next-1)
				}
			}
		}
		if hidden > 0 {
			t.Problems = append(t.Problems, fmt.Sprintf("LVM2 VG %s: %d hidden component LV(s) (raid images, pool data/metadata, snapshot stores) are not listed as volumes", vg.Name, hidden))
		}
		for pn, info := range vg.PVs {
			if byUUID[info.UUID] == nil {
				t.Problems = append(t.Problems, fmt.Sprintf("LVM2 VG %s: physical volume %s (%s) is not in this image; LVs on it are UNSUPPORTED", vg.Name, pn, info.UUID))
			}
		}
		t.Volumes = append(t.Volumes, lvVols...)
	}
	// PVs whose metadata could not be read stay ordinary volumes: the
	// signature table reports them as LVM2, unread, with the workaround.
}

func lvType(lv lvm.LV) string {
	if lv.Unsupported == "" {
		return "linear"
	}
	if strings.HasPrefix(lv.Unsupported, "snapshot of") {
		return "snapshot"
	}
	if len(lv.Segments) > 0 {
		return lv.Segments[0].Type
	}
	return "unknown"
}

func pvName(vg *lvm.VG, uuid string) string {
	for pn, info := range vg.PVs {
		if info.UUID == uuid {
			return pn
		}
	}
	return uuid
}

// mapLinear turns a linear LV's segments into disk extents, merging
// neighbours that are contiguous on disk.
func mapLinear(vg *lvm.VG, lv lvm.LV, byUUID map[string]*pvFound) ([]Extent, string) {
	var out []Extent
	for i, s := range lv.Segments {
		info := vg.PVs[s.PV]
		p := byUUID[info.UUID]
		if p == nil {
			return nil, fmt.Sprintf("segment %d lives on physical volume %s (%s), which is not in this image", i+1, s.PV, info.UUID)
		}
		start := info.PEStart + s.PE*vg.ExtentSize
		n := s.ExtentCount * vg.ExtentSize
		if start > uint64(p.vol.Size) || n > uint64(p.vol.Size)-start {
			return nil, fmt.Sprintf("segment %d extends past the end of physical volume %s", i+1, s.PV)
		}
		e := Extent{Offset: p.vol.Offset + int64(start), Size: int64(n)}
		if len(p.vol.Segments) > 0 {
			return nil, "physical volume is itself a multi-segment volume"
		}
		if k := len(out); k > 0 && out[k-1].Offset+out[k-1].Size == e.Offset {
			out[k-1].Size += e.Size
			continue
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, "no segments"
	}
	return out, ""
}

// segmentReader concatenates a multi-segment volume's disk extents.
type segmentReader struct {
	r    io.ReaderAt
	segs []Extent
}

func (s *segmentReader) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	var base int64
	for _, e := range s.segs {
		if len(p) == 0 {
			break
		}
		if off >= base+e.Size {
			base += e.Size
			continue
		}
		in := off - base
		n := int(min(int64(len(p)), e.Size-in))
		got, err := s.r.ReadAt(p[:n], e.Offset+in)
		total += got
		if got < n {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return total, err
		}
		p = p[n:]
		off += int64(n)
		base += e.Size
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}
