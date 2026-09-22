package sqlitero

import (
	"encoding/binary"
	"fmt"
	"math"
)

// applyWAL overlays the committed frames of a write-ahead log onto the
// database image.
//
// A product that keeps its store in WAL mode (Codex does) may have
// hundreds of rows that exist only in the -wal file until the next
// checkpoint. Ignoring it would read a stale database and call that the
// evidence. Frames are trusted only when their salt matches the log
// header and their cumulative checksum verifies — the same test SQLite
// applies on recovery — and only frames up to the last commit record are
// applied, because everything after it is an unfinished transaction.
func (d *DB) applyWAL(wal []byte) error {
	if len(wal) > MaxWALBytes {
		return fmt.Errorf("sqlite: WAL is %d bytes, over the %d-byte bound", len(wal), MaxWALBytes)
	}
	if len(wal) < 32 {
		return nil // empty or header-only log: nothing committed
	}
	magic := binary.BigEndian.Uint32(wal[0:4])
	var order binary.ByteOrder
	switch magic {
	case 0x377f0682:
		order = binary.LittleEndian
	case 0x377f0683:
		order = binary.BigEndian
	default:
		return fmt.Errorf("%w: WAL magic 0x%08x", errCorrupt, magic)
	}
	if ps := int(binary.BigEndian.Uint32(wal[8:12])); ps != d.pageSize {
		return fmt.Errorf("%w: WAL page size %d, database %d", errCorrupt, ps, d.pageSize)
	}
	salt1 := binary.BigEndian.Uint32(wal[16:20])
	salt2 := binary.BigEndian.Uint32(wal[20:24])
	s0, s1 := walChecksum(order, wal[:24], 0, 0)
	if s0 != binary.BigEndian.Uint32(wal[24:28]) || s1 != binary.BigEndian.Uint32(wal[28:32]) {
		return fmt.Errorf("%w: WAL header checksum", errCorrupt)
	}

	frame := 24 + d.pageSize
	pending := map[uint32][]byte{}
	committed := map[uint32][]byte{}
	var dbSize uint32
	for off := 32; off+frame <= len(wal); off += frame {
		h := wal[off : off+24]
		if binary.BigEndian.Uint32(h[8:12]) != salt1 || binary.BigEndian.Uint32(h[12:16]) != salt2 {
			break // frame from an earlier incarnation of the log
		}
		s0, s1 = walChecksum(order, h[:8], s0, s1)
		s0, s1 = walChecksum(order, wal[off+24:off+frame], s0, s1)
		if s0 != binary.BigEndian.Uint32(h[16:20]) || s1 != binary.BigEndian.Uint32(h[20:24]) {
			break // torn or corrupt frame: nothing after it is trustworthy
		}
		pgno := binary.BigEndian.Uint32(h[0:4])
		if pgno == 0 {
			break
		}
		pending[pgno] = wal[off+24 : off+frame]
		if n := binary.BigEndian.Uint32(h[4:8]); n != 0 {
			for k, v := range pending {
				committed[k] = v
			}
			pending = map[uint32][]byte{}
			dbSize = n
		}
	}
	if dbSize == 0 {
		return nil
	}
	d.wal = committed
	d.walPages = dbSize
	return nil
}

// walChecksum is SQLite's WAL checksum: a Fletcher-style pair of 32-bit
// sums over native-endian 32-bit words, chained from the previous frame.
func walChecksum(order binary.ByteOrder, b []byte, s0, s1 uint32) (uint32, uint32) {
	for i := 0; i+8 <= len(b); i += 8 {
		s0 += order.Uint32(b[i:i+4]) + s1
		s1 += order.Uint32(b[i+4:i+8]) + s0
	}
	return s0, s1
}

func float64FromBits(u uint64) float64 { return math.Float64frombits(u) }
