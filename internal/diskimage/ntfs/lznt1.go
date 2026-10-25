package ntfs

import (
	"encoding/binary"
	"fmt"
)

// decompressLZNT1 inflates one NTFS compression unit. The stream is a
// series of chunks, each a 2-byte header (bit 15 = compressed, low 12
// bits = stored length - 3) and up to 4096 bytes of output. A compressed
// chunk is groups of a flag byte and eight tokens: literal bytes or
// 16-bit back-references whose offset/length split depends on how far
// into the chunk the output is. Output is bounded by limit.
func decompressLZNT1(src []byte, limit int) ([]byte, error) {
	out := make([]byte, 0, limit)
	i := 0
	for i+2 <= len(src) && len(out) < limit {
		h := binary.LittleEndian.Uint16(src[i:])
		if h == 0 {
			break
		}
		// Each chunk decompresses to its own 4 KiB slot; a short one is
		// zero-padded when another chunk follows.
		if r := len(out) % 4096; r != 0 {
			pad := 4096 - r
			if len(out)+pad > limit {
				pad = limit - len(out)
			}
			out = append(out, make([]byte, pad)...)
			if len(out) >= limit {
				break
			}
		}
		size := int(h&0x0FFF) + 1 // bytes of chunk data after the header
		i += 2
		if i+size > len(src) {
			return out, fmt.Errorf("LZNT1 chunk of %d bytes past end of unit", size)
		}
		chunk := src[i : i+size]
		i += size
		if h&0x8000 == 0 {
			// Stored chunk: always 4096 bytes of literal data (or the rest).
			out = append(out, chunk...)
			continue
		}
		start := len(out)
		j := 0
		for j < len(chunk) {
			flags := chunk[j]
			j++
			for bit := 0; bit < 8 && j < len(chunk); bit++ {
				if len(out) >= limit {
					return out[:limit], nil
				}
				if flags&(1<<bit) == 0 {
					out = append(out, chunk[j])
					j++
					continue
				}
				if j+2 > len(chunk) {
					return out, fmt.Errorf("LZNT1 back-reference truncated")
				}
				tok := int(binary.LittleEndian.Uint16(chunk[j:]))
				j += 2
				pos := len(out) - start
				if pos == 0 {
					return out, fmt.Errorf("LZNT1 back-reference at chunk start")
				}
				lenBits := 12
				for p := pos - 1; p >= 0x10; p >>= 1 {
					lenBits--
				}
				off := tok>>lenBits + 1
				n := tok&(1<<lenBits-1) + 3
				if off > pos {
					return out, fmt.Errorf("LZNT1 back-reference before chunk start")
				}
				from := len(out) - off
				for k := 0; k < n && len(out) < limit && len(out)-start < 4096; k++ {
					out = append(out, out[from+k])
				}
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
