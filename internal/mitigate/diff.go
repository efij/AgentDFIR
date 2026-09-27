package mitigate

import (
	"fmt"
	"strings"
)

// UnifiedDiff renders a minimal unified diff (Myers, 3 lines of context).
// Config edits here touch a few lines of a file that can be thousands of
// lines long, so trimming a common prefix and suffix would still print
// everything between the first and the last change.
func UnifiedDiff(name string, a, b []byte) string {
	x, y := splitLines(string(a)), splitLines(string(b))
	ops := myers(x, y)
	const ctx = 3
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s (after)\n", name, name)
	// group ops into hunks
	type op struct {
		k    byte // ' ', '-', '+'
		s    string
		i, j int // line numbers in a and b (0-based) at this op
	}
	var seq []op
	i, j := 0, 0
	for _, o := range ops {
		switch o {
		case '=':
			seq = append(seq, op{' ', x[i], i, j})
			i++
			j++
		case '-':
			seq = append(seq, op{'-', x[i], i, j})
			i++
		case '+':
			seq = append(seq, op{'+', y[j], i, j})
			j++
		}
	}
	for k := 0; k < len(seq); {
		if seq[k].k == ' ' {
			k++
			continue
		}
		start := k - ctx
		if start < 0 {
			start = 0
		}
		end := k
		last := k
		for end < len(seq) {
			if seq[end].k != ' ' {
				last = end
			} else if end-last > 2*ctx {
				break
			}
			end++
		}
		stop := last + ctx + 1
		if stop > len(seq) {
			stop = len(seq)
		}
		na, nb := 0, 0
		for _, o := range seq[start:stop] {
			if o.k != '+' {
				na++
			}
			if o.k != '-' {
				nb++
			}
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", seq[start].i+1, na, seq[start].j+1, nb)
		for _, o := range seq[start:stop] {
			out.WriteByte(o.k)
			out.WriteString(o.s)
			out.WriteByte('\n')
		}
		k = stop
	}
	return out.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// myers returns the edit script as '=', '-', '+' per line.
func myers(a, b []string) []byte {
	n, m := len(a), len(b)
	max := n + m
	if max == 0 {
		return nil
	}
	off := max
	v := make([]int, 2*max+2)
	var trace [][]int
	for d := 0; d <= max; d++ {
		cp := make([]int, len(v))
		copy(cp, v)
		trace = append(trace, cp)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				return backtrack(trace, a, b, off, d)
			}
		}
	}
	return nil
}

func backtrack(trace [][]int, a, b []string, off, d int) []byte {
	x, y := len(a), len(b)
	var ops []byte
	for ; d > 0; d-- {
		v := trace[d]
		k := x - y
		var pk int
		if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := v[off+pk]
		py := px - pk
		for x > px && y > py {
			ops = append(ops, '=')
			x--
			y--
		}
		if x == px {
			ops = append(ops, '+')
		} else {
			ops = append(ops, '-')
		}
		x, y = px, py
	}
	for x > 0 && y > 0 {
		ops = append(ops, '=')
		x--
		y--
	}
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}
	return ops
}
