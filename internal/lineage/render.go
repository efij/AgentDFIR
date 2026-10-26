package lineage

import (
	"fmt"
	"io"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/detect"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// WriteText prints one line per edge, grouped by source node, with the
// basis and evidence state of every step.
func WriteText(w io.Writer, g *Graph) {
	label := map[string]string{}
	for _, n := range g.Nodes {
		label[n.ID] = fmt.Sprintf("[%s] %s", n.Kind, sanitize.Terminal(detect.MaskSecrets(n.Label)))
	}
	scope := "whole case"
	switch {
	case g.Scope.Finding != "":
		scope = "finding " + sanitize.Terminal(g.Scope.Finding)
	case g.Scope.SessionID != "":
		scope = "session " + sanitize.Terminal(g.Scope.SessionID)
	}
	fmt.Fprintf(w, "Lineage for case %s (%s): %d node(s), %d edge(s)\n", sanitize.Terminal(g.CaseID), scope, len(g.Nodes), len(g.Edges))
	// Edges grouped under their source, sources in node order (humans and
	// agents first), so the text reads from who asked to what happened.
	bySrc := map[string][]Edge{}
	for _, e := range g.Edges {
		bySrc[e.From] = append(bySrc[e.From], e)
	}
	for _, n := range g.Nodes {
		edges := bySrc[n.ID]
		if len(edges) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", label[n.ID])
		for _, e := range edges {
			conf := ""
			if e.Confidence != "" {
				conf = ", confidence " + e.Confidence
			}
			fmt.Fprintf(w, "  --%s--> %s\n      %s · %s%s\n", e.Relation, label[e.To], schema.Label(e.State), sanitize.Terminal(e.Basis), conf)
			if e.Note != "" {
				fmt.Fprintf(w, "      %s\n", sanitize.Terminal(e.Note))
			}
			for _, r := range e.Refs {
				fmt.Fprintf(w, "      Evidence: %s\n", sanitize.Terminal(r.String()))
			}
		}
	}
	for _, n := range g.Notes {
		fmt.Fprintf(w, "note: %s\n", sanitize.Terminal(n))
	}
	if g.Truncated {
		fmt.Fprintln(w, "TRUNCATED: the graph hit its bound; see the notes above.")
	}
}

// String renders a reference for a human.
func (r Ref) String() string {
	if r.External != "" {
		return "telemetry " + r.External
	}
	id := r.ArtifactID
	if len(id) > 12 {
		id = id[:12]
	}
	return fmt.Sprintf("%s:%d (artifact %s, offset %d)", r.Path, r.Line, id, r.Offset)
}

// WriteMermaid renders a Mermaid flowchart. Node ids are positional
// (n0, n1, …) because evidence ids contain characters Mermaid treats as
// syntax; labels are escaped and cut.
func WriteMermaid(w io.Writer, g *Graph) {
	ids := map[string]string{}
	fmt.Fprintln(w, "flowchart LR")
	for i, n := range g.Nodes {
		ids[n.ID] = fmt.Sprintf("n%d", i)
		open, closing := "[", "]"
		switch n.Kind {
		case KindHuman:
			open, closing = "([", "])"
		case KindNetwork, KindCloud:
			open, closing = "{{", "}}"
		case KindFile:
			open, closing = "[/", "/]"
		}
		fmt.Fprintf(w, "  %s%s\"%s\"%s\n", ids[n.ID], open, mermaidText(n.Kind+": "+n.Label), closing)
	}
	for _, e := range g.Edges {
		lbl := e.Relation + " · " + schema.Label(e.State)
		if e.Confidence != "" {
			lbl += " · " + e.Confidence
		}
		fmt.Fprintf(w, "  %s -->|\"%s\"| %s\n", ids[e.From], mermaidText(lbl), ids[e.To])
	}
	if g.Truncated {
		fmt.Fprintf(w, "  %%%% TRUNCATED: %d node(s), %d edge(s) left out\n", g.Omitted.Nodes, g.Omitted.Edges)
	}
}

func mermaidText(s string) string {
	s = detect.MaskTruncate(sanitize.Terminal(s), 80)
	return strings.NewReplacer("#", "#35;", "\"", "#quot;", "\n", " ", "\r", " ", "|", "#124;", "<", "#lt;", ">", "#gt;", "`", "'").Replace(s)
}

// WriteDOT renders Graphviz DOT.
func WriteDOT(w io.Writer, g *Graph) {
	fmt.Fprintln(w, "digraph lineage {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [fontname=\"Helvetica\", fontsize=10];")
	ids := map[string]string{}
	for i, n := range g.Nodes {
		ids[n.ID] = fmt.Sprintf("n%d", i)
		shape := "box"
		switch n.Kind {
		case KindHuman:
			shape = "ellipse"
		case KindNetwork, KindCloud:
			shape = "hexagon"
		case KindFile:
			shape = "note"
		case KindProcess:
			shape = "component"
		}
		fmt.Fprintf(w, "  %s [label=\"%s\", shape=%s];\n", ids[n.ID], dotText(n.Kind+": "+n.Label), shape)
	}
	for _, e := range g.Edges {
		lbl := e.Relation + " · " + schema.Label(e.State)
		if e.Confidence != "" {
			lbl += " · " + e.Confidence
		}
		fmt.Fprintf(w, "  %s -> %s [label=\"%s\"];\n", ids[e.From], ids[e.To], dotText(lbl))
	}
	if g.Truncated {
		fmt.Fprintf(w, "  // TRUNCATED: %d node(s), %d edge(s) left out\n", g.Omitted.Nodes, g.Omitted.Edges)
	}
	fmt.Fprintln(w, "}")
}

func dotText(s string) string {
	s = detect.MaskTruncate(sanitize.Terminal(s), 80)
	return strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", " ", "\r", " ").Replace(s)
}
