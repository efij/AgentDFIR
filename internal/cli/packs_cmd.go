package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/efij/AgentDFIR/internal/productpack"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/seal"
)

const packsUsage = `usage:
  agentdfir packs list                         installed product packs and their trust state
  agentdfir packs validate <file>              validate a pack file (same checks the loader applies)
  agentdfir packs add <file> [--sig <file.sig>] install a pack (and its detached signature)
  agentdfir packs remove <id>                  uninstall a pack
  agentdfir packs init <id> [--name N] [--config-dir D] [--out file]
                                               write a starter pack to edit

Packs live in ~/.agentdfir/packs/products (or $AGENTDFIR_PACKS_DIR/products).
A pack loads only when <file>.sig verifies against trusted.pub;
AGENTDFIR_ALLOW_UNSIGNED_PACKS=1 permits unsigned packs during development.
`

// activatePacks registers installed product packs before dispatch so
// detect/collect/normalize see pack products exactly like built-ins.
// Rejections are printed once, to stderr, and never abort the command.
func activatePacks() {
	_, rejected := productpack.Activate(seal.VerifyFileSig)
	for _, r := range rejected {
		fmt.Fprintf(os.Stderr, "warning: product pack %s: %v\n", sanitize.Terminal(r.Path), r.Err)
	}
}

func cmdPacks(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, packsUsage)
		return 2
	}
	switch args[0] {
	case "list":
		insts := productpack.Scan(seal.VerifyFileSig)
		if len(insts) == 0 {
			fmt.Printf("No product packs installed in %s\n", productpack.Dir())
			return 0
		}
		fmt.Printf("Product packs (%s)\n", productpack.Dir())
		for _, in := range insts {
			state := "ACCEPTED (signed)"
			switch {
			case in.Err != nil:
				state = in.Err.Error()
			case !in.Signed:
				state = "ACCEPTED (unsigned — development mode)"
			}
			id := "?"
			if in.Pack != nil {
				id = in.Pack.Product.ID
			}
			fmt.Printf("  %-24s sha256:%s  %s\n", sanitize.Terminal(id), short12(in.SHA256), state)
		}
		return 0
	case "validate":
		if len(args) != 2 {
			fmt.Fprint(os.Stderr, packsUsage)
			return 2
		}
		p, sum, err := productpack.Load(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			return 1
		}
		fmt.Printf("OK  %s (%s) — %d collector entries, engine %s, sha256 %s\n",
			p.Product.ID, sanitize.Terminal(p.Product.Name), len(p.Manifest.Entries), p.Parser.Engine, short12(sum))
		return 0
	case "add":
		fs := flag.NewFlagSet("packs add", flag.ContinueOnError)
		sig := fs.String("sig", "", "detached signature file")
		file, rest := splitPositional(args[1:])
		if err := fs.Parse(rest); err != nil || file == "" || fs.NArg() != 0 {
			fmt.Fprint(os.Stderr, packsUsage)
			return 2
		}
		dst, err := productpack.Install(file, *sig)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Installed %s\n", dst)
		if *sig == "" {
			fmt.Println("Note: unsigned — it will load only with AGENTDFIR_ALLOW_UNSIGNED_PACKS=1. Sign with `agentdfir sign --key <k> --file <pack>`.")
		}
		return 0
	case "remove":
		if len(args) != 2 {
			fmt.Fprint(os.Stderr, packsUsage)
			return 2
		}
		if err := productpack.Remove(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Removed pack %s\n", sanitize.Terminal(args[1]))
		return 0
	case "init":
		fs := flag.NewFlagSet("packs init", flag.ContinueOnError)
		name := fs.String("name", "", "product display name")
		cfgDir := fs.String("config-dir", "", "config dir relative to the user profile (default .<id>)")
		out := fs.String("out", "", "output file (default <id>.product.json)")
		id, rest := splitPositional(args[1:])
		if err := fs.Parse(rest); err != nil || id == "" || fs.NArg() != 0 {
			fmt.Fprint(os.Stderr, packsUsage)
			return 2
		}
		if *name == "" {
			*name = id
		}
		if *cfgDir == "" {
			*cfgDir = "." + id
		}
		if *out == "" {
			*out = id + productpack.Suffix
		}
		tpl := productpack.Template(id, *name, *cfgDir)
		if err := productpack.Validate(tpl); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		data, _ := json.MarshalIndent(tpl, "", "  ")
		if err := os.WriteFile(*out, append(data, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Wrote %s — edit paths and field_map, then `agentdfir packs validate %s`.\n", *out, *out)
		return 0
	default:
		fmt.Fprint(os.Stderr, packsUsage)
		return 2
	}
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// packProvenance returns case notes identifying the product pack that
// supplied a product's definition, if any, so the evidence package
// records exactly which pack (and whether it was signed) drove collection.
func packProvenance(productID string) map[string]string {
	for _, in := range productpack.Scan(seal.VerifyFileSig) {
		if in.Err != nil || in.Pack == nil || in.Pack.Product.ID != productID {
			continue
		}
		return map[string]string{
			"product_pack_path":   in.Path,
			"product_pack_sha256": in.SHA256,
			"product_pack_signed": fmt.Sprint(in.Signed),
		}
	}
	return nil
}

// splitPositional lets `packs add <file> --sig x` and `packs init <id>
// --name x` take the positional argument first, as people type it.
func splitPositional(args []string) (string, []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", args
	}
	return args[0], args[1:]
}
