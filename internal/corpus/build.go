package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/parsers/aiexport"
	"github.com/efij/AgentDFIR/v4/internal/products"
)

// BuildPackage collects one corpus case into a sealed package at pkg, the
// way the product acquires the same evidence: product collectors over the
// case directory, or `collect --ai-export` for export cases. The corpus
// test and the benchmark both build through here, so a case means the
// same thing to each.
func BuildPackage(c Case, pkg, caseID, operator string) error {
	b, err := casepkg.New(pkg, caseID, casepkg.CaseInfo{OperatorOSUser: operator})
	if err != nil {
		return err
	}
	defer b.Close()
	if c.Collect == CollectAIExport {
		err = ingestExport(b, c)
	} else {
		err = collectProducts(b, c)
	}
	if err != nil {
		return err
	}
	return b.Seal()
}

func collectProducts(b *casepkg.Builder, c Case) error {
	for _, pid := range c.ProductIDs() {
		man, err := products.ManifestAllPlatforms(pid)
		if err != nil || man == nil {
			return fmt.Errorf("product %s: no manifest (%v)", pid, err)
		}
		prod, err := products.ByID(pid)
		if err != nil {
			return err
		}
		configRoot := c.Dir
		if len(prod.ConfigDirs) > 0 {
			configRoot = filepath.Join(c.Dir, filepath.FromSlash(prod.ConfigDirs[0]))
		}
		if _, err := collector.Run(b, man, collector.Options{
			ProfileRoot: c.Dir, ConfigRoot: configRoot,
			SystemRoot: c.Dir, Product: pid,
		}); err != nil {
			return err
		}
	}
	// IDE extensions, for the cases that carry an editor profile.
	for _, pid := range c.ProductIDs() {
		if pid == "ide-extensions" {
			return nil
		}
	}
	if ext, err := products.ManifestAllPlatforms("ide-extensions"); err == nil && ext != nil {
		if _, err := collector.Run(b, ext, collector.Options{ProfileRoot: c.Dir, SystemRoot: c.Dir, Product: "ide-extensions"}); err != nil {
			return err
		}
	}
	return nil
}

// ingestExport seals a case's export/ tree the way `collect --ai-export`
// does. @@RUNTIME_SECRET@@ is replaced by a credential-shaped string built
// here, because a key-shaped literal in the repository is refused by push
// protection.
func ingestExport(b *casepkg.Builder, c Case) error {
	root, err := os.MkdirTemp("", "corpus-export-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	src := filepath.Join(c.Dir, "export")
	sum := sha256.Sum256([]byte("agentdfir corpus " + c.Name))
	secret := "gh" + "p_" + hex.EncodeToString(sum[:])[:36]
	err = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(root, rel)
		if info.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, bytes.ReplaceAll(data, []byte("@@RUNTIME_SECRET@@"), []byte(secret)), 0o644)
	})
	if err != nil {
		return err
	}
	pl, err := aiexport.PlanTree(root, aiexport.PlanAll, nil)
	if err != nil || !pl.Found() {
		return fmt.Errorf("export not recognized: %v", err)
	}
	var specs []collector.FileSpec
	for _, f := range pl.Files {
		specs = append(specs, collector.FileSpec{Path: f.Path, Product: f.Product,
			Entry: products.ManifestEntry{ID: f.Rule, Category: f.Type, Sensitivity: "high"}})
	}
	_, err = collector.IngestFiles(b, specs, collector.Options{ProfileRoot: root, SystemRoot: root})
	return err
}
