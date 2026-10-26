package chain

import (
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/mitre"
)

// TestBuiltinChainsMitreIDs: every built-in chain cites a real ATLAS
// technique and an active ATT&CK Enterprise technique (no revoked IDs; see
// internal/mitre/data/migrations.json).
func TestBuiltinChainsMitreIDs(t *testing.T) {
	for _, c := range Builtin {
		if c.MitreATLAS != "" && !mitre.ValidATLAS(c.MitreATLAS) {
			t.Errorf("%s: mitre_atlas %q not in ATLAS %s", c.ID, c.MitreATLAS, mitre.ATLASVersion)
		}
		if c.MitreATTACK != "" && !mitre.ValidATTACK(c.MitreATTACK) {
			t.Errorf("%s: mitre_attack %q is %s in ATT&CK Enterprise %s", c.ID, c.MitreATTACK, mitre.ATTACKStatus(c.MitreATTACK), mitre.ATTACKVersion)
		}
	}
}
