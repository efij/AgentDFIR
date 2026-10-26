package rulepack

// ATLAS 2026.09 techniques the v5 attack chains map to that the 5.6.0
// table above does not list yet. Names are copied from ATLAS-2026.09.yaml.
// The pinned 2026.09 table replaces atlas_ids.go; once it lists these, the
// init below adds nothing and this file can be deleted.
func init() {
	for id, name := range map[string]string{
		"AML.T0110.001": "Implementation",
		"AML.T0110.002": "Runtime Response",
		"AML.T0113":     "Steal Web Session Cookie",
		"AML.T0116":     "Autonomous Reconnaissance",
		"AML.T0117":     "Autonomous Attack-Path Adaptation",
		"AML.T0118":     "Autonomous AI Agent Communication",
		"AML.T0118.000": "Communication via Shared Artifacts",
	} {
		if _, ok := atlasTechniques[id]; !ok {
			atlasTechniques[id] = name
		}
	}
}
