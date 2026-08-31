package p2

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// builtinTable is the table shipped in the binary. It is the asset: entries are
// added here or in a manifest override, never inferred at runtime (§6.2).
//
//go:embed p2-maven.json
var builtinTable []byte

// tableSchemaVersion is the only format this build understands. It is a
// compatibility lever, not a version stamp: bumping it is a breaking change to
// every override file in the wild.
const tableSchemaVersion = 1

// coordinates are the Maven groupId and artifactId a bundle symbolic name
// resolves to.
type coordinates struct {
	GroupID    string `json:"groupId"`
	ArtifactID string `json:"artifactId"`
}

// tableFile is the on-disk and embedded format:
//
//	{"schemaVersion":1,"entries":{"<bsn>":{"groupId":...,"artifactId":...}}}
type tableFile struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Entries       map[string]coordinates `json:"entries"`
}

// table maps a bundle symbolic name to Maven coordinates. Lookups only; it is
// never iterated, so no map order ever reaches the output (§7).
type table map[string]coordinates

// loadTable parses one table document. source names the file in every error,
// because a broken table is a configuration error the operator has to find (§10).
func loadTable(data []byte, source string) (table, error) {
	var parsed tableFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("mapping table %s: %w", source, err)
	}
	if parsed.SchemaVersion != tableSchemaVersion {
		return nil, fmt.Errorf("mapping table %s: schemaVersion is %d, want %d",
			source, parsed.SchemaVersion, tableSchemaVersion)
	}
	out := make(table, len(parsed.Entries))
	for bsn, coords := range parsed.Entries {
		// Half an entry is worse than no entry: it would produce a purl with an
		// empty segment that looks resolvable and is not.
		if coords.GroupID == "" {
			return nil, fmt.Errorf("mapping table %s: entry %q has an empty groupId", source, bsn)
		}
		if coords.ArtifactID == "" {
			return nil, fmt.Errorf("mapping table %s: entry %q has an empty artifactId", source, bsn)
		}
		out[bsn] = coords
	}
	return out, nil
}

// loadTables returns the built-in table with the file at path merged over it:
// an entry present in both wins from the override, an entry only in the
// override is added (§6.2). An empty path means the built-in table alone.
func loadTables(path, baseDir string) (table, error) {
	merged, err := loadTable(builtinTable, "built in")
	if err != nil {
		// Unreachable in a released binary: the embedded table is compiled in
		// and covered by the tests.
		return nil, err
	}
	if path == "" {
		return merged, nil
	}

	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, path)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("reading mapping table %s: %w", resolved, err)
	}
	override, err := loadTable(data, resolved)
	if err != nil {
		return nil, err
	}
	for bsn, coords := range override {
		merged[bsn] = coords
	}
	return merged, nil
}
