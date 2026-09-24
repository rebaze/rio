package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rebaze/rio/internal/index"
)

const IndexLimit int64 = 16 << 20
const PayloadLimit int64 = 64 << 20
const ConfigLimit int64 = 1 << 20

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidDigest(s string) bool { return digestPattern.MatchString(s) }
func Digest(b []byte) string    { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func ReadBounded(path string, limit int64) ([]byte, error) {
	before, err := os.Stat(path)
	if err != nil {
		return nil, Fail("read_failed", "input file")
	}
	if !before.Mode().IsRegular() {
		return nil, Fail("invalid_file", "regular file required")
	}
	f, err := openRegular(path)
	if err != nil {
		return nil, Fail("read_failed", "input file")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, Fail("invalid_file", "regular file required")
	}
	if st.Size() > limit {
		return nil, Fail("size_limit", "input exceeds documented byte limit")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, Fail("read_failed", "input file")
	}
	if int64(len(b)) > limit {
		return nil, Fail("size_limit", "input exceeds documented byte limit")
	}
	return b, nil
}
func relative(s string) bool {
	return s != "" && !strings.HasPrefix(s, "/") && !strings.ContainsAny(s, `\:`) && !filepath.IsAbs(s) && filepath.VolumeName(s) == ""
}
func Verify(indexPath, artifactID string, allowFailed bool) (Verified, error) {
	b, err := ReadBounded(indexPath, IndexLimit)
	if err != nil {
		return Verified{}, err
	}
	idx, err := ParseIndex(b)
	if err != nil {
		return Verified{}, err
	}
	return verifyArtifact(indexPath, Digest(b), idx, artifactID, allowFailed)
}
func verifyArtifact(indexPath, indexSHA string, idx index.Index, artifactID string, allowFailed bool) (Verified, error) {
	bad := func(code, field string) (Verified, error) { return Verified{}, Fail(code, field) }
	var selected *index.Artifact
	for i := range idx.Artifacts {
		if idx.Artifacts[i].ID == artifactID {
			selected = &idx.Artifacts[i]
		}
	}
	if selected == nil {
		return bad("artifact_missing", "selected artifact")
	}
	a := *selected
	if a.Gate == index.GateFail && !allowFailed {
		return bad("failed_gate", "explicit allow-failed-gate required")
	}
	payload, err := ReadBounded(filepath.Join(filepath.Dir(indexPath), filepath.FromSlash(a.Output.Path)), PayloadLimit)
	if err != nil {
		return Verified{}, err
	}
	if Digest(payload) != a.Output.SHA256 {
		return bad("digest_mismatch", "output.sha256")
	}
	// Parse only enough of the same snapshot to describe a subject; never rewrite it.
	var bom map[string]json.RawMessage
	if err = DecodeJSON(payload, &bom, false); err != nil {
		return Verified{}, err
	}
	var format string
	if json.Unmarshal(bom["bomFormat"], &format) != nil || format != "CycloneDX" {
		return bad("invalid_sbom", "bomFormat")
	}
	subject := readSubject(bom)

	return Verified{source: Source{indexSHA, a.ID, a.Output.SHA256, string(a.Gate), a.SchemaValidated, allowFailed}, subject: subject, payloads: []Payload{{ref: PayloadRef{"sbom", "application/vnd.cyclonedx+json", a.Output.SHA256, int64(len(payload)), a.Output.SHA256, "identity"}, data: payload}}}, nil
}

// Subject fields are an optional source of destination identity, not a second
// schema-validation gate. Explicit selectors may deliver verified bytes with
// unusable subject metadata; fromSubject must still resolve a complete pair.
func readSubject(bom map[string]json.RawMessage) Subject {
	var meta, component map[string]json.RawMessage
	if DecodeJSON(bom["metadata"], &meta, false) != nil {
		return Subject{}
	}
	if DecodeJSON(meta["component"], &component, false) != nil {
		return Subject{}
	}
	var subject Subject
	if DecodeJSON(component["name"], &subject.Name, false) != nil || DecodeJSON(component["version"], &subject.Version, false) != nil {
		return Subject{}
	}
	return subject
}

// ParseIndex validates the complete v1 base structure without opening payloads.
// Additive v1 fields remain supported; callers retain raw bytes for provenance.
func ParseIndex(b []byte) (index.Index, error) {
	bad := func(code, field string) (index.Index, error) { return index.Index{}, Fail(code, field) }
	var idx index.Index
	if err := DecodeJSON(b, &idx, false); err != nil {
		return index.Index{}, err
	}
	if idx.SchemaVersion != 1 {
		return bad("unsupported_version", "index.schemaVersion")
	}
	if idx.Tool.Name == "" || idx.Tool.Version == "" || !relative(idx.Manifest.Path) || !ValidDigest(idx.Manifest.SHA256) {
		return bad("invalid_index", "tool or manifest")
	}
	seen := map[string]bool{}
	for i := range idx.Artifacts {
		a := &idx.Artifacts[i]
		if a.ID == "" || seen[a.ID] {
			return bad("invalid_index", "artifact id")
		}
		seen[a.ID] = true
		if !relative(a.Input.Path) || !relative(a.Output.Path) || !ValidDigest(a.Input.SHA256) || !ValidDigest(a.Output.SHA256) || a.SpecVersion.Input == "" || a.SpecVersion.Output == "" || a.Components < 0 {
			return bad("invalid_index", "artifact fields")
		}
		for _, tr := range a.Transforms {
			if tr.ID == "" || tr.Applied < 0 || tr.Unmapped < 0 || tr.Skipped < 0 {
				return bad("invalid_index", "transform fields")
			}
		}
	}
	return idx, nil
}
