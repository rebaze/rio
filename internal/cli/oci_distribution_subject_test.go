package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rebaze/rio/internal/index"
)

// distributionSubjectProject writes a project whose OCI target attaches the SBOM
// to subjectHex, with the build context declaring declared (possibly none).
func distributionSubjectProject(t *testing.T, server, subjectHex string, declared []string) string {
	t.Helper()
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"app","version":"1.0.0"}}}`)
	dists := ""
	if len(declared) > 0 {
		var parts []string
		for i, h := range declared {
			parts = append(parts, fmt.Sprintf(`{"name":"app-%d.tgz","sha256":"%s"}`, i, h))
		}
		dists = `,"distributions":[` + strings.Join(parts, ",") + `]`
	}
	ctx := fmt.Sprintf(`{"contextVersion":1,"artifacts":[{"id":"app","sbom":{"sha256":"%s"},"source":{"repository":"https://code.example/app"}%s}]}`, index.SHA256Bytes(sbom), dists)
	manifest := fmt.Sprintf("version: 1\nartifacts:\n  - id: app\n    sbom: app.json\n    context: {file: context.json}\noutput:\n  specVersionFloor: \"1.6\"\ndelivery:\n  targets:\n    registry:\n      type: oci\n      registry: '%s'\n      repository: acme/app\n      allowHTTP: true\n      auth: {anonymous: true}\n      subject: {digest: 'sha256:%s', mediaType: application/vnd.oci.image.manifest.v1+json, size: 527}\n", strings.TrimPrefix(server, "http://"), subjectHex)
	dir := t.TempDir()
	for name, data := range map[string]string{"rio.yaml": manifest, "app.json": string(sbom), "context.json": ctx} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// normalizedIndex runs the pipeline offline and returns the run's index.json.
func normalizedIndex(t *testing.T, dir string) string {
	t.Helper()
	t.Chdir(dir)
	var out, errout bytes.Buffer
	if c := Main([]string{"--skip-delivery"}, &out, &errout); c != 0 {
		t.Fatalf("normalize exit=%d %s", c, errout.String())
	}
	return filepath.Join(latestOutput(t, dir, "target/rio"), "index.json")
}

func TestOCISubjectMustBeDeclaredDistribution(t *testing.T) {
	declared, other := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	const code = "subject_digest_mismatch"
	t.Run("mismatch refused by pipeline before any request", func(t *testing.T) {
		requests.Store(0)
		t.Chdir(distributionSubjectProject(t, server.URL, other, []string{declared}))
		exit, d, _ := rootReceipt(t)
		if exit == 0 || requests.Load() != 0 {
			t.Fatalf("exit=%d requests=%d", exit, requests.Load())
		}
		found := false
		for _, e := range d.Exceptions {
			found = found || e == code
		}
		if !found {
			t.Fatalf("receipt exceptions %v", d.Exceptions)
		}
	})
	t.Run("mismatch refused by plan and deliver", func(t *testing.T) {
		requests.Store(0)
		dir := distributionSubjectProject(t, server.URL, declared, []string{declared})
		t.Chdir(dir)
		// Produce the index with a matching subject, then point the manifest elsewhere.
		ip := normalizedIndex(t, dir)
		raw, _ := os.ReadFile("rio.yaml")
		os.WriteFile("rio.yaml", bytes.ReplaceAll(raw, []byte("sha256:"+declared), []byte("sha256:"+other)), 0o644)
		for _, args := range [][]string{{"delivery", "plan"}, {"deliver"}} {
			c, result, _ := runBatch(t, append(args, "--index", ip, "--manifest", "rio.yaml")...)
			if c == 0 || requests.Load() != 0 || !strings.Contains(fmt.Sprint(result), code) {
				t.Fatalf("%v: exit=%d requests=%d %v", args, c, requests.Load(), result)
			}
		}
	})
	for _, tc := range []struct {
		name     string
		subject  string
		declared []string
	}{
		{"match accepted", declared, []string{other, declared}},
		{"no distributions unchanged", other, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests.Store(0)
			dir := distributionSubjectProject(t, server.URL, tc.subject, tc.declared)
			t.Chdir(dir)
			c, result, _ := runBatch(t, "delivery", "plan", "--index", normalizedIndex(t, dir), "--manifest", "rio.yaml")
			if c != 0 || requests.Load() != 0 {
				t.Fatalf("exit=%d requests=%d %v", c, requests.Load(), result)
			}
		})
	}
}
