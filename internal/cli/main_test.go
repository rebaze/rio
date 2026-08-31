package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func TestMain(m *testing.M) {
	flag.Parse()
	// Pinned so golden files do not move with the build stamp. In a real build
	// this comes from ldflags (§9).
	version = "0.1.0-test"
	commit = "0000000"
	date = "1970-01-01T00:00:00Z"
	os.Exit(m.Run())
}

// run is one invocation of the whole binary, from a working directory.
type run struct {
	dir    string
	exit   int
	stdout string
	stderr string
}

func rio(t *testing.T, dir string, args ...string) run {
	t.Helper()

	// The manifest and --out are resolved against the process working
	// directory, so the test has to be there, exactly as a user would be.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	var stdout, stderr bytes.Buffer
	code := Main(args, &stdout, &stderr)

	if err := os.Chdir(wd); err != nil {
		t.Fatal(err)
	}
	return run{dir: dir, exit: code, stdout: stdout.String(), stderr: stderr.String()}
}

// project builds a working directory holding a manifest and the named
// fixtures, copied under in/.
func project(t *testing.T, manifest string, fixtures ...string) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "in"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range fixtures {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "in", name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "rio.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func readFile(t *testing.T, path ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(path...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	return out
}

// golden compares against internal/cli/testdata/<name>, rewriting it under
// -update. A diff in a golden file must be reviewable as a human readable
// change (§11).
func golden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the golden file: %v (run: go test ./internal/cli -update)", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s differs from the golden file.\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

func properties(t *testing.T, doc map[string]any) map[string][]string {
	t.Helper()

	meta, _ := doc["metadata"].(map[string]any)
	list, _ := meta["properties"].([]any)
	out := map[string][]string{}
	for _, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		name, _ := obj["name"].(string)
		value, _ := obj["value"].(string)
		out[name] = append(out[name], value)
	}
	return out
}

func purls(t *testing.T, doc map[string]any) []string {
	t.Helper()

	list, _ := doc["components"].([]any)
	out := make([]string, 0, len(list))
	for _, entry := range list {
		obj, _ := entry.(map[string]any)
		purl, _ := obj["purl"].(string)
		out = append(out, purl)
	}
	return out
}

func bomRefs(t *testing.T, doc map[string]any) []string {
	t.Helper()

	list, _ := doc["components"].([]any)
	out := make([]string, 0, len(list))
	for _, entry := range list {
		obj, _ := entry.(map[string]any)
		ref, _ := obj["bom-ref"].(string)
		out = append(out, ref)
	}
	return out
}

func indexOf(t *testing.T, r run, out string) map[string]any {
	t.Helper()
	return decode(t, readFile(t, r.dir, out, "index.json"))
}

func requireExit(t *testing.T, r run, want int) {
	t.Helper()
	if r.exit != want {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.exit, want, r.stdout, r.stderr)
	}
}

func requireStderr(t *testing.T, r run, substrings ...string) {
	t.Helper()
	for _, s := range substrings {
		if !strings.Contains(r.stderr, s) {
			t.Fatalf("stderr does not mention %q:\n%s", s, r.stderr)
		}
	}
}
