package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rebaze/rio/internal/discover"
	"github.com/rebaze/rio/internal/index"
	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/transform"
	"github.com/rebaze/rio/internal/transform/purl/p2"
)

// PlanVersion is the compatibility lever for the plan document, the role
// version plays in the manifest and schemaVersion in the mapping table. A
// consumer checks it before anything else and refuses a number it does not
// know, rather than reading half a document it misunderstands.
const PlanVersion = 1

// plan is the whole of `rio plan --json`: what a normalize run would read,
// write and repair, described without doing any of it.
//
// The shape is a contract. tools/build-p2-table.py execs `rio plan --json` and
// builds its work-list from it, which is the entire reason the command exists:
// the manifest already says which SBOMs to harvest and which table to write,
// and a tool that made you retype them could disagree with rio in silence.
//
// It is deliberately not index.json. The index needs a completed run, and a
// completed run needs the mapping table, which is what the plan is read to
// produce -- so the index can never describe the first run in a repository.
type plan struct {
	PlanVersion int          `json:"planVersion"`
	Tool        planTool     `json:"tool"`
	Manifest    planManifest `json:"manifest"`
	// Out is --out exactly as given, resolved by rio against the process
	// working directory rather than the manifest's.
	Out string `json:"out"`
	// BuiltinTable is the mapping table compiled into this binary. It is
	// published so a generated override table can stay a delta over it: an
	// override always wins, so an entry that redundantly repeats a built-in
	// one silently shadows every later fix rio makes to it.
	BuiltinTable map[string]p2.Coordinates `json:"builtinTable"`
	Artifacts    []planArtifact            `json:"artifacts"`
	Gate         planGate                  `json:"gate"`
}

type planTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// planManifest identifies the manifest the plan was read from, so a consumer
// can record what it acted on.
type planManifest struct {
	// Path is the manifest's name inside Dir, as index.json records it: what
	// the caller typed would put "$WORKSPACE/rio.yaml" in one run and
	// "rio.yaml" in the next, for the same file.
	Path string `json:"path"`
	// Dir is absolute, which is the one place a plan breaks index.json's rule
	// against absolute paths. The index refuses them because it is a committed
	// artifact whose digests are a contract; a plan is transient stdout that
	// exists to be joined against, and making the consumer guess the base
	// directory is worse.
	Dir    string `json:"dir"`
	SHA256 string `json:"sha256"`
}

type planArtifact struct {
	ID string `json:"id"`
	// Input.Path is relative to the manifest directory and Output.Path is
	// relative to Out, exactly as index.json records them.
	Input      planFile        `json:"input"`
	Output     planFile        `json:"output"`
	Transforms []planTransform `json:"transforms"`
}

type planFile struct {
	Path string `json:"path"`
}

type planGate struct {
	Require []string `json:"require"`
}

// planTransform is one transform as the plan describes it: its manifest name,
// then its configuration resolved, defaults filled in.
//
// It marshals by hand because the option set belongs to the transform, not to
// this package. A struct here would mean the CLI carrying its own copy of
// "groupPrefix" and "osgi.bundle", which is the duplication the plan exists to
// remove -- and a second ecosystem would have to come and edit it.
type planTransform struct {
	Name    string
	Options []transform.Option
}

// nameKey is reserved for the transform's own name, so no option may use it.
const nameKey = "name"

func (t planTransform) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	write := func(key, value string) error {
		if buf.Len() > 1 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(key)
		if err != nil {
			return err
		}
		v, err := json.Marshal(value)
		if err != nil {
			return err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
		return nil
	}
	if err := write(nameKey, t.Name); err != nil {
		return nil, err
	}
	seen := map[string]bool{nameKey: true}
	for _, opt := range t.Options {
		// A duplicate key would produce an object whose meaning depends on
		// which half the reader keeps. Only a transform bug can get here.
		if seen[opt.Key] {
			return nil, fmt.Errorf("transform %q reports the option %q twice", t.Name, opt.Key)
		}
		seen[opt.Key] = true
		if err := write(opt.Key, opt.Value); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func newPlanCommand(opts *globalOptions, stdout io.Writer) *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Print what a normalize run would read, write and repair",
		Long: "plan reads the manifest, resolves each artifact's SBOM glob, and prints what\n" +
			"a normalize run would read, where it would write, and which transforms it\n" +
			"would apply. It writes nothing and makes no network calls.\n\n" +
			"--json prints the same thing as a machine contract, which is how\n" +
			"tools/build-p2-table.py learns which SBOMs to harvest and which mapping\n" +
			"table to write. Unlike index.json it needs no prior run, so it works in a\n" +
			"repository whose mapping table does not exist yet.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runPlan(opts, asJSON, stdout)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the plan as JSON")
	return cmd
}

func runPlan(opts *globalOptions, asJSON bool, stdout io.Writer) error {
	man, err := manifest.Load(opts.manifest)
	if err != nil {
		return usageErrorf("%v", err)
	}

	builtin, err := p2.BuiltinEntries()
	if err != nil {
		// The table is compiled in, so only a broken build reaches this.
		return internalErrorf("reading the built-in mapping table: %w", err)
	}

	p := plan{
		PlanVersion: PlanVersion,
		Tool:        planTool{Name: index.ToolName, Version: version},
		Manifest: planManifest{
			Path:   filepath.Base(man.Path),
			Dir:    man.Dir,
			SHA256: man.SHA256,
		},
		Out:          filepath.ToSlash(opts.out),
		BuiltinTable: builtin,
		Artifacts:    make([]planArtifact, 0, len(man.Artifacts)),
		// gate.require may legally be the empty subset, and a nil slice
		// serializes as null. Every array this format promises is an array,
		// exactly as in index.json, so a consumer can iterate it unguarded.
		Gate: planGate{Require: append([]string{}, man.Gate.Require...)},
	}

	for _, spec := range man.Artifacts {
		a, err := describeArtifact(man, spec)
		if err != nil {
			return err
		}
		p.Artifacts = append(p.Artifacts, a)
	}

	if asJSON {
		return writePlanJSON(p, stdout)
	}
	return writePlanText(p, man, opts, stdout)
}

// describeArtifact is the plan's counterpart to normalize's prepare, minus
// everything that touches the artifact's contents.
//
// The transforms are described before the glob is resolved, in the order
// prepare builds and resolves them, so the two commands report the same
// failure first on a manifest with more than one problem.
func describeArtifact(man *manifest.Manifest, spec manifest.Artifact) (planArtifact, error) {
	a := planArtifact{
		ID:         spec.ID,
		Output:     planFile{Path: spec.ID + ".cdx.json"},
		Transforms: make([]planTransform, 0, len(spec.Transforms)),
	}

	// A plan that succeeded on a manifest normalize refuses would describe a
	// run that cannot happen, so an unknown transform name or a bad transform
	// config is still exit 2 here (§2, §10).
	for _, ts := range spec.Transforms {
		options, err := transform.Describe(ts.Name, ts.Config)
		if err != nil {
			return planArtifact{}, usageErrorf("%s: artifact %q: %v", man.Path, spec.ID, err)
		}
		a.Transforms = append(a.Transforms, planTransform{Name: ts.Name, Options: options})
	}

	path, err := discover.Resolve(man.Dir, spec.ID, spec.SBOM)
	if err != nil {
		return planArtifact{}, usageErrorf("%v", err)
	}
	rel, err := index.RelPath(man.Dir, path)
	if err != nil {
		return planArtifact{}, usageErrorf("artifact %q: %v", spec.ID, err)
	}
	a.Input = planFile{Path: rel}

	return a, nil
}

// writePlanJSON emits the machine contract, with the same encoder settings
// index.json uses so paths and purls stay readable and two runs over the same
// manifest produce the same bytes (§7).
func writePlanJSON(p plan, stdout io.Writer) error {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return internalErrorf("serializing the plan: %w", err)
	}
	return nil
}

// writePlanText is the human half. It shows the options a manifest actually
// set rather than every resolved one: the full set is in --json, and a reader
// checking a manifest wants to see what it changed.
func writePlanText(p plan, man *manifest.Manifest, opts *globalOptions, stdout io.Writer) error {
	// The manifest is named the way the caller named it, which is what a human
	// recognises; the JSON records it the way index.json does instead.
	fmt.Fprintf(stdout, "manifest  %s (sha256 %s)\n", man.Path, shortDigest(p.Manifest.SHA256))

	if !opts.quiet {
		for _, a := range p.Artifacts {
			fmt.Fprintf(stdout, "\n%s\n", a.ID)
			fmt.Fprintf(stdout, "  read   %s\n", a.Input.Path)
			fmt.Fprintf(stdout, "  write  %s\n", filepath.ToSlash(filepath.Join(opts.out, a.Output.Path)))
			if len(a.Transforms) == 0 {
				fmt.Fprintf(stdout, "  no transforms\n")
				continue
			}
			for _, t := range a.Transforms {
				fmt.Fprintf(stdout, "  %s\n", describeTransformLine(t, man.Dir))
			}
		}
		fmt.Fprintln(stdout)
	}

	fmt.Fprintf(stdout, "gate  require %s\n", requireList(p.Gate.Require))
	return nil
}

// describeTransformLine renders one transform for a human: its name, then the
// options the manifest set, then a note on any named file that is not there
// yet.
//
// A missing file is not an error. The mapping table is produced from this very
// plan, so the first run in a repository necessarily names one that does not
// exist -- but `rio normalize` hard-fails on it, so a plan that stayed silent
// would be describing a run the reader is about to watch fail.
func describeTransformLine(t planTransform, baseDir string) string {
	parts := []string{t.Name}
	for _, opt := range t.Options {
		if opt.IsDefault {
			continue
		}
		part := opt.Key + " " + opt.Value
		if opt.Path && !fileExists(baseDir, opt.Value) {
			part += " (not there yet; rio normalize fails until it is)"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "  ")
}

func fileExists(baseDir, path string) bool {
	resolved := path
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(baseDir, path)
	}
	info, err := os.Stat(resolved)
	return err == nil && info.Mode().IsRegular()
}

// shortDigest trims a sha256 to the head a human compares by eye. The whole
// digest is in --json, where something reads it rather than looks at it.
func shortDigest(sum string) string {
	const head = 12
	if len(sum) <= head {
		return sum
	}
	return sum[:head] + "…"
}

// requireList renders gate.require, which the manifest allows to be explicitly
// empty. "nothing" reads as a decision; a trailing blank reads as a bug.
func requireList(require []string) string {
	if len(require) == 0 {
		return "nothing"
	}
	return strings.Join(require, ", ")
}
