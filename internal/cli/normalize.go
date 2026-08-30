package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rebaze/rio/internal/discover"
	"github.com/rebaze/rio/internal/gate"
	"github.com/rebaze/rio/internal/index"
	"github.com/rebaze/rio/internal/manifest"
	"github.com/rebaze/rio/internal/sbom"
	"github.com/rebaze/rio/internal/transform"

	// Registers the repair-purl transform and its p2 ecosystem.
	_ "github.com/rebaze/rio/internal/transform/purl"
)

// Gate modes (§1).
const (
	gateWarn = "warn"
	gateFail = "fail"
)

func newNormalizeCommand(opts *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	var gateMode string

	cmd := &cobra.Command{
		Use:   "normalize",
		Short: "Level the spec version, repair identity, and check quality",
		Long: "normalize reads the manifest, resolves each artifact's SBOM, raises it to\n" +
			"the spec version floor, applies the configured transforms, checks the gate,\n" +
			"and writes one normalized document per artifact plus index.json.\n\n" +
			"Run it from the repository root, after the build has produced SBOMs.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runNormalize(opts, gateMode, stdout, stderr)
		},
	}
	// Local to normalize; the persistent flags live on the root (§8).
	cmd.Flags().StringVar(&gateMode, "gate", gateWarn, `"warn" or "fail"`)
	return cmd
}

// artifact is one manifest artifact carried through the five steps of §5.
type artifact struct {
	spec       manifest.Artifact
	transforms []transform.Transform

	inputPath string // absolute
	inputRel  string // relative to the manifest directory, for index.json
	inputSHA  string
	inputSpec string
	doc       *sbom.Document

	outputSpec      string
	schemaValidated bool
	components      int
	stats           []index.TransformResult
	gate            gate.Result
	integrity       []sbom.IntegrityFinding
	output          []byte
}

func runNormalize(opts *globalOptions, gateMode string, stdout, stderr io.Writer) error {
	if gateMode != gateWarn && gateMode != gateFail {
		return usageErrorf("--gate must be %q or %q, got %q", gateWarn, gateFail, gateMode)
	}

	man, err := manifest.Load(opts.manifest)
	if err != nil {
		return usageErrorf("%v", err)
	}

	// Steps 1 to 4 for every artifact before anything is written. Exit 2
	// conditions abort the whole run before any file is created (§5, §10).
	artifacts := make([]*artifact, 0, len(man.Artifacts))
	for _, spec := range man.Artifacts {
		a, err := prepare(man, spec)
		if err != nil {
			return err
		}
		if err := process(man, a); err != nil {
			return err
		}
		artifacts = append(artifacts, a)
	}

	outDir, err := filepath.Abs(opts.out)
	if err != nil {
		return internalErrorf("resolving --out %q: %w", opts.out, err)
	}
	if err := writeAll(man, artifacts, outDir); err != nil {
		return err
	}

	return report(artifacts, gateMode, opts.quiet, stdout, stderr)
}

// prepare is step 1: resolve the glob, read the file, hash it, and decode it.
func prepare(man *manifest.Manifest, spec manifest.Artifact) (*artifact, error) {
	a := &artifact{spec: spec}

	// Build the transforms first: an unknown transform name or a bad transform
	// config is a configuration error, and finding it before touching the
	// filesystem keeps exit 2 free of side effects (§2).
	for _, ts := range spec.Transforms {
		t, err := transform.New(ts.Name, ts.Config, man.Dir)
		if err != nil {
			return nil, usageErrorf("%s: artifact %q: %v", man.Path, spec.ID, err)
		}
		a.transforms = append(a.transforms, t)
	}

	path, err := discover.Resolve(man.Dir, spec.ID, spec.SBOM)
	if err != nil {
		return nil, usageErrorf("%v", err)
	}
	a.inputPath = path
	rel, err := index.RelPath(man.Dir, path)
	if err != nil {
		return nil, usageErrorf("artifact %q: %v", spec.ID, err)
	}
	a.inputRel = rel

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, usageErrorf("artifact %q: reading %s: %v", spec.ID, path, err)
	}
	a.inputSHA = index.SHA256Bytes(data)

	doc, err := sbom.Load(data)
	if err != nil {
		return nil, usageErrorf("artifact %q: %s: %v", spec.ID, a.inputRel, err)
	}
	a.doc = doc
	a.inputSpec = doc.SpecVersion()

	// Validate the input at its own declared spec version. Doing it here means
	// a broken input is attributed to the input, not to rio (§5 step 2b).
	if err := sbom.Validate(data, a.inputSpec); err != nil {
		var noSchema *sbom.ErrNoSchema
		var invalid *sbom.ValidationError
		switch {
		case errors.As(err, &noSchema):
			// Above the highest embedded schema: pass through (§3).
		case errors.As(err, &invalid):
			return nil, usageErrorf(
				"artifact %q: %s is not valid CycloneDX %s as generated, before rio touched it.\n"+
					"This is a finding about the input, not a rio bug: fix the generator or the document, then run rio again.\n%v",
				spec.ID, a.inputRel, a.inputSpec, invalid)
		default:
			return nil, internalErrorf("artifact %q: validating %s: %w", spec.ID, a.inputRel, err)
		}
	}

	return a, nil
}

// process runs steps 2 to 4: uplift, transform, record, gate, validate.
func process(man *manifest.Manifest, a *artifact) error {
	doc := a.doc
	a.components = doc.ComponentCount()

	upliftApplied, upliftFrom, err := doc.Uplift(man.Output.SpecVersionFloor)
	if err != nil {
		return usageErrorf("%s: %v", man.Path, err)
	}
	a.outputSpec = doc.SpecVersion()

	// Step 3: transforms, in the order the manifest gave them.
	for _, t := range a.transforms {
		before := doc.Fingerprint()

		result, err := t.Apply(doc)
		if err != nil {
			return internalErrorf("artifact %q: transform %s: %w", a.spec.ID, t.ID(), err)
		}

		// A transform never adds or removes components. Fail loudly rather
		// than writing a document whose membership silently changed (§5 step 3).
		if after := doc.Fingerprint(); !sameFingerprint(before, after) {
			return internalErrorf(
				"artifact %q: transform %s changed component membership: %d components before, %d after."+
					" v1 transforms may only rewrite identity fields",
				a.spec.ID, t.ID(), len(before), len(after))
		}

		a.stats = append(a.stats, recordTransform(doc, t.ID(), result))
	}

	// Subject override before the gate, since the gate reads what ends up in
	// the document (§4.3d).
	if s := a.spec.Subject; s != nil {
		oldName, oldVersion := doc.SetSubject(s.Name, s.Version)
		doc.AddMetadataProperty(sbom.PropertyPrefix+"subject-override",
			fmt.Sprintf("from=%s@%s | to=%s@%s", oldName, oldVersion, s.Name, s.Version))
	}

	// Run metadata (§4.3a).
	doc.AddTool(version)
	doc.AddMetadataProperty(sbom.PropertyPrefix+"tool", "rio "+version)
	doc.AddMetadataProperty(sbom.PropertyPrefix+"artifact-id", a.spec.ID)
	doc.AddMetadataProperty(sbom.PropertyPrefix+"manifest-sha256", man.SHA256)
	doc.AddMetadataProperty(sbom.PropertyPrefix+"input-sha256", a.inputSHA)
	if upliftApplied {
		doc.AddMetadataProperty(sbom.PropertyPrefix+"spec-uplift",
			fmt.Sprintf("from=%s to=%s", upliftFrom, a.outputSpec))
	}

	doc.Finalize()

	a.integrity = doc.IntegrityFindings()

	output, err := doc.Bytes()
	if err != nil {
		return internalErrorf("artifact %q: %w", a.spec.ID, err)
	}
	a.output = output

	// Step 2b: validate the finished document. Reaching here means the input
	// was valid at its own version, so an invalid output is rio's fault.
	if err := sbom.Validate(output, a.outputSpec); err != nil {
		var noSchema *sbom.ErrNoSchema
		var invalid *sbom.ValidationError
		switch {
		case errors.As(err, &noSchema):
			a.schemaValidated = false
		case errors.As(err, &invalid):
			return usageErrorf(
				"artifact %q: rio produced a document that is not valid CycloneDX %s, from an input that was valid.\n"+
					"This is a bug in rio. Please report it with the input document.\n%v",
				a.spec.ID, a.outputSpec, invalid)
		default:
			return internalErrorf("artifact %q: validating output: %w", a.spec.ID, err)
		}
	} else {
		a.schemaValidated = true
	}

	// Step 4: the gate reads, it never modifies.
	a.gate = gate.Check(doc, requirements(man.Gate.Require))

	return nil
}

// recordTransform writes the canonical repair records into metadata.properties
// and the identity evidence onto each repaired component (§4.3a, §4.3b), and
// returns the counts for index.json.
//
// This lives in the pipeline rather than in each transform so that every
// transform, present and future, produces the same record format.
func recordTransform(doc *sbom.Document, id string, result transform.Result) index.TransformResult {
	stat := index.TransformResult{ID: id}

	for _, c := range result.Changes {
		doc.AddMetadataProperty(sbom.PropertyPrefix+"repair",
			fmt.Sprintf("rule=%s | from=%s | to=%s", id, c.From, c.To))

		if comp := doc.Component(c.ComponentIndex); comp != nil {
			comp.AppendIdentityEvidence(c.Field, 0.9, fmt.Sprintf("rio %s: %s", id, c.From))
		}
		stat.Applied++
	}

	for _, n := range result.Notes {
		switch n.Kind {
		case transform.NoteUnmapped:
			// Misses are recorded as visibly as hits, so an unmapped bundle is
			// discoverable from the output document alone (§4.3a).
			doc.AddMetadataProperty(sbom.PropertyPrefix+"unmapped",
				fmt.Sprintf("rule=%s | purl=%s | reason=%s", id, n.PURL, n.Reason))
			stat.Unmapped++
		case transform.NoteSkipped:
			// Out of scope is a third outcome, counted in the index but not
			// written into the document: on a real product SBOM most
			// components are out of scope and the noise would bury the hits.
			stat.Skipped++
		}
	}

	return stat
}

func sameFingerprint(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeAll is step 5. Nothing is written until every artifact has passed steps
// 1 to 4, so an exit 2 leaves the output directory as it found it (§1).
func writeAll(man *manifest.Manifest, artifacts []*artifact, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return internalErrorf("creating output directory %s: %w", outDir, err)
	}

	idx := index.New(version, index.FileRef{Path: man.Path, SHA256: man.SHA256})

	for _, a := range artifacts {
		name := a.spec.ID + ".cdx.json"
		path := filepath.Join(outDir, name)

		if err := sbom.WriteFile(path, a.output); err != nil {
			return internalErrorf("artifact %q: %w", a.spec.ID, err)
		}

		// Hash the bytes on disk, not the bytes in memory: index.json claims
		// something about the file a consumer will read (§4.2).
		sum, err := index.SHA256File(path)
		if err != nil {
			return internalErrorf("artifact %q: %w", a.spec.ID, err)
		}

		idx.Artifacts = append(idx.Artifacts, index.Artifact{
			ID:                a.spec.ID,
			Input:             index.FileRef{Path: a.inputRel, SHA256: a.inputSHA},
			Output:            index.FileRef{Path: name, SHA256: sum},
			SpecVersion:       index.SpecVersions{Input: a.inputSpec, Output: a.outputSpec},
			SchemaValidated:   a.schemaValidated,
			Components:        a.components,
			Transforms:        a.stats,
			Gate:              gateStatus(a.gate),
			GateFindings:      gateFindings(a.gate),
			IntegrityFindings: a.integrity,
		})
	}

	// index.json is written last, after every artifact (§4.2).
	if _, err := index.Write(outDir, idx); err != nil {
		return internalErrorf("%w", err)
	}
	return nil
}

func gateStatus(r gate.Result) index.Gate {
	if r.OK() {
		return index.GateOK
	}
	return index.GateFail
}

// gateFindings converts the gate's findings into the index's own shape. The
// index owns the on-disk contract (§4.2) and the gate owns the checks; keeping
// the types separate means neither can drift the other by accident.
func gateFindings(r gate.Result) []index.GateFinding {
	out := make([]index.GateFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, index.GateFinding{
			Subject:   f.Subject,
			Component: f.Component,
			Missing:   f.Missing,
		})
	}
	return out
}

// requirements converts the manifest's gate.require strings into the gate's
// own type. Values outside the three the manifest accepts cannot reach here.
func requirements(require []string) []gate.Requirement {
	out := make([]gate.Requirement, 0, len(require))
	for _, r := range require {
		out = append(out, gate.Requirement(r))
	}
	return out
}

// report prints the per artifact lines and the summary, and decides the exit
// code. Under --gate warn a failure is still recorded in the index and printed
// to stderr, but does not affect the exit code (§5 step 4).
func report(artifacts []*artifact, gateMode string, quiet bool, stdout, stderr io.Writer) error {
	idWidth, countWidth := 0, 0
	for _, a := range artifacts {
		idWidth = max(idWidth, len(a.spec.ID))
		countWidth = max(countWidth, len(fmt.Sprint(a.components)))
	}

	failures := 0
	for _, a := range artifacts {
		var applied, unmapped int
		for _, s := range a.stats {
			applied += s.Applied
			unmapped += s.Unmapped
		}

		status := "ok"
		if !a.gate.OK() {
			failures++
			status = "FAIL (" + summarizeFindings(a.gate) + ")"
			fmt.Fprintf(stderr, "rio: artifact %q failed the gate: %s\n", a.spec.ID, summarizeFindings(a.gate))
		}
		for _, f := range a.integrity {
			fmt.Fprintf(stderr, "rio: artifact %q: dangling dependency reference %s\n", a.spec.ID, f.Ref)
		}

		if !quiet {
			fmt.Fprintf(stdout, "%-*s  %*d components   repaired %-4d unmapped %-4d gate %s\n",
				idWidth, a.spec.ID, countWidth, a.components, applied, unmapped, status)
		}
	}

	fmt.Fprintf(stdout, "%s, %s\n", plural(len(artifacts), "artifact"), gateSummary(failures))

	if failures > 0 && gateMode == gateFail {
		return gateFailure
	}
	return nil
}

// summarizeFindings turns gate findings into one human-readable clause.
func summarizeFindings(r gate.Result) string {
	var parts []string
	byField := map[string]int{}

	for _, f := range r.Findings {
		if f.Subject {
			parts = append(parts, "subject missing "+strings.Join(f.Missing, " and "))
			continue
		}
		for _, m := range f.Missing {
			byField[m]++
		}
	}

	fields := make([]string, 0, len(byField))
	for field := range byField {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		parts = append(parts, fmt.Sprintf("%s missing %s", plural(byField[field], "component"), field))
	}

	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, ", ")
}

func gateSummary(failures int) string {
	if failures == 0 {
		return "no gate failures"
	}
	return plural(failures, "gate failure")
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
