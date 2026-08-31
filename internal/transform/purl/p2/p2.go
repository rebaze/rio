// Package p2 repairs Eclipse p2 coordinates into Maven coordinates (§6).
//
//	pkg:p2/com.google.gson@2.8.9.v20220111-1409?classifier=osgi.bundle&location=...
//	  becomes
//	pkg:maven/com.google.code.gson/gson@2.8.9
//
// It is the reason rio exists: nothing in the vulnerability world understands
// p2 coordinates, so an Eclipse RCP SBOM uploads with almost no findings until
// its identity fields are repaired.
//
// Two independent operations run per component and either can succeed without
// the other, so a bundle can have its version qualifier stripped while staying
// unmapped.
//
// The transform writes component.purl and one component property. Repair
// records in metadata.properties and evidence.identity are the pipeline's job,
// driven by the Changes and Notes returned here, so they stay uniform across
// every transform (§4.3).
package p2

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/rebaze/rio/internal/sbom"
	"github.com/rebaze/rio/internal/transform"
)

// ID names the transform in repair records and in index.json.
const ID = "repair-purl/p2"

// QualifierProperty holds the Eclipse build qualifier dropped from a version by
// §6.1. It is the only link back to the exact Eclipse build, so it is recorded
// rather than discarded.
const QualifierProperty = sbom.PropertyPrefix + "p2-qualifier"

// Defaults for the scope filter, all configurable from the manifest (§6.2).
const (
	DefaultGroupPrefix = "p2."
	DefaultClassifier  = "osgi.bundle"
	// DefaultSyntheticNamespace is the purl namespace Tycho invents for an
	// OSGi bundle it publishes as a Maven-shaped coordinate. See
	// applyToSyntheticMaven.
	DefaultSyntheticNamespace = "p2.eclipse.plugin"
)

// unmappedReason is the wording §4.3a shows in an unmapped record.
const unmappedReason = "no mapping entry"

// propertyKeyPairs are the generator-specific component property keys that
// carry Maven coordinates, checked in this order, first complete pair wins
// (§6.2 step 2). cyclonedx-maven-plugin emits none of them; they are cheap
// insurance for other generators.
var propertyKeyPairs = [][2]string{
	{"maven-groupId", "maven-artifactId"},
	{"maven.groupId", "maven.artifactId"},
	{"cdx:maven:groupId", "cdx:maven:artifactId"},
}

// qualifierGroupID and qualifierArtifactID are the purl qualifier keys checked
// by §6.2 step 1. purl qualifier keys are lowercased on parse, so these are
// matched case-insensitively.
const (
	qualifierGroupID    = "maven-groupid"
	qualifierArtifactID = "maven-artifactid"
)

type repairer struct {
	groupPrefix        string
	classifier         string
	syntheticNamespace string
	table              table
}

// The manifest keys this ecosystem accepts, beside the ecosystem key itself
// which belongs to the dispatch above.
const (
	OptionTable              = "table"
	OptionGroupPrefix        = "groupPrefix"
	OptionClassifier         = "classifier"
	OptionSyntheticNamespace = "syntheticNamespace"
)

// optionKeys is the one copy of the key list, in the order `rio plan` reports
// them. Describe rejects everything outside it and Scope.Options emits exactly
// it, so a key the transform starts honouring cannot stay invisible in a plan,
// and a key the plan advertises cannot be one the transform ignores.
var optionKeys = []string{
	OptionTable,
	OptionGroupPrefix,
	OptionClassifier,
	OptionSyntheticNamespace,
}

// Scope is what a manifest's p2 configuration resolves to: the three keys of
// the scope filter with their defaults filled in, plus the override table.
//
// It is the whole of what New needs besides the table's contents, and it is
// what `rio plan` publishes, so tools that have to filter an SBOM the same way
// rio does -- tools/build-p2-table.py is the one -- read the values in force
// rather than carrying their own copy of "p2." and "osgi.bundle".
type Scope struct {
	// Table is the manifest's table path exactly as written, because that is
	// how loadTables resolves it: against the manifest's own directory. Empty
	// when the manifest names no override.
	Table              string
	GroupPrefix        string
	Classifier         string
	SyntheticNamespace string
}

// Describe validates cfg and resolves it, without reading anything.
//
// It is deliberately the half of New that does not touch the filesystem. New
// loads the mapping table, and the mapping table is the file
// tools/build-p2-table.py exists to produce, so the first run in a repository
// has none: a describe that went through New could not describe the run that
// creates it.
func Describe(cfg transform.Config) (Scope, error) {
	if err := cfg.Reject(append([]string{"ecosystem"}, optionKeys...)...); err != nil {
		return Scope{}, err
	}

	tablePath, err := cfg.String(OptionTable, "")
	if err != nil {
		return Scope{}, err
	}
	groupPrefix, err := cfg.String(OptionGroupPrefix, DefaultGroupPrefix)
	if err != nil {
		return Scope{}, err
	}
	classifier, err := cfg.String(OptionClassifier, DefaultClassifier)
	if err != nil {
		return Scope{}, err
	}
	syntheticNamespace, err := cfg.String(OptionSyntheticNamespace, DefaultSyntheticNamespace)
	if err != nil {
		return Scope{}, err
	}
	// Empty would match every purl that has no namespace at all, putting the
	// whole Maven ecosystem in scope and turning §6.3 off by typo.
	if strings.TrimSpace(syntheticNamespace) == "" {
		return Scope{}, fmt.Errorf("syntheticNamespace must not be empty; " +
			"omit it to use the default " + DefaultSyntheticNamespace)
	}

	return Scope{
		Table:              tablePath,
		GroupPrefix:        groupPrefix,
		Classifier:         classifier,
		SyntheticNamespace: syntheticNamespace,
	}, nil
}

// defaultValues is what each option means with the manifest silent. The table
// has no default: no override table is a legal configuration, and the built-in
// table alone is what it resolves to.
var defaultValues = map[string]string{
	OptionTable:              "",
	OptionGroupPrefix:        DefaultGroupPrefix,
	OptionClassifier:         DefaultClassifier,
	OptionSyntheticNamespace: DefaultSyntheticNamespace,
}

// Options renders the scope as the ordered key/value pairs `rio plan` prints.
// The order is this package's, not the caller's: the plan says what this
// transform will do, so this package says in what terms.
func (s Scope) Options() []transform.Option {
	values := map[string]string{
		OptionTable:              s.Table,
		OptionGroupPrefix:        s.GroupPrefix,
		OptionClassifier:         s.Classifier,
		OptionSyntheticNamespace: s.SyntheticNamespace,
	}
	out := make([]transform.Option, 0, len(optionKeys))
	for _, key := range optionKeys {
		out = append(out, transform.Option{
			Key:       key,
			Value:     values[key],
			IsDefault: values[key] == defaultValues[key],
			Path:      key == OptionTable,
		})
	}
	return out
}

// New builds the p2 repairer. Every path in cfg resolves against baseDir, the
// manifest's own directory.
func New(cfg transform.Config, baseDir string) (transform.Transform, error) {
	scope, err := Describe(cfg)
	if err != nil {
		return nil, err
	}
	tbl, err := loadTables(scope.Table, baseDir)
	if err != nil {
		return nil, err
	}

	return &repairer{
		groupPrefix:        scope.GroupPrefix,
		classifier:         scope.Classifier,
		syntheticNamespace: scope.SyntheticNamespace,
		table:              tbl,
	}, nil
}

func (r *repairer) ID() string { return ID }

// Apply walks the components in document order and never iterates a map into
// the output, so two runs over the same input produce the same result (§7).
func (r *repairer) Apply(doc *sbom.Document) (transform.Result, error) {
	var res transform.Result
	for _, c := range doc.Components() {
		r.applyTo(c, &res)
	}
	return res, nil
}

func (r *repairer) applyTo(c *sbom.Component, res *transform.Result) {
	original := c.PURL()

	// Scope filter step 1. Three shapes are in scope, because Tycho emits
	// three: a pkg:p2 purl, a Maven-shaped purl under the namespace Tycho
	// invents for a bundle it has no coordinate for, and no purl at all
	// beside an OSGi bundle symbolic name (§6.3, and applyToSyntheticMaven
	// for why the second is here at all). A component carrying any other
	// Maven namespace is left alone unconditionally: garbage in stays
	// garbage, visibly, rather than being "corrected" into different garbage.
	if original == "" {
		r.applyToBundleWithoutPURL(c, res)
		return
	}
	parsed, err := packageurl.FromString(original)
	if err != nil {
		r.skip(res, c.Index, original, fmt.Sprintf("purl does not parse: %v", err))
		return
	}
	if parsed.Type == packageurl.TypeMaven && parsed.Namespace == r.syntheticNamespace {
		r.applyToSyntheticMaven(c, res, original, parsed)
		return
	}
	if parsed.Type != packageurl.TypeP2 {
		r.skip(res, c.Index, original,
			fmt.Sprintf("purl type is %q, not %q", parsed.Type, packageurl.TypeP2))
		return
	}

	// Scope filter step 2 (§6.2): only an OSGi bundle under the p2. group
	// prefix is in scope. Everything else is skipped, which is a third outcome
	// counted separately from unmapped, because a table hit against a
	// first-party reactor module or an Eclipse feature would be a confident
	// false positive.
	//
	// The filter gates BOTH operations below, not just the mapping: §6.2 says
	// a filtered-out component is "neither repaired nor counted as unmapped".
	// Stripping the Eclipse qualifier off a first-party 1.0.0.today would make
	// it read as a released 1.0.0, which is exactly the confident-looking lie
	// the scope filter exists to prevent.
	if reason, ok := r.inScope(c, parsed); !ok {
		r.skip(res, c.Index, original, reason)
		return
	}

	head, rawVersion, tail, splittable := splitPURL(original)

	// Operation A, the version qualifier (§6.1). It runs independently of
	// whether the coordinates can be mapped, so a bundle can have its version
	// fixed while staying unmapped.
	//
	// The rule is applied once, to the raw version substring, and the decoded
	// form is derived from that same split. Applying it separately to the
	// decoded version can disagree with the raw one when the version carries
	// percent-encoding — a %2E is a dot after decoding but not before — and
	// the document would then claim a qualifier drop that did not happen.
	repaired := original
	version := parsed.Version
	if splittable {
		if base, dropped := splitVersionQualifier(rawVersion); dropped != "" {
			repaired = head + base + tail
			version = decodeSegment(base, parsed.Version)
			c.AddProperty(QualifierProperty, decodeSegment(dropped, dropped))
		}
	}

	// Operation B, the coordinate mapping (§6.2).
	coords, found := r.resolve(c, &parsed)
	if !found {
		// No hit. The purl keeps its p2 type, its name and all its qualifiers;
		// only the version fix from A survives. A groupId is never inferred
		// from the symbolic name prefix, because a wrong coordinate is worse
		// than a missing one: it produces confident lookups against the wrong
		// package.
		r.unmapped(res, c.Index, original, unmappedReason)
	} else if reason, ok := coords.valid(); !ok {
		r.unmapped(res, c.Index, original, reason)
	} else {
		// The p2 qualifiers describe the p2 repository, not the Maven
		// artifact, so they are dropped along with any subpath.
		repaired = mavenPURL(coords, version)
	}

	// One Change per component even when both operations fired: the purl has
	// one before and one after.
	if repaired == original {
		return
	}
	c.SetPURL(repaired)
	res.Changes = append(res.Changes, transform.Change{
		ComponentIndex: c.Index,
		Field:          "purl",
		From:           original,
		To:             repaired,
	})
}

// applyToSyntheticMaven handles an OSGi bundle that the generator published as
// a Maven-shaped purl under a namespace it invented:
//
//	pkg:maven/p2.eclipse.plugin/org.apache.commons.commons-io@2.11.0?type=eclipse-plugin
//
// This is a deliberate override of §6.3, which says a component with a valid
// pkg:maven purl is left alone unconditionally and gives the example of an
// installable unit whose synthetic groupId "will never resolve to anything".
// The spec's reason is visibility: garbage in stays garbage rather than being
// corrected into different garbage. That reasoning was written around one
// stray component. On the estate rio was built for this shape is 605 of 688
// — the entire product — and leaving it alone means the tool declines to do
// the one job it exists for, silently.
//
// What makes the override safe is not that §6.3 does not apply. It is that
// p2.eclipse.plugin is a placeholder rather than a groupId, so no such purl
// resolves in any public registry or vulnerability database, and that the
// replacement is looked up rather than derived.
//
// What does NOT change is §6.2's prohibition: the coordinate still comes from
// the table or from the component's own properties, never from splitting the
// symbolic name. "org.apache.commons.commons-io" is only
// org.apache.commons:commons-io because a curated entry says so.
//
// Unlike the p2-purl path, the version fix in §6.1 is not applied on its own
// here, and the reason is not symmetry but what the two shapes look like to a
// consumer. An unmapped pkg:p2 purl announces its own unusability through its
// type, so tidying its version is harmless. An unmapped synthetic purl already
// looks like Maven; strip the Eclipse qualifier off
// pkg:maven/p2.eclipse.plugin/com.google.guava@30.1.0.v1 and it becomes
// indistinguishable from a well-formed coordinate that a lenient matcher will
// act on, against a groupId that does not exist. A miss therefore leaves the
// purl byte-identical.
func (r *repairer) applyToSyntheticMaven(c *sbom.Component, res *transform.Result, original string, parsed packageurl.PackageURL) {
	// A plugin carries no classifier here; a nested artefact does, and it
	// shares the plugin's name and version. In the estate this was built for,
	// org.eclipse.jdt.debug appears twice — once as the bundle and once as
	// classifier=jdimodel.jar, a jar shipped inside it. Resolving by name
	// alone would give both the same coordinate, asserting that the nested jar
	// IS the plugin and putting two identical purls in a document rio calls
	// valid. The p2 path is guarded by classifier=osgi.bundle; this is the
	// same guard, stated the way this shape states it.
	if classifier := qualifier(&parsed, "classifier"); classifier != "" {
		r.skip(res, c.Index, original, fmt.Sprintf(
			"purl carries classifier %q, so it is an artefact inside a bundle rather than the bundle",
			classifier))
		return
	}

	// §6.2's full resolution order, step 1 included: a generator that already
	// put maven-groupId on the purl should be believed over the table, exactly
	// as it is on the p2 path.
	coords, found := r.resolve(c, &parsed)
	if !found {
		r.unmapped(res, c.Index, original, unmappedReason)
		return
	}
	if reason, ok := coords.valid(); !ok {
		r.unmapped(res, c.Index, original, reason)
		return
	}

	// The version may still carry an Eclipse build qualifier even here, so
	// §6.1 applies once the coordinate is known.
	version, dropped := splitVersionQualifier(parsed.Version)
	if dropped != "" {
		c.AddProperty(QualifierProperty, dropped)
	}

	// type=eclipse-plugin describes the p2 packaging, not the Maven artifact,
	// so it goes the way the p2 qualifiers do.
	repaired := mavenPURL(coords, version)
	if repaired == original {
		return
	}
	c.SetPURL(repaired)
	res.Changes = append(res.Changes, transform.Change{
		ComponentIndex: c.Index,
		Field:          "purl",
		From:           original,
		To:             repaired,
	})
}

// applyToBundleWithoutPURL handles §6.3's second case: a component with no
// purl that carries an OSGi bundle symbolic name.
//
// There is no classifier qualifier to check here, so the scope filter is the
// group prefix plus a symbolic name, and a coordinate is only ever written on
// a real table or property hit. Nothing is inferred from the name: writing a
// purl the generator did not write is only defensible when a curated entry
// says what it should be.
func (r *repairer) applyToBundleWithoutPURL(c *sbom.Component, res *transform.Result) {
	name := c.Name()
	if group := c.Group(); !strings.HasPrefix(group, r.groupPrefix) {
		r.skip(res, c.Index, "", fmt.Sprintf(
			"component has no purl, and group %q does not start with %q", group, r.groupPrefix))
		return
	}
	if name == "" {
		r.skip(res, c.Index, "", "component has no purl and no name to resolve it by")
		return
	}

	coords, found := r.resolveByName(c, name)
	if !found {
		r.unmapped(res, c.Index, "", unmappedReason)
		return
	}
	if reason, ok := coords.valid(); !ok {
		r.unmapped(res, c.Index, "", reason)
		return
	}

	// component.version is the only version available, so §6.1 applies to it
	// here. The component's own version field still stays as found (§6.4).
	version, dropped := splitVersionQualifier(c.Version())
	if dropped != "" {
		c.AddProperty(QualifierProperty, dropped)
	}

	repaired := mavenPURL(coords, version)
	c.SetPURL(repaired)
	res.Changes = append(res.Changes, transform.Change{
		ComponentIndex: c.Index,
		Field:          "purl",
		From:           "",
		To:             repaired,
	})
}

// mavenPURL builds the repaired coordinate. Rebuilding through packageurl-go
// rather than by hand keeps percent-encoding and qualifier ordering correct.
func mavenPURL(coords Coordinates, version string) string {
	p := packageurl.PackageURL{
		Type:      packageurl.TypeMaven,
		Namespace: coords.GroupID,
		Name:      coords.ArtifactID,
		Version:   version,
	}
	return p.ToString()
}

// valid rejects coordinates that would produce a confident but wrong lookup
// key, and says why.
//
// packageurl-go only refuses an empty name, so it is no guard here: a groupId
// of "com/example" silently becomes the nested namespace
// pkg:maven/com/example/artifact, which resolves to nothing while looking
// entirely plausible. Steps 1 and 2 of §6.2 read these values out of the SBOM,
// so they are as untrusted as the document itself.
func (c Coordinates) valid() (reason string, ok bool) {
	for _, f := range []struct{ what, value string }{
		{"groupId", c.GroupID},
		{"artifactId", c.ArtifactID},
	} {
		switch {
		case f.value == "":
			return "resolved " + f.what + " is empty", false
		case strings.ContainsAny(f.value, "/?#@"):
			return fmt.Sprintf("resolved %s %q contains a purl separator", f.what, f.value), false
		case strings.TrimSpace(f.value) != f.value || strings.ContainsAny(f.value, " \t\n\r"):
			return fmt.Sprintf("resolved %s %q contains whitespace", f.what, f.value), false
		}
	}
	return "", true
}

// decodeSegment returns the decoded form of a raw purl segment, falling back to
// the value the parser already produced when the escape is malformed.
func decodeSegment(raw, fallback string) string {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return fallback
	}
	return decoded
}

func (r *repairer) unmapped(res *transform.Result, index int, purl, reason string) {
	res.Notes = append(res.Notes, transform.Note{
		ComponentIndex: index,
		Kind:           transform.NoteUnmapped,
		PURL:           purl,
		Reason:         reason,
	})
}

func (r *repairer) skip(res *transform.Result, index int, purl, reason string) {
	res.Notes = append(res.Notes, transform.Note{
		ComponentIndex: index,
		Kind:           transform.NoteSkipped,
		PURL:           purl,
		Reason:         reason,
	})
}

// inScope reports whether the component is in scope for the transform, and why
// not when it is not (§6.2).
func (r *repairer) inScope(c *sbom.Component, parsed packageurl.PackageURL) (reason string, ok bool) {
	classifier := qualifier(&parsed, "classifier")
	if classifier != r.classifier {
		if classifier == "" {
			return fmt.Sprintf("purl carries no classifier qualifier, want %q", r.classifier), false
		}
		return fmt.Sprintf("purl classifier is %q, not %q", classifier, r.classifier), false
	}
	if group := c.Group(); !strings.HasPrefix(group, r.groupPrefix) {
		return fmt.Sprintf("group %q does not start with %q", group, r.groupPrefix), false
	}
	return "", true
}

// resolve runs §6.2's resolution order, first hit wins.
func (r *repairer) resolve(c *sbom.Component, parsed *packageurl.PackageURL) (Coordinates, bool) {
	// 1. Qualifiers already on the purl. Free, exact, no table needed.
	if g, a := qualifier(parsed, qualifierGroupID), qualifier(parsed, qualifierArtifactID); g != "" && a != "" {
		return Coordinates{GroupID: g, ArtifactID: a}, true
	}

	// Steps 2 and 3 are keyed by the bundle symbolic name, which is the purl's
	// name segment rather than component.name: the purl is the field being
	// repaired and the only one guaranteed to hold the symbolic name, even
	// though the two agree in every generator seen so far.
	return r.resolveByName(c, parsed.Name)
}

// resolveByName runs steps 2 and 3 of §6.2's resolution order. Step 1 needs
// purl qualifiers and is therefore unavailable to a component with no purl.
func (r *repairer) resolveByName(c *sbom.Component, name string) (Coordinates, bool) {
	// 2. The component's own properties, for generators that carry Maven
	//    coordinates there.
	props := c.Properties()
	for _, pair := range propertyKeyPairs {
		g, a := property(props, pair[0]), property(props, pair[1])
		if g != "" && a != "" {
			return Coordinates{GroupID: g, ArtifactID: a}, true
		}
	}

	// 3. The mapping table.
	if coords, found := r.table[name]; found {
		return coords, true
	}

	// 4. No hit.
	return Coordinates{}, false
}

// qualifier reads one purl qualifier. Keys are compared case-insensitively
// because packageurl-go lowercases them on parse and generators do not.
func qualifier(parsed *packageurl.PackageURL, key string) string {
	for _, q := range parsed.Qualifiers {
		if strings.EqualFold(q.Key, key) {
			return q.Value
		}
	}
	return ""
}

func property(props []sbom.Property, name string) string {
	for _, p := range props {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// splitPURL cuts a purl string into the text up to and including the version
// separator, the raw version substring, and the qualifier and subpath tail.
//
// The version fix splices these back together rather than rebuilding through
// packageurl-go, because ToString re-encodes qualifier values: a generator's
// location=https%3A%2F%2Fdownload.eclipse.org%2F comes back as
// location=https:%2F%2Fdownload.eclipse.org%2F. The value is equal but the
// string is not, and the component's bom-ref still holds the original, so the
// document would carry an unexplained difference in a field rio was never
// asked to touch (§6.4).
func splitPURL(purl string) (head, version, tail string, ok bool) {
	body := purl
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		body, tail = purl[:i], purl[i:]
	}
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return "", "", "", false
	}
	return body[:at+1], body[at+1:], tail, true
}

// splitVersionQualifier applies §6.1. An Eclipse version is
// major.minor.micro.qualifier and a Maven version is not, so exactly four
// segments whose fourth is not purely numeric means the fourth is an Eclipse
// build qualifier. Anything else is left alone: 1.2.3.4 is a legitimate Maven
// version and dropping its fourth segment would be a lie.
func splitVersionQualifier(version string) (base, dropped string) {
	segments := strings.Split(version, ".")
	if len(segments) != 4 {
		return version, ""
	}
	last := segments[3]
	// An empty fourth segment carries no build information, so there is nothing
	// to preserve and nothing to drop.
	if last == "" || isDigits(last) {
		return version, ""
	}
	return strings.Join(segments[:3], "."), last
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
