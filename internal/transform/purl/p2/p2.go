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

// Defaults for the scope filter, both configurable from the manifest (§6.2).
const (
	DefaultGroupPrefix = "p2."
	DefaultClassifier  = "osgi.bundle"
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
	groupPrefix string
	classifier  string
	table       table
}

// New builds the p2 repairer. Every path in cfg resolves against baseDir, the
// manifest's own directory.
func New(cfg transform.Config, baseDir string) (transform.Transform, error) {
	if err := cfg.Reject("ecosystem", "table", "groupPrefix", "classifier"); err != nil {
		return nil, err
	}

	groupPrefix, err := cfg.String("groupPrefix", DefaultGroupPrefix)
	if err != nil {
		return nil, err
	}
	classifier, err := cfg.String("classifier", DefaultClassifier)
	if err != nil {
		return nil, err
	}
	tablePath, err := cfg.String("table", "")
	if err != nil {
		return nil, err
	}
	tbl, err := loadTables(tablePath, baseDir)
	if err != nil {
		return nil, err
	}

	return &repairer{groupPrefix: groupPrefix, classifier: classifier, table: tbl}, nil
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

	// Scope filter step 1 (§6.3). A component whose purl is absent, unparseable
	// or not of type p2 is left alone unconditionally. That includes the
	// installable unit already carrying a valid pkg:maven purl with a synthetic
	// groupId that will never resolve: garbage in stays garbage, visibly,
	// rather than being silently "corrected" into different garbage.
	if original == "" {
		r.skip(res, c.Index, original, "component has no purl")
		return
	}
	parsed, err := packageurl.FromString(original)
	if err != nil {
		r.skip(res, c.Index, original, fmt.Sprintf("purl does not parse: %v", err))
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
	repaired := original
	version := parsed.Version
	if splittable {
		if base, dropped := splitVersionQualifier(rawVersion); dropped != "" {
			repaired = head + base + tail
			version, _ = splitVersionQualifier(parsed.Version)
			c.AddProperty(QualifierProperty, dropped)
		}
	}

	// Operation B, the coordinate mapping (§6.2).
	if coords, found := r.resolve(c, parsed); !found {
		// No hit. The purl keeps its p2 type, its name and all its qualifiers;
		// only the version fix from A survives. A groupId is never inferred
		// from the symbolic name prefix, because a wrong coordinate is worse
		// than a missing one: it produces confident lookups against the wrong
		// package.
		res.Notes = append(res.Notes, transform.Note{
			ComponentIndex: c.Index,
			Kind:           transform.NoteUnmapped,
			PURL:           original,
			Reason:         unmappedReason,
		})
	} else {
		// The p2 qualifiers describe the p2 repository, not the Maven
		// artifact, so they are dropped along with any subpath.
		mapped := packageurl.PackageURL{
			Type:      packageurl.TypeMaven,
			Namespace: coords.GroupID,
			Name:      coords.ArtifactID,
			Version:   version,
		}
		if err := mapped.Normalize(); err != nil {
			// Coordinates that cannot form a purl are reported, never written:
			// a malformed lookup key is the failure mode this transform exists
			// to remove.
			res.Notes = append(res.Notes, transform.Note{
				ComponentIndex: c.Index,
				Kind:           transform.NoteUnmapped,
				PURL:           original,
				Reason: fmt.Sprintf("resolved coordinates %s:%s do not form a valid purl: %v",
					coords.GroupID, coords.ArtifactID, err),
			})
		} else {
			repaired = mapped.ToString()
		}
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
	classifier := qualifier(parsed, "classifier")
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
func (r *repairer) resolve(c *sbom.Component, parsed packageurl.PackageURL) (coordinates, bool) {
	// 1. Qualifiers already on the purl. Free, exact, no table needed.
	if g, a := qualifier(parsed, qualifierGroupID), qualifier(parsed, qualifierArtifactID); g != "" && a != "" {
		return coordinates{GroupID: g, ArtifactID: a}, true
	}

	// 2. The component's own properties, for generators that carry Maven
	//    coordinates there.
	props := c.Properties()
	for _, pair := range propertyKeyPairs {
		g, a := property(props, pair[0]), property(props, pair[1])
		if g != "" && a != "" {
			return coordinates{GroupID: g, ArtifactID: a}, true
		}
	}

	// 3. The mapping table, keyed by bundle symbolic name. The key is the
	//    purl's name segment rather than component.name: the purl is the field
	//    being repaired and the only one guaranteed to hold the symbolic name,
	//    even though the two agree in every generator seen so far.
	if coords, found := r.table[parsed.Name]; found {
		return coords, true
	}

	// 4. No hit.
	return coordinates{}, false
}

// qualifier reads one purl qualifier. Keys are compared case-insensitively
// because packageurl-go lowercases them on parse and generators do not.
func qualifier(parsed packageurl.PackageURL, key string) string {
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
