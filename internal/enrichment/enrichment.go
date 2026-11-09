// Package enrichment resolves manifest metadata declarations without reading SBOMs.
package enrichment

import "encoding/json"

// Config declares values that fill absent SBOM metadata unless Replace opts in.
// Pointer leaves distinguish omission from explicitly supplied values.
type Config struct {
	Subject     *Subject      `yaml:"subject" json:"subject,omitempty"`
	Producer    *Organization `yaml:"producer" json:"producer,omitempty"`
	DataLicense *string       `yaml:"dataLicense" json:"dataLicense,omitempty"`
	Replace     *[]string     `yaml:"replace" json:"replace,omitempty"`
}

type Subject struct {
	Name            *string       `yaml:"name" json:"name,omitempty"`
	Group           *string       `yaml:"group" json:"group,omitempty"`
	Version         *string       `yaml:"version" json:"version,omitempty"`
	Type            *string       `yaml:"type" json:"type,omitempty"`
	PURL            *string       `yaml:"purl" json:"purl,omitempty"`
	Manufacturer    *Organization `yaml:"manufacturer" json:"manufacturer,omitempty"`
	Supplier        *Organization `yaml:"supplier" json:"supplier,omitempty"`
	SecurityContact *string       `yaml:"securityContact" json:"securityContact,omitempty"`
	Website         *string       `yaml:"website" json:"website,omitempty"`
	Documentation   *string       `yaml:"documentation" json:"documentation,omitempty"`
	Support         *string       `yaml:"support" json:"support,omitempty"`
	IssueTracker    *string       `yaml:"issueTracker" json:"issueTracker,omitempty"`
	ReleaseNotes    *string       `yaml:"releaseNotes" json:"releaseNotes,omitempty"`
	Advisories      *string       `yaml:"advisories" json:"advisories,omitempty"`
	// Links are labelled external references. Each label is its own leaf,
	// subject.links[<label>], so shared and artifact lists merge per label.
	Links *[]Link `yaml:"links" json:"links,omitempty"`
}

// Link is one labelled subject reference. The label becomes the CycloneDX
// reference's comment; Type defaults to "other".
type Link struct {
	Label *string `yaml:"label" json:"label,omitempty"`
	URL   *string `yaml:"url" json:"url,omitempty"`
	Type  *string `yaml:"type" json:"type,omitempty"`
}

// LinkValue is the effective value of one subject.links[<label>] leaf.
type LinkValue struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

type Organization struct {
	Name    *string    `yaml:"name" json:"name,omitempty"`
	URL     *[]string  `yaml:"url" json:"url,omitempty"`
	Contact *[]Contact `yaml:"contact" json:"contact,omitempty"`
}

type Contact struct {
	Name  *string `yaml:"name" json:"name,omitempty"`
	Email *string `yaml:"email" json:"email,omitempty"`
	Phone *string `yaml:"phone" json:"phone,omitempty"`
}

// Resolved is a versioned additive extension in rio plan's JSON contract.
type Resolved struct {
	Version int     `json:"version"`
	Fields  []Field `json:"fields"`
}

// Field is one effective metadata leaf and its manifest provenance.
type Field struct {
	Field   string          `json:"field"`
	Value   json.RawMessage `json:"value"`
	Source  string          `json:"source"`
	Replace bool            `json:"replace"`
}
