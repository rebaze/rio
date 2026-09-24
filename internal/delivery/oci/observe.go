package oci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"strings"

	"github.com/rebaze/rio/internal/delivery"
)

func (c *client) verifyDescriptor(ctx context.Context, path string, expected Descriptor, canonical []byte) (string, int) {
	resp, e := c.request(ctx, "GET", "/v2/"+c.options.Repository+"/"+path, nil, 0, "")
	if e != nil {
		return "content_unavailable", status(ctx)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "content_unavailable", resp.StatusCode
	}
	if strings.HasPrefix(path, "manifests/") {
		media, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if e != nil || media != expected.MediaType {
			return "content_mismatch", 200
		}
	}
	if resp.ContentLength >= 0 && resp.ContentLength != expected.Size {
		return "content_mismatch", 200
	}
	if canonical != nil {
		raw, e := readResponse(resp, DocumentLimit)
		if e != nil {
			return "content_unavailable", 200
		}
		if !bytes.Equal(raw, canonical) || int64(len(raw)) != expected.Size || "sha256:"+delivery.Digest(raw) != expected.Digest {
			return "content_mismatch", 200
		}
	} else {
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(resp.Body, expected.Size+1))
		if e != nil {
			return "content_unavailable", 200
		}
		if n != expected.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != expected.Digest {
			return "content_mismatch", 200
		}
	}
	return "", 200
}
func (c *client) observeGraph(ctx context.Context, began bool) (delivery.Observation, error) {
	facts := Facts{PublicationBegan: began, Phase: "readback"}
	fail := func(code string, httpStatus int) (delivery.Observation, error) {
		value := "unavailable"
		if code == "content_mismatch" || code == "tag_drift" {
			value = "mismatch"
		}
		return observation("content", value, code, httpStatus, facts, nil), delivery.Fail(code, "OCI read-back incomplete")
	}
	pub := c.options.Publication
	if code, s := c.verifyDescriptor(ctx, "manifests/"+pub.Manifest.Digest, pub.Manifest, []byte(pub.ManifestJSON)); code != "" {
		return fail(code, s)
	}
	facts.Manifest = "verified"
	if code, s := c.verifyDescriptor(ctx, "blobs/"+pub.Config.Digest, pub.Config, nil); code != "" {
		return fail(code, s)
	}
	facts.Config = "verified"
	if code, s := c.verifyDescriptor(ctx, "blobs/sha256:"+pub.Payload.SHA256, Descriptor{SBOMMediaType, "sha256:" + pub.Payload.SHA256, pub.Payload.Size}, nil); code != "" {
		return fail(code, s)
	}
	facts.Blob = "verified"
	if code, s := c.verifyDescriptor(ctx, "manifests/"+pub.Tag, pub.Manifest, []byte(pub.ManifestJSON)); code != "" {
		if code == "content_mismatch" {
			code = "tag_drift"
			facts.Tag = "drift"
		}
		return fail(code, s)
	}
	facts.Tag = "expected"
	if c.options.Subject != nil {
		if code, s := c.verifyDescriptor(ctx, "manifests/"+c.options.Subject.Digest, *c.options.Subject, nil); code != "" {
			return fail(code, s)
		}
		facts.Subject = "verified"
		found, code, s := c.referrers(ctx, true)
		if code != "" {
			facts.Discovery = "unavailable"
			return fail(code, s)
		}
		if !found {
			facts.Discovery = "not-observed"
			return fail("discovery_not_observed", 200)
		}
		facts.Discovery = "observed"
	}
	return observation("content", "verified", "content_verified", 200, facts, expected(c.options)), nil
}

type referrer struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

func (c *client) referrers(ctx context.Context, find bool) (bool, string, int) {
	next := "/v2/" + c.options.Repository + "/referrers/" + c.options.Subject.Digest
	seenPages := map[string]bool{}
	seenDescriptors := map[string]bool{}
	total := 0
	for page := 0; page < 100; page++ {
		if seenPages[next] {
			return false, "invalid_referrers", 0
		}
		seenPages[next] = true
		resp, e := c.request(ctx, "GET", next, nil, 0, "")
		if e != nil {
			return false, "referrers_unavailable", status(ctx)
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			code := "referrers_unavailable"
			if resp.StatusCode == 404 {
				code = "unsupported_referrers"
			}
			return false, code, resp.StatusCode
		}
		raw, e := readResponse(resp, DocumentLimit)
		resp.Body.Close()
		if e != nil {
			return false, "invalid_referrers", 200
		}
		found, e := parseReferrers(raw, c.options.Publication.Manifest, &total, seenDescriptors)
		if e != nil {
			return false, "invalid_referrers", 200
		}
		if find && found {
			return true, "", 200
		}
		links := resp.Header.Values("Link")
		if len(links) == 0 {
			return false, "", 200
		}
		if len(links) != 1 {
			return false, "invalid_referrers", 200
		}
		link := strings.TrimSpace(links[0])
		end := strings.Index(link, ">")
		if !strings.HasPrefix(link, "<") || end < 1 || strings.TrimSpace(link[end+1:]) != `; rel="next"` {
			return false, "invalid_referrers", 200
		}
		u, e := validLocation(link[1:end], resp.Request.URL, c.options, "referrers")
		if e != nil {
			return false, "unsafe_location", 200
		}
		next = u.String()
	}
	return false, "referrers_limit", 200
}

// Bound descriptor counts before decoding an element, across all pages. Never
// materialize the server's manifests array before applying the traversal budget.
func parseReferrers(raw []byte, want Descriptor, total *int, seen map[string]bool) (bool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, e := dec.Token()
	if e != nil || tok != json.Delim('{') {
		return false, invalid("referrers index")
	}
	fields := map[string]bool{}
	found := false
	for dec.More() {
		tok, e := dec.Token()
		if e != nil {
			return false, invalid("referrers index")
		}
		key, ok := tok.(string)
		if !ok || fields[key] {
			return false, invalid("referrers index")
		}
		fields[key] = true
		switch key {
		case "schemaVersion":
			var v int
			if dec.Decode(&v) != nil || v != 2 {
				return false, invalid("referrers schema")
			}
		case "mediaType":
			var v string
			if dec.Decode(&v) != nil || v != IndexMediaType {
				return false, invalid("referrers media type")
			}
		case "manifests":
			tok, e := dec.Token()
			if e != nil || tok != json.Delim('[') {
				return false, invalid("referrers descriptors")
			}
			for dec.More() {
				if *total >= 10000 {
					return false, delivery.Fail("referrers_limit", "maximum 10000 descriptors")
				}
				*total++
				var rawDescriptor json.RawMessage
				if dec.Decode(&rawDescriptor) != nil {
					return false, invalid("referrer descriptor")
				}
				var d referrer
				if delivery.DecodeJSON(rawDescriptor, &d, true) != nil || !validDescriptor(Descriptor{d.MediaType, d.Digest, d.Size}) || seen[d.Digest] {
					return false, invalid("referrer descriptor")
				}
				seen[d.Digest] = true
				if d.Digest == want.Digest {
					if d.MediaType != want.MediaType || d.Size != want.Size || d.ArtifactType != SBOMMediaType {
						return false, invalid("referrer descriptor mismatch")
					}
					found = true
				}
			}
			if _, e = dec.Token(); e != nil {
				return false, invalid("referrers descriptors")
			}
		case "annotations":
			var m map[string]string
			if dec.Decode(&m) != nil {
				return false, invalid("referrers annotations")
			}
		default:
			return false, invalid("referrers index field")
		}
	}
	if _, e = dec.Token(); e != nil {
		return false, invalid("referrers index")
	}
	if _, e = dec.Token(); e != io.EOF || !fields["schemaVersion"] || !fields["manifests"] {
		return false, invalid("referrers index")
	}
	return found, nil
}
