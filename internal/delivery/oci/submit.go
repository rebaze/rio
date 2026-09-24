package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rebaze/rio/internal/delivery"
)

type receiptFacts struct {
	Status                    int
	Digest, Location, Subject bool
}

func validLocation(raw string, base *url.URL, o Options, kind string) (*url.URL, error) {
	if raw == "" {
		return nil, delivery.Fail("unsafe_location", "missing OCI location")
	}
	relative, e := url.Parse(raw)
	if e != nil || relative.Fragment != "" || strings.Contains(raw, "#") {
		return nil, delivery.Fail("unsafe_location", "OCI location")
	}
	u := base.ResolveReference(relative)
	if !safeURL(u) || originURL(u) != origin(o) {
		return nil, delivery.Fail("unsafe_location", "OCI location origin")
	}
	prefix := "/v2/" + o.Repository + "/"
	switch kind {
	case "upload":
		if !strings.HasPrefix(u.Path, prefix+"blobs/uploads/") || u.Path == prefix+"blobs/uploads/" || u.Query().Has("digest") {
			return nil, delivery.Fail("unsafe_location", "upload session location")
		}
	case "manifest":
		if u.RawQuery != "" || u.ForceQuery || u.Path != prefix+"manifests/"+o.Publication.Manifest.Digest && u.Path != prefix+"manifests/"+o.Publication.Tag {
			return nil, delivery.Fail("unsafe_location", "manifest receipt location")
		}
	case "blob":
		if !strings.HasPrefix(u.Path, prefix+"blobs/sha256:") || !delivery.ValidDigest(strings.TrimPrefix(u.Path, prefix+"blobs/sha256:")) || u.RawQuery != "" {
			return nil, delivery.Fail("unsafe_location", "blob receipt location")
		}
	case "referrers":
		if o.Subject == nil || u.Path != prefix+"referrers/"+o.Subject.Digest {
			return nil, delivery.Fail("unsafe_location", "referrers paging location")
		}
	default:
		return nil, delivery.Fail("unsafe_location", "OCI location kind")
	}
	return u, nil
}
func ociDescriptor(d Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{MediaType: d.MediaType, Digest: digest.Digest(d.Digest), Size: d.Size}
}
func (c *client) Submit(parent context.Context, payloads []delivery.Payload) (delivery.Submission, error) {
	if len(payloads) != 1 || payloads[0].Ref() != c.options.Publication.Payload {
		return delivery.Submission{Disposition: "unknown", References: []delivery.Reference{}, Observations: []delivery.Observation{}}, invalid("prepared snapshot mismatch")
	}
	ctx, cancel := c.traversal(parent, true)
	defer cancel()
	began := false
	resp, e := c.request(ctx, "GET", "/v2/", nil, 0, "")
	if e != nil || resp.StatusCode != 200 {
		return c.failed(ctx, "auth", began, resp, e)
	}
	resp.Body.Close()
	if c.options.Subject != nil {
		if code, httpStatus := c.verifyDescriptor(ctx, "manifests/"+c.options.Subject.Digest, *c.options.Subject, nil); code != "" {
			return c.contentFailure("subject", began, code, httpStatus)
		}
		if _, code, httpStatus := c.referrers(ctx, false); code != "" {
			return c.contentFailure("referrers", began, code, httpStatus)
		}
	}
	pub := c.options.Publication
	resp, e = c.request(ctx, "GET", "/v2/"+c.options.Repository+"/manifests/"+pub.Tag, nil, 0, "")
	if e != nil {
		return c.failed(ctx, "tag", began, resp, e)
	}
	if resp.StatusCode == 200 {
		raw, readErr := readResponse(resp, DocumentLimit)
		resp.Body.Close()
		if readErr != nil {
			return c.failed(ctx, "tag", began, nil, readErr)
		}
		if string(raw) != pub.ManifestJSON {
			return c.contentFailure("tag", false, "target_conflict", 200)
		}
		ob, err := c.observeGraph(ctx, false)
		if err != nil {
			return delivery.Submission{Disposition: "unknown", References: []delivery.Reference{}, Observations: []delivery.Observation{ob}}, err
		}
		ack := ob
		ack.Kind = "acknowledgment"
		ack.Value = "accepted"
		ack.Code = "already_present"
		ack.HTTPStatus = 200
		return delivery.Submission{Disposition: "accepted", References: expected(c.options), Observations: []delivery.Observation{ack, ob}}, nil
	}
	if resp.StatusCode != 404 {
		return c.failed(ctx, "tag", began, resp, nil)
	}
	resp.Body.Close()
	for _, blob := range []struct {
		phase      string
		descriptor Descriptor
		open       func() (io.ReadCloser, error)
	}{
		{"config-upload", pub.Config, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(emptyConfig)), nil }},
		{"sbom-upload", Descriptor{SBOMMediaType, "sha256:" + pub.Payload.SHA256, pub.Payload.Size}, func() (io.ReadCloser, error) { return payloads[0].Open(), nil }},
	} {
		resp, e = c.request(ctx, "HEAD", "/v2/"+c.options.Repository+"/blobs/"+blob.descriptor.Digest, nil, 0, "")
		if e != nil {
			return c.failed(ctx, blob.phase, began, resp, e)
		}
		if resp.StatusCode == 200 {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != 404 {
			return c.failed(ctx, blob.phase, began, resp, nil)
		}
		resp.Body.Close()
		began = true
		resp, e = c.request(ctx, "POST", "/v2/"+c.options.Repository+"/blobs/uploads/", nil, 0, "")
		if e != nil || resp.StatusCode != 202 {
			return c.failed(ctx, blob.phase, began, resp, e)
		}
		location, locationErr := validLocation(resp.Header.Get("Location"), resp.Request.URL, c.options, "upload")
		resp.Body.Close()
		if locationErr != nil {
			return c.failed(ctx, blob.phase, began, nil, locationErr)
		}
		if location.RawQuery != "" {
			location.RawQuery += "&"
		}
		location.RawQuery += "digest=" + url.QueryEscape(blob.descriptor.Digest)
		resp, e = c.request(ctx, "PUT", location.String(), blob.open, blob.descriptor.Size, "application/octet-stream")
		if e != nil || resp.StatusCode != 201 {
			return c.failed(ctx, blob.phase, began, resp, e)
		}
		_, locationErr = validLocation(resp.Header.Get("Location"), resp.Request.URL, c.options, "blob")
		digestOK := resp.Header.Get("Docker-Content-Digest") == blob.descriptor.Digest
		resp.Body.Close()
		if locationErr != nil || !digestOK {
			return c.failed(ctx, blob.phase, began, nil, delivery.Fail("unusable_blob_receipt", "blob completion receipt"))
		}
	}
	began = true
	e = c.repo.Manifests().PushReference(ctx, ociDescriptor(pub.Manifest), bytes.NewReader([]byte(pub.ManifestJSON)), pub.Tag)
	state := ctx.Value(traversalKey{}).(*traversalState)
	state.mu.Lock()
	receipt := state.manifestReceipt
	state.mu.Unlock()
	if receipt != nil && receipt.Status == 201 {
		facts := Facts{PublicationBegan: true, Phase: "manifest-upload"}
		ack := observation("acknowledgment", "accepted", "manifest_accepted", 201, facts, nil)
		if e != nil || !receipt.Digest || !receipt.Location || !receipt.Subject {
			code := "unusable_receipt"
			if !receipt.Subject {
				code = "unsupported_attachment"
			}
			ack.Code = code
			return delivery.Submission{Disposition: "unknown", References: []delivery.Reference{}, Observations: []delivery.Observation{ack}}, delivery.Fail(code, "manifest HTTP acceptance observed; usable receipt unavailable")
		}
		ack.References = expected(c.options)
		return delivery.Submission{Disposition: "accepted", References: expected(c.options), Observations: []delivery.Observation{ack}}, nil
	}
	// SDK errors may wrap raw registry text. Classify only facts captured at the
	// transport boundary; never return the SDK error string or reconstruct a receipt.
	return c.failed(ctx, "manifest-upload", began, nil, e)
}
func (c *client) failed(ctx context.Context, phase string, began bool, resp *http.Response, e error) (delivery.Submission, error) {
	code := "remote_unknown"
	httpStatus := status(ctx)
	rejected := false
	if state, ok := ctx.Value(traversalKey{}).(*traversalState); ok {
		state.mu.Lock()
		rejected = state.rejected
		state.mu.Unlock()
	}
	if resp != nil {
		httpStatus = resp.StatusCode
		rejected = supportedRejection(resp)
		resp.Body.Close()
	}
	if e != nil {
		if safe, ok := safeError(e).(*delivery.Error); ok {
			code = safe.Code
		}
	}
	value := "unknown"
	origin := "local"
	if httpStatus > 0 {
		origin = "receiver"
	}
	if rejected {
		value = "rejected"
		code = "upload_rejected"
	}
	o := observation("acknowledgment", value, code, httpStatus, Facts{PublicationBegan: began, Phase: phase}, nil)
	o.Origin = origin
	return delivery.Submission{Disposition: value, References: []delivery.Reference{}, Observations: []delivery.Observation{o}}, delivery.Fail(code, "OCI publication incomplete")
}
func (c *client) contentFailure(phase string, began bool, code string, httpStatus int) (delivery.Submission, error) {
	value := "unavailable"
	if slices.Contains([]string{"content_mismatch", "target_conflict", "tag_drift"}, code) {
		value = "mismatch"
	}
	o := observation("content", value, code, httpStatus, Facts{PublicationBegan: began, Phase: phase}, nil)
	return delivery.Submission{Disposition: "unknown", References: []delivery.Reference{}, Observations: []delivery.Observation{o}}, delivery.Fail(code, "OCI content or discovery not verified")
}
func supportedRejection(resp *http.Response) bool {
	if !slices.Contains([]int{400, 401, 403, 404, 405, 409, 413, 415, 422}, resp.StatusCode) || !jsonMedia(resp.Header.Get("Content-Type")) {
		return false
	}
	raw, e := readResponse(resp, ErrorLimit)
	if e != nil {
		return false
	}
	var env struct {
		Errors []struct {
			Code    string          `json:"code"`
			Message string          `json:"message,omitempty"`
			Detail  json.RawMessage `json:"detail,omitempty"`
		} `json:"errors"`
	}
	if delivery.DecodeJSON(raw, &env, false) != nil || len(env.Errors) == 0 {
		return false
	}
	for _, v := range env.Errors {
		if !slices.Contains([]string{"BLOB_UNKNOWN", "BLOB_UPLOAD_INVALID", "BLOB_UPLOAD_UNKNOWN", "DIGEST_INVALID", "MANIFEST_BLOB_UNKNOWN", "MANIFEST_INVALID", "MANIFEST_UNKNOWN", "NAME_INVALID", "NAME_UNKNOWN", "SIZE_INVALID", "TAG_INVALID", "UNAUTHORIZED", "DENIED", "UNSUPPORTED"}, v.Code) {
			return false
		}
	}
	return true
}
