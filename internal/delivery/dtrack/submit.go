package dtrack

import (
	"bytes"
	"context"
	"github.com/rebaze/rio/internal/delivery"
	"io"
	"mime/multipart"
	"net/textproto"
	"strconv"
	"strings"
)

func (c *client) Submit(ctx context.Context, payloads []delivery.Payload) (delivery.Submission, error) {
	sub := delivery.Submission{Disposition: "unknown", References: []delivery.Reference{}, Observations: []delivery.Observation{}}
	if len(payloads) != 1 || payloads[0].Ref().Role != "sbom" || payloads[0].Ref().Transformation != "identity" || payloads[0].Ref().MediaType != "application/vnd.cyclonedx+json" || !delivery.ValidDigest(payloads[0].Ref().SHA256) {
		return sub, delivery.Fail("unsupported_payload", "one verified identity SBOM required")
	}
	var envelope bytes.Buffer
	mw := multipart.NewWriter(&envelope)
	p := c.identity.Project
	if p.UUID != "" {
		mw.WriteField("project", p.UUID)
	} else {
		mw.WriteField("projectName", p.Name)
		mw.WriteField("projectVersion", p.Version)
		mw.WriteField("autoCreate", strconv.FormatBool(*c.options.AutoCreate))
	}
	headers := textproto.MIMEHeader{}
	headers.Set("Content-Disposition", `form-data; name="bom"; filename="bom.json"`)
	headers.Set("Content-Type", payloads[0].Ref().MediaType)
	if _, e := mw.CreatePart(headers); e != nil {
		return sub, delivery.Fail("request_invalid", "multipart")
	}
	prefix := append([]byte(nil), envelope.Bytes()...)
	envelope.Reset()
	mw.Close()
	suffix := append([]byte(nil), envelope.Bytes()...)
	snapshot := payloads[0].Open()
	defer snapshot.Close()
	body := io.NopCloser(io.MultiReader(bytes.NewReader(prefix), snapshot, bytes.NewReader(suffix)))
	resp, e := c.request(ctx, "POST", "/api/v1/bom", mw.FormDataContentType(), body)
	if e != nil {
		sub.Observations = append(sub.Observations, observation("unavailable", "unavailable", "local", "transport_unavailable", 0))
		return sub, e
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	o := observation("acknowledgment", "unknown", "receiver", "unexpected_status", status)
	switch status {
	case 200:
		var receipt struct {
			Token string `json:"token"`
		}
		if e = responseJSON(resp, &receipt); e != nil || !ValidUUID(receipt.Token) {
			o.Code = "invalid_receipt"
			sub.Observations = append(sub.Observations, o)
			return sub, delivery.Fail("invalid_receipt", "submission may have been accepted")
		}
		sub.Disposition = "accepted"
		sub.References = []delivery.Reference{{Kind: "dependency-track:event-token", Value: strings.ToLower(receipt.Token)}}
		o.Value = "accepted"
		o.Code = "accepted"
		o.References = append([]delivery.Reference(nil), sub.References...)
	case 400, 401, 403, 404, 413, 415, 422:
		sub.Disposition = "rejected"
		o.Value = "rejected"
		o.Code = "upload_rejected"
	}
	sub.Observations = append(sub.Observations, o)
	if sub.Disposition == "unknown" {
		return sub, delivery.Fail("remote_unknown", "submission outcome unknown")
	}
	return sub, nil
}
