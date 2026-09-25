package oci

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/rebaze/rio/internal/delivery"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// registryClient retains native ORAS repository operations and its credential
// cache, while Rio owns the finite authentication exchange. In particular,
// explicit trusted private origins must not be vetoed by SDK realm heuristics.
// Every request, including token requests, still passes safeTransport before I/O.
type registryClient struct{ owner *client }

func (c registryClient) Do(req *http.Request) (*http.Response, error) { return c.owner.do(req) }
func (c *client) authScope(ctx context.Context) (string, error) {
	state, ok := ctx.Value(traversalKey{}).(*traversalState)
	if !ok {
		return "", delivery.Fail("invalid_request", "bounded OCI traversal required")
	}
	state.mu.Lock()
	write := state.write
	state.mu.Unlock()
	actions := "pull"
	if write {
		actions += ",push"
	}
	return "repository:" + c.options.Repository + ":" + actions, nil
}
func (c *client) sendAuthenticated(original *http.Request, authorization string, rewind bool) (*http.Response, error) {
	req := original.Clone(original.Context())
	if rewind && original.Body != nil && original.Body != http.NoBody {
		if original.GetBody == nil {
			return nil, delivery.Fail("invalid_request", "authentication requires repeatable body")
		}
		body, e := original.GetBody()
		if e != nil {
			return nil, delivery.Fail("payload_unavailable", "verified snapshot unavailable")
		}
		req.Body = body
	}
	for key, values := range c.auth.Header {
		req.Header[key] = append(req.Header[key], values...)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	response, e := c.auth.Client.Do(req)
	if e != nil {
		return nil, safeError(e)
	}
	return response, nil
}
func (c *client) do(original *http.Request) (*http.Response, error) {
	key, e := c.authScope(original.Context())
	if e != nil {
		return nil, e
	}
	explicit := original.Header.Get("Authorization") != ""
	authorization := ""
	if !explicit {
		if scheme, e := c.auth.Cache.GetScheme(original.Context(), c.options.Registry); e == nil {
			cacheKey := key
			if scheme == auth.SchemeBasic {
				cacheKey = ""
			}
			if token, e := c.auth.Cache.GetToken(original.Context(), c.options.Registry, scheme, cacheKey); e == nil {
				switch scheme {
				case auth.SchemeBasic:
					authorization = "Basic " + token
				case auth.SchemeBearer:
					authorization = "Bearer " + token
				}
			}
		}
	}
	response, e := c.sendAuthenticated(original, authorization, false)
	// Only an explicit401 permits one fresh-body replay. No retry occurs after
	// transport loss,429,5xx,redirects or an unusable publication receipt.
	if e != nil || response.StatusCode != 401 || explicit {
		return response, e
	}
	scheme, params, e := challenge(response.Header.Get("Www-Authenticate"))
	if e != nil {
		response.Body.Close()
		return nil, delivery.Fail("invalid_auth_challenge", "authentication challenge refused")
	}
	if scheme != "basic" && scheme != "bearer" {
		return response, nil
	}
	response.Body.Close()
	credential, e := c.auth.Credential(original.Context(), c.options.Registry)
	if e != nil {
		return nil, safeError(e)
	}
	var token string
	switch scheme {
	case "basic":
		token, e = c.auth.Cache.Set(original.Context(), c.options.Registry, auth.SchemeBasic, "", func(context.Context) (string, error) {
			if credential.Username == "" || credential.Password == "" {
				return "", delivery.Fail("transport_unavailable", "Basic authentication unavailable")
			}
			return base64.StdEncoding.EncodeToString([]byte(credential.Username + ":" + credential.Password)), nil
		})
		authorization = "Basic " + token
	case "bearer":
		token, e = c.auth.Cache.Set(original.Context(), c.options.Registry, auth.SchemeBearer, key, func(ctx context.Context) (string, error) {
			if credential.AccessToken != "" {
				return credential.AccessToken, nil
			}
			return c.fetchToken(ctx, params, key, credential)
		})
		authorization = "Bearer " + token
	}
	if e != nil {
		return nil, safeError(e)
	}
	return c.sendAuthenticated(original, authorization, true)
}
func (c *client) fetchToken(ctx context.Context, params map[string]string, scope string, credential auth.Credential) (string, error) {
	realm, e := url.Parse(params["realm"])
	if e != nil {
		return "", delivery.Fail("auth_origin_refused", "token service location")
	}
	query := realm.Query()
	query.Set("scope", scope)
	if service := params["service"]; service != "" {
		query.Set("service", service)
	}
	realm.RawQuery = query.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if e != nil {
		return "", delivery.Fail("auth_origin_refused", "token service request")
	}
	if credential.Username != "" || credential.Password != "" {
		req.SetBasicAuth(credential.Username, credential.Password)
	}
	// safeTransport has already registered this exact realm from a trusted401.
	// It rechecks origin, method, scope, deadlines and body bounds on this request.
	response, e := c.auth.Client.Do(req)
	if e != nil {
		return "", safeError(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", delivery.Fail("transport_unavailable", "token service unavailable")
	}
	raw, e := readResponse(response, ErrorLimit)
	if e != nil {
		return "", e
	}
	var result struct {
		Token       string `json:"token,omitempty"`
		AccessToken string `json:"access_token,omitempty"`
	}
	if delivery.DecodeJSON(raw, &result, false) != nil {
		return "", delivery.Fail("invalid_auth_response", "token response refused")
	}
	if result.AccessToken != "" {
		return result.AccessToken, nil
	}
	if result.Token != "" {
		return result.Token, nil
	}
	return "", delivery.Fail("invalid_auth_response", "token response missing token")
}
