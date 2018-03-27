/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

import (
	"context"
	"net/http"
	"strings"
	"regexp"
	"encoding/json"

	"net/url"

	"github.com/pkg/errors"
)

var regexListSplit = regexp.MustCompile("[, ]+")

// Implements
// * https://tools.ietf.org/html/rfc6749#section-2.3.1
//   Clients in possession of a client password MAY use the HTTP Basic
//   authentication scheme as defined in [RFC2617] to authenticate with
//   the authorization server.  The client identifier is encoded using the
//   "application/x-www-form-urlencoded" encoding algorithm per
//   Appendix B, and the encoded value is used as the username; the client
//   password is encoded using the same algorithm and used as the
//   password.  The authorization server MUST support the HTTP Basic
//   authentication scheme for authenticating clients that were issued a
//   client password.
//   Including the client credentials in the request-body using the two
//   parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
//   to directly utilize the HTTP Basic authentication scheme (or other
//   password-based HTTP authentication schemes).  The parameters can only
//   be transmitted in the request-body and MUST NOT be included in the
//   request URI.
//   * https://tools.ietf.org/html/rfc6749#section-3.2.1
//   - Confidential clients or other clients issued client credentials MUST
//   authenticate with the authorization server as described in
//   Section 2.3 when making requests to the token endpoint.
//   - If the client type is confidential or the client was issued client
//   credentials (or assigned other authentication requirements), the
//   client MUST authenticate with the authorization server as described
//   in Section 3.2.1.
func (f *Fosite) NewAccessRequest(ctx context.Context, r *http.Request, session Session) (AccessRequester, error) {
	var err error
	accessRequest := NewAccessRequest(session)

	if r.Method != "POST" {
		return accessRequest, errors.WithStack(ErrInvalidRequest.WithDebug("HTTP method is not POST"))
	} else if err := r.ParseForm(); err != nil {
		return accessRequest, errors.WithStack(ErrInvalidRequest.WithDebug(err.Error()))
	}

	accessRequest.Form, err = accessRequestFromRequest(r)
	if err != nil {
		return accessRequest, errors.WithStack(ErrInvalidRequest.WithDebug("Request does not contain a valid body or form."))
	}
	if session == nil {
		return accessRequest, errors.New("Session must not be nil")
	}

	accessRequest.SetRequestedScopes(removeEmpty(regexListSplit.Split(accessRequest.Form.Get("scope"), -1)))
	accessRequest.GrantTypes = removeEmpty(regexListSplit.Split(accessRequest.Form.Get("grant_type"), -1))
	if len(accessRequest.GrantTypes) < 1 {
		return accessRequest, errors.WithStack(ErrInvalidRequest.WithDebug("No grant type given"))
	}

	// Decode client_id and client_secret which should be in "application/x-www-form-urlencoded",
	// authorization header, or raw json format.
	clientID, clientSecret, err := clientCredentialsFromRequest(r, accessRequest.Form)
	if err != nil {
		return accessRequest, err
	}

	client, err := f.Store.GetClient(ctx, clientID)
	if err != nil {
		return accessRequest, errors.WithStack(ErrInvalidClient.WithDebug(err.Error()))
	}

	if !client.IsPublic() {
		// Enforce client authentication
		if err := f.Hasher.Compare(client.GetHashedSecret(), []byte(clientSecret)); err != nil {
			return accessRequest, errors.WithStack(ErrInvalidClient.WithDebug(err.Error()))
		}
	}
	accessRequest.Client = client

	var found bool = false
	for _, loader := range f.TokenEndpointHandlers {
		if err := loader.HandleTokenEndpointRequest(ctx, accessRequest); err == nil {
			found = true
		} else if errors.Cause(err).Error() == ErrUnknownRequest.Error() {
			// do nothing
		} else if err != nil {
			return accessRequest, err
		}
	}

	if !found {
		return nil, errors.WithStack(ErrInvalidRequest)
	}
	return accessRequest, nil
}

func accessRequestFromRequest(r *http.Request) (url.Values, error) {
	result := url.Values{}
	var err error
	if len(r.Form) > 0 {
		return r.Form, nil
	} else if len(r.PostForm) > 0 {
		return r.PostForm, nil
	} else if r.Body != nil {
		body := map[string]interface{}{}
		if err = json.NewDecoder(r.Body).Decode(&body); err == nil {
			for k, v := range body {
				if str, ok := v.(string); ok {
					result.Set(k, str)
				} else if arr, ok := v.([]string); ok {
					result.Set(k, strings.Join(arr, " "))
				}
			}
		}
	}

	return result, err
}

func clientCredentialsFromRequest(r *http.Request, v url.Values) (clientID, clientSecret string, err error) {
	if id, secret, ok := r.BasicAuth(); !ok {
		return clientCredentialsFromRequestBody(v)
	} else if clientID, err = url.QueryUnescape(id); err != nil {
		return "", "", errors.WithStack(ErrInvalidRequest.WithDebug(`The client id in the HTTP authorization header could not be decoded from the authorization header`))
	} else if clientSecret, err = url.QueryUnescape(secret); err != nil {
		return "", "", errors.WithStack(ErrInvalidRequest.WithDebug(`The client secret in the HTTP authorization header could not be decoded from the authorization header`))
	}

	return clientID, clientSecret, nil
}

func clientCredentialsFromRequestBody(r url.Values) (clientID, clientSecret string, err error) {
	clientID = r.Get("client_id")
	clientSecret = r.Get("client_secret")

	if clientID == "" {
		return "", "", errors.WithStack(ErrInvalidRequest.WithDebug("Client credentials missing or malformed in both HTTP Authorization header and HTTP POST body"))
	}

	if clientID, err = url.QueryUnescape(clientID); err != nil {
		return "", "", errors.WithStack(ErrInvalidRequest.WithDebug(`The client id in the HTTP authorization header could not be decoded from the HTTP POST body`))
	} else if clientSecret, err = url.QueryUnescape(clientSecret); err != nil {
		return "", "", errors.WithStack(ErrInvalidRequest.WithDebug(`The client secret in the HTTP authorization header could not be decoded from "application/x-www-form-urlencoded"`))
	}

	return clientID, clientSecret, nil
}
