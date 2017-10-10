// Copyright © 2017 Aeneas Rekkas <aeneas+oss@aeneas.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth2

import (
	"net/url"
	"testing"
	"time"

	"github.com/spotxchange/fosite/storage"
	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/spotxchange/fosite"
	"github.com/spotxchange/fosite/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshFlow_HandleTokenEndpointRequest(t *testing.T) {
	var areq *fosite.AccessRequest
	sess := &fosite.DefaultSession{Subject: "othersub"}

	for k, strategy := range map[string]RefreshTokenStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {

			store := storage.NewMemoryStore()
			h := RefreshTokenGrantHandler{
				TokenRevocationStorage: store,
				RefreshTokenStrategy:   strategy,
				AccessTokenLifespan:    time.Hour,
			}

			for _, c := range []struct {
				description string
				setup       func()
				expectErr   error
				expect      func(t *testing.T)
			}{
				{
					description: "should fail because not responsible",
					expectErr:   fosite.ErrUnknownRequest,
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"123"}
					},
				},
				{
					description: "should fail because token invalid",
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"refresh_token"}}

						areq.Form.Add("refresh_token", "some.refreshtokensig")
					},
					expectErr: fosite.ErrInvalidRequest,
				},
				{
					description: "should fail because token is valid but does not exist",
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"refresh_token"}}

						token, _, err := strategy.GenerateRefreshToken(nil, nil)
						require.NoError(t, err)
						areq.Form.Add("refresh_token", token)
					},
					expectErr: fosite.ErrInvalidRequest,
				},
				{
					description: "should fail because client mismatches",
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
						}

						token, sig, err := strategy.GenerateRefreshToken(nil, nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(nil, sig, &fosite.Request{
							Client:        &fosite.DefaultClient{ID: ""},
							GrantedScopes: []string{"offline"},
						})
						require.NoError(t, err)
					},
					expectErr: fosite.ErrInvalidRequest,
				},
				{
					description: "should pass",
					setup: func() {
						areq.GrantTypes = fosite.Arguments{"refresh_token"}
						areq.Client = &fosite.DefaultClient{
							ID:         "foo",
							GrantTypes: fosite.Arguments{"refresh_token"},
						}

						token, sig, err := strategy.GenerateRefreshToken(nil, nil)
						require.NoError(t, err)

						areq.Form.Add("refresh_token", token)
						err = store.CreateRefreshTokenSession(nil, sig, &fosite.Request{
							Client:        &fosite.DefaultClient{ID: "foo"},
							GrantedScopes: fosite.Arguments{"foo", "offline"},
							Scopes:        fosite.Arguments{"foo", "bar"},
							Session:       sess,
							Form:          url.Values{"foo": []string{"bar"}},
							RequestedAt:   time.Now().UTC().Add(-time.Hour).Round(time.Hour),
						})
						require.NoError(t, err)
					},
					expect: func(t *testing.T) {
						assert.NotEqual(t, sess, areq.Session)
						assert.NotEqual(t, time.Now().UTC().Add(-time.Hour).Round(time.Hour), areq.RequestedAt)
						assert.Equal(t, fosite.Arguments{"foo", "offline"}, areq.GrantedScopes)
						assert.Equal(t, fosite.Arguments{"foo", "bar"}, areq.Scopes)
						assert.NotEqual(t, url.Values{"foo": []string{"bar"}}, areq.Form)
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					areq = fosite.NewAccessRequest(&fosite.DefaultSession{})
					areq.Form = url.Values{}
					c.setup()

					err := h.HandleTokenEndpointRequest(nil, areq)
					if c.expectErr != nil {
						require.EqualError(t, errors.Cause(err), c.expectErr.Error())
					} else {
						require.NoError(t, err)
					}

					if c.expect != nil {
						c.expect(t)
					}
				})
			}
		})
	}
}

func TestRefreshFlow_PopulateTokenEndpointResponse(t *testing.T) {
	var areq *fosite.AccessRequest
	var aresp *fosite.AccessResponse

	for k, strategy := range map[string]CoreStrategy{
		"hmac": &hmacshaStrategy,
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			h := RefreshTokenGrantHandler{
				TokenRevocationStorage: store,
				RefreshTokenStrategy:   strategy,
				AccessTokenStrategy:    strategy,
				AccessTokenLifespan:    time.Hour,
			}
			for _, c := range []struct {
				description string
				setup       func()
				check       func()
				expectErr   error
			}{
				{
				description: "should fail because not responsible",
				expectErr:   fosite.ErrUnknownRequest,
				setup: func() {
					areq.GrantTypes = fosite.Arguments{"313"}
				},
			},
			{
				description: "should fail because access token generation fails",
				setup: func() {
					areq.GrantTypes = fosite.Arguments{"refresh_token"}
					areq.Form.Add("refresh_token", "foo.reftokensig")
					rcts.EXPECT().RefreshTokenSignature("foo.reftokensig").AnyTimes().Return("reftokensig")
					acts.EXPECT().GenerateAccessToken(nil, areq).Return("", "", errors.New(""))
				},
				expectErr: fosite.ErrServerError,
			},
			{
				description: "should fail because access token generation fails",
				setup: func() {
					acts.EXPECT().GenerateAccessToken(nil, areq).AnyTimes().Return("access.atsig", "atsig", nil)
					rcts.EXPECT().GenerateRefreshToken(nil, areq).Return("", "", errors.New(""))
				},
				expectErr: fosite.ErrServerError,
			},
			{
				description: "should fail because persisting fails",
				setup: func() {
					rcts.EXPECT().GenerateRefreshToken(nil, areq).AnyTimes().Return("refresh.resig", "resig", nil)
					store.EXPECT().PersistRefreshTokenGrantSession(nil, "reftokensig", "atsig", "resig", areq).Return(errors.New(""))
				},
				expectErr: fosite.ErrServerError,
			},
			{
				description: "should pass",
				setup: func() {
					areq.Session = &fosite.DefaultSession{}
					store.EXPECT().PersistRefreshTokenGrantSession(nil, "reftokensig", "atsig", "resig", areq).AnyTimes().Return(nil)

					aresp.EXPECT().SetAccessToken("access.atsig")
					aresp.EXPECT().SetTokenType("bearer")
					aresp.EXPECT().SetExpiresIn(gomock.Any())
					aresp.EXPECT().SetScopes(gomock.Any())
					aresp.EXPECT().SetExtra("refresh_token", "refresh.resig")
				},
			},
			{
				description: "should insert the same token signature for permanent",
				setup: func() {
					areq.Session = &fosite.DefaultSession{}

					h.RefreshTokenLifespan = -1

					store.EXPECT().PersistRefreshTokenGrantSession(nil, "reftokensig", "atsig", "reftokensig", areq).AnyTimes().Return(nil)
					aresp.EXPECT().SetAccessToken("access.atsig")
					aresp.EXPECT().SetTokenType("bearer")
					aresp.EXPECT().SetExpiresIn(gomock.Any())
					aresp.EXPECT().SetScopes(gomock.Any())
					aresp.EXPECT().SetExtra("refresh_token", "foo.reftokensig")
				},
			},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					areq = fosite.NewAccessRequest(&fosite.DefaultSession{})
					aresp = fosite.NewAccessResponse()
					areq.Client = &fosite.DefaultClient{}
					areq.Form = url.Values{}

					c.setup()

					err := h.PopulateTokenEndpointResponse(nil, areq, aresp)
					if c.expectErr != nil {
						assert.EqualError(t, errors.Cause(err), c.expectErr.Error())
					} else {
						assert.NoError(t, err)
					}

					if c.check != nil {
						c.check()
					}
				})
			}
		})
	}
}
