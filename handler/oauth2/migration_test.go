package oauth2

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	token                 = "mytoken"
	tokenSignature        = "mysignedtoken"
	refreshToken          = "refreshtoken"
	refreshTokenSignature = "signedrefreshtoken"
)

func TestTokenMigration(t *testing.T) {
	ctrl := gomock.NewController(t)
	atStore := internal.NewMockAccessTokenStorage(ctrl)
	rtStore := internal.NewMockRefreshTokenGrantStorage(ctrl)
	atStrat := internal.NewMockAccessTokenStrategy(ctrl)
	rtStrat := internal.NewMockRefreshTokenStrategy(ctrl)

	defer ctrl.Finish()

	h := TokenMigrationHandler{
		AccessTokenStorage:   atStore,
		RefreshTokenStorage:  rtStore,
		AccessTokenStrategy:  atStrat,
		RefreshTokenStrategy: rtStrat,
	}

	areq := fosite.NewAccessRequest(new(fosite.DefaultSession))
	var aresp *fosite.AccessResponse

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "should store a token correctly",
			setup: func() {
				aresp = newAccessTokenResponse(token, nil)
				atStrat.EXPECT().AccessTokenSignature(token).Return(tokenSignature)
				atStore.EXPECT().CreateAccessTokenSession(nil, tokenSignature, areq).Return(nil)
			},
			expectErr: nil,
		},
		{
			description: "should store a token with refresh correctly",
			setup: func() {
				aresp = newAccessTokenResponse(token, refreshToken)
				atStrat.EXPECT().AccessTokenSignature(token).Return(tokenSignature)
				atStore.EXPECT().CreateAccessTokenSession(nil, tokenSignature, areq).Return(nil)
				rtStrat.EXPECT().RefreshTokenSignature(refreshToken).Return(refreshTokenSignature)
				rtStore.EXPECT().CreateRefreshTokenSession(nil, refreshTokenSignature, areq).Return(nil)
			},
			expectErr: nil,
		},
		{
			description: "should return an error with an incorrecly typed refresh token",
			setup: func() {
				aresp = newAccessTokenResponse(token, 0)
			},
			expectErr: fosite.ErrInvalidRequest,
		},
		{
			description: "should return an error if the create session errors",
			setup: func() {
				aresp = newAccessTokenResponse(token, refreshToken)
				atStrat.EXPECT().AccessTokenSignature(token).Return(tokenSignature)
				atStore.EXPECT().CreateAccessTokenSession(nil, tokenSignature, areq).Return(fosite.ErrInvalidState)
			},
			expectErr: fosite.ErrInvalidState,
		},
		{
			description: "should return an error if the create refresh session errors",
			setup: func() {
				aresp = newAccessTokenResponse(token, refreshToken)
				atStrat.EXPECT().AccessTokenSignature(token).Return(tokenSignature)
				atStore.EXPECT().CreateAccessTokenSession(nil, tokenSignature, areq).Return(nil)
				rtStrat.EXPECT().RefreshTokenSignature(refreshToken).Return(refreshTokenSignature)
				rtStore.EXPECT().CreateRefreshTokenSession(nil, refreshTokenSignature, areq).Return(fosite.ErrInvalidState)
				atStore.EXPECT().DeleteAccessTokenSession(nil, tokenSignature).Return(nil)
			},
			expectErr: fosite.ErrInvalidState,
		},
		{
			description: "should return an error if the create refresh session errors and wraps compound errors",
			setup: func() {
				aresp = newAccessTokenResponse(token, refreshToken)
				atStrat.EXPECT().AccessTokenSignature(token).Return(tokenSignature)
				atStore.EXPECT().CreateAccessTokenSession(nil, tokenSignature, areq).Return(nil)
				rtStrat.EXPECT().RefreshTokenSignature(refreshToken).Return(refreshTokenSignature)
				rtStore.EXPECT().CreateRefreshTokenSession(nil, refreshTokenSignature, areq).Return(fosite.ErrInvalidState)
				atStore.EXPECT().DeleteAccessTokenSession(nil, tokenSignature).Return(fosite.ErrAccessDenied)
			},
			expectErr: fosite.ErrInvalidState,
		},
	} {
		c.setup()
		err := h.MigrateToken(nil, areq, aresp)

		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\n%s\n%s", k, c.description, err, c.expectErr)
		t.Logf("Passed test case %d", k)
	}
}

func newAccessTokenResponse(token string, refresh interface{}) *fosite.AccessResponse {
	result := &fosite.AccessResponse{
		AccessToken: token,
		Extra:       map[string]interface{}{},
	}

	if refresh != nil {
		result.Extra["refresh_token"] = refresh
	}
	return result
}
