package oauth2

import (
	"time"

	"context"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

type RefreshTokenGrantHandler struct {
	AccessTokenStrategy AccessTokenStrategy

	RefreshTokenStrategy RefreshTokenStrategy

	// RefreshTokenGrantStorage is used to persist session data across requests.
	RefreshTokenGrantStorage RefreshTokenGrantStorage

	// AccessTokenLifespan defines the lifetime of an access token.
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan sets how long an id token is going to be valid. Defaults to one hour.
	RefreshTokenLifespan time.Duration
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token".
	if !request.GetGrantTypes().Exact("refresh_token") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errors.Wrap(fosite.ErrInvalidGrant, "The client is not allowed to use grant type refresh_token")
	}

	refresh := request.GetRequestForm().Get("refresh_token")
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(refresh)
	originalRequest, err := c.RefreshTokenGrantStorage.GetRefreshTokenSession(ctx, signature, request.GetSession())
	if errors.Cause(err) == fosite.ErrNotFound {
		return errors.Wrap(fosite.ErrInvalidRequest, err.Error())
	} else if err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	} else if c.RefreshTokenLifespan > 0 && originalRequest.GetRequestedAt().Add(c.RefreshTokenLifespan).Before(time.Now()) {
		return errors.WithStack(fosite.ErrTokenExpired)
	}

	if !originalRequest.GetGrantedScopes().Has("offline") {
		return errors.Wrap(fosite.ErrScopeNotGranted, "The client is not allowed to use grant type refresh_token")

	}

	// The authorization server MUST ... validate the refresh token.
	if err := c.RefreshTokenStrategy.ValidateRefreshToken(ctx, request, refresh); err != nil {
		return errors.Wrap(fosite.ErrInvalidRequest, err.Error())
	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if originalRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errors.Wrap(fosite.ErrInvalidRequest, "Client ID mismatch")
	}

	request.SetSession(originalRequest.GetSession().Clone())
	request.SetRequestedScopes(originalRequest.GetRequestedScopes())
	for _, scope := range originalRequest.GetGrantedScopes() {
		request.GrantScope(scope)
	}

	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().Add(c.AccessTokenLifespan))
	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !requester.GetGrantTypes().Exact("refresh_token") {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	accessToken, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	refreshToken, refreshSignature, err := c.getRefreshTokenAndSignature(ctx, requester)
	if err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	signature := c.RefreshTokenStrategy.RefreshTokenSignature(requester.GetRequestForm().Get("refresh_token"))
	if err := c.RefreshTokenGrantStorage.PersistRefreshTokenGrantSession(ctx, signature, accessSignature, refreshSignature, requester); err != nil {
		return errors.Wrap(fosite.ErrServerError, err.Error())
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, c.AccessTokenLifespan, time.Now()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("refresh_token", refreshToken)
	return nil
}

func (c *RefreshTokenGrantHandler) getRefreshTokenAndSignature(ctx context.Context, requester fosite.AccessRequester) (refreshToken string, refreshSignature string, err error) {
	if c.RefreshTokenLifespan < 0 {
		refreshToken = requester.GetRequestForm().Get("refresh_token")
		refreshSignature = c.RefreshTokenStrategy.RefreshTokenSignature(refreshToken)
	} else {
		refreshToken, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
	}
	return
}
