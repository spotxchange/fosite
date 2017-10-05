package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
)

// TokenMigrationHandler handlers migrating tokens from another OAuth 2 system
type TokenMigrationHandler struct {
	AccessTokenStorage AccessTokenStorage

	RefreshTokenStorage RefreshTokenStorage

	AccessTokenStrategy AccessTokenStrategy

	RefreshTokenStrategy RefreshTokenStrategy

	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
}

// MigrateToken handles generating the token signatures and storing the tokens
func (c *TokenMigrationHandler) MigrateToken(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	var refreshToken string
	if token := responder.GetExtra("refresh_token"); token != nil {
		var ok bool
		if refreshToken, ok = token.(string); !ok {
			return errors.Wrap(fosite.ErrInvalidRequest, "The refresh token is in a bad format")
		}
	}

	tokenSignature := c.AccessTokenStrategy.AccessTokenSignature(responder.GetAccessToken())

	if tokenSignature == "" {
		return errors.Wrap(fosite.ErrInvalidRequest, "The access token is in a bad format")
	}

	requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().Add(c.AccessTokenLifespan))
	if err = c.AccessTokenStorage.CreateAccessTokenSession(ctx, tokenSignature, requester); err != nil {
		return err
	}
	if refreshToken != "" {
		refreshTokenSignature := c.RefreshTokenStrategy.RefreshTokenSignature(refreshToken)
		if refreshTokenSignature == "" {
			return errors.Wrap(fosite.ErrInvalidRequest, "The refresh token is in a bad format")
		}
		if c.RefreshTokenLifespan > 0 {
			requester.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().Add(c.AccessTokenLifespan))
		}
		if err = c.RefreshTokenStorage.CreateRefreshTokenSession(ctx, refreshTokenSignature, requester); err != nil {
			if ex := c.AccessTokenStorage.DeleteAccessTokenSession(ctx, tokenSignature); ex != nil {
				err = errors.Wrap(err, ex.Error())
			}
			return err
		}
	}

	return nil
}
