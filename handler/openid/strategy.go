package openid

import (
	"context"

	"github.com/spotxchange/fosite"
)

type OpenIDConnectTokenStrategy interface {
	GenerateIDToken(ctx context.Context, requester fosite.Requester) (token string, err error)
}
