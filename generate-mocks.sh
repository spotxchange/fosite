#!/bin/bash

mockgen -package internal -destination internal/hash.go github.com/spotxchange/fosite Hasher
mockgen -package internal -destination internal/storage.go github.com/spotxchange/fosite Storage
mockgen -package internal -destination internal/oauth2_storage.go github.com/spotxchange/fosite/handler/oauth2 CoreStorage
mockgen -package internal -destination internal/oauth2_strategy.go github.com/spotxchange/fosite/handler/oauth2 CoreStrategy
mockgen -package internal -destination internal/authorize_code_storage.go github.com/spotxchange/fosite/handler/oauth2 AuthorizeCodeStorage
mockgen -package internal -destination internal/access_token_storage.go github.com/spotxchange/fosite/handler/oauth2 AccessTokenStorage
mockgen -package internal -destination internal/refresh_token_strategy.go github.com/spotxchange/fosite/handler/oauth2 RefreshTokenStorage
mockgen -package internal -destination internal/oauth2_client_storage.go github.com/spotxchange/fosite/handler/oauth2 ClientCredentialsGrantStorage
mockgen -package internal -destination internal/oauth2_owner_storage.go github.com/spotxchange/fosite/handler/oauth2 ResourceOwnerPasswordCredentialsGrantStorage
mockgen -package internal -destination internal/oauth2_explicit_storage.go github.com/spotxchange/fosite/handler/oauth2 AuthorizeCodeGrantStorage
mockgen -package internal -destination internal/oauth2_owner_storage.go github.com/spotxchange/fosite/handler/oauth2 ResourceOwnerPasswordCredentialsGrantStorage
mockgen -package internal -destination internal/oauth2_refresh_storage.go github.com/spotxchange/fosite/handler/oauth2 RefreshTokenGrantStorage
mockgen -package internal -destination internal/oauth2_revoke_storage.go github.com/spotxchange/fosite/handler/oauth2 TokenRevocationStorage
mockgen -package internal -destination internal/openid_id_token_storage.go github.com/spotxchange/fosite/handler/openid OpenIDConnectRequestStorage
mockgen -package internal -destination internal/access_token_strategy.go github.com/spotxchange/fosite/handler/oauth2 AccessTokenStrategy
mockgen -package internal -destination internal/refresh_token_strategy.go github.com/spotxchange/fosite/handler/oauth2 RefreshTokenStrategy
mockgen -package internal -destination internal/authorize_code_strategy.go github.com/spotxchange/fosite/handler/oauth2 AuthorizeCodeStrategy
mockgen -package internal -destination internal/id_token_strategy.go github.com/spotxchange/fosite/handler/openid OpenIDConnectTokenStrategy
mockgen -package internal -destination internal/authorize_handler.go github.com/spotxchange/fosite AuthorizeEndpointHandler
mockgen -package internal -destination internal/revoke_handler.go github.com/spotxchange/fosite RevocationHandler
mockgen -package internal -destination internal/token_handler.go github.com/spotxchange/fosite TokenEndpointHandler
mockgen -package internal -destination internal/introspector.go github.com/spotxchange/fosite TokenIntrospector
mockgen -package internal -destination internal/client.go github.com/spotxchange/fosite Client
mockgen -package internal -destination internal/request.go github.com/spotxchange/fosite Requester
mockgen -package internal -destination internal/access_request.go github.com/spotxchange/fosite AccessRequester
mockgen -package internal -destination internal/access_response.go github.com/spotxchange/fosite AccessResponder
mockgen -package internal -destination internal/authorize_request.go github.com/spotxchange/fosite AuthorizeRequester
mockgen -package internal -destination internal/authorize_response.go github.com/spotxchange/fosite AuthorizeResponder

goimports -w internal/