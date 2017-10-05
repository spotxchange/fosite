package fosite

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type migrationSession struct {
	DefaultSession `json:"idToken"`
	Extras         map[string]interface{} `json:"extra"`
}

// NewTokenMigrationRequest handles incoming token migration requests and
// validates various parameters
//
// The authorization server first validates the client credentials (in
// case of a confidential client) and then verifies whether the client
// has permission to migrate tokens
//
// Client that originally was associated with the token in the other system is
// then verified, full client migration must be done first. Lastly the old
// token is translated and inserted into the new system
func (f *Fosite) NewTokenMigrationRequest(ctx context.Context, r *http.Request) error {
	var err error

	if r.Method != "POST" {
		return errors.Wrap(ErrInvalidRequest, "HTTP method is not POST")
	} else if err := r.ParseForm(); err != nil {
		return errors.Wrap(ErrInvalidRequest, err.Error())
	}

	token := r.PostForm.Get("token")
	if token == "" {
		return ErrInvalidTokenFormat
	}

	refreshToken := r.PostForm.Get("refresh_token")

	// Decode client_id and client_secret which should be in "application/x-www-form-urlencoded" format.
	var clientID, clientSecret string
	if id, secret, ok := r.BasicAuth(); !ok {
		return errors.Wrap(ErrInvalidRequest, "HTTP authorization header missing or invalid")
	} else if clientID, err = url.QueryUnescape(id); err != nil {
		return errors.Wrap(ErrInvalidRequest, `The client id in the HTTP authorization header could not be decoded from "application/x-www-form-urlencoded"`)
	} else if clientSecret, err = url.QueryUnescape(secret); err != nil {
		return errors.Wrap(ErrInvalidRequest, `The client secret in the HTTP authorization header could not be decoded from "application/x-www-form-urlencoded"`)
	}

	client, err := f.Store.GetClient(ctx, clientID)
	if err != nil {
		return errors.Wrap(ErrInvalidClient, err.Error())
	}

	if !client.IsPublic() {
		// Enforce client authentication
		if err := f.Hasher.Compare(client.GetHashedSecret(), []byte(clientSecret)); err != nil {
			return errors.Wrap(ErrInvalidClient, err.Error())
		}
	} else {
		return errors.Wrap(ErrInvalidClient, "Only internal clients are allowed to migrate")
	}

	if !client.GetScopes().Has("hydra.token.migration") {
		return ErrInvalidClient
	}

	originalClientEncoded := r.PostForm.Get("client")
	if originalClientEncoded == "" {
		return ErrInvalidClient
	}

	var orgClientID, orgClientSecret string
	if orgID, orgSecret, err := f.getOriginalClientCredentials(originalClientEncoded); err != nil {
		return errors.Wrap(ErrInvalidClient, err.Error())
	} else if orgClientID, err = url.QueryUnescape(orgID); err != nil {
		return errors.Wrap(ErrInvalidRequest, `The client id in the body of the request could not be decoded from "application/x-www-form-urlencoded"`)
	} else if orgClientSecret, err = url.QueryUnescape(orgSecret); err != nil {
		return errors.Wrap(ErrInvalidRequest, `The client secret in the body of the request could not be decoded from "application/x-www-form-urlencoded"`)
	}

	originalClient, err := f.Store.GetClient(ctx, orgClientID)
	if err != nil {
		return errors.Wrap(ErrInvalidClient, err.Error())
	}

	if orgClientSecret != "" && !originalClient.IsPublic() {
		// Enforce client authentication
		if err := f.Hasher.Compare(originalClient.GetHashedSecret(), []byte(orgClientSecret)); err != nil {
			return errors.Wrap(ErrInvalidClient, err.Error())
		}
	}
	session := &migrationSession{
		DefaultSession: DefaultSession{
			Subject:   orgClientID,
			Username:  r.PostForm.Get("username"),
			ExpiresAt: make(map[TokenType]time.Time),
		},
		Extras: map[string]interface{}{
			"migrated": true,
		},
	}

	accessRequest := NewAccessRequest(session)
	accessRequest.Client = originalClient
	accessRequest.SetRequestedScopes(originalClient.GetScopes())
	accessRequest.Form = r.PostForm
	accessRequest.GrantedScopes = removeEmpty(strings.Split(r.PostForm.Get("scope"), " "))

	resp := NewAccessResponse()

	if !strings.Contains(token, ".") {
		token = "." + token
	}
	if refreshToken != "" && !strings.Contains(refreshToken, ".") {
		refreshToken = "." + refreshToken
	}

	resp.SetAccessToken(token)
	resp.SetExtra("refresh_token", refreshToken)
	resp.SetExtra("migrated", true)

	var found bool
	for _, migrater := range f.MigrationHandlers {
		if err := migrater.MigrateToken(ctx, accessRequest, resp); err == nil {
			found = true
		} else if errors.Cause(err) == ErrUnknownRequest {
			// do nothing
		} else if err != nil {
			return err
		}
	}

	if !found {
		return errors.WithStack(errors.Wrap(ErrInvalidRequest, "No handlers"))
	}

	return nil
}

func (f *Fosite) WriteTokenMigrationResponse(rw http.ResponseWriter, err error) {
	if err != nil || errors.Cause(err) != nil {
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

		rfcerr := ErrorToRFC6749Error(err)
		js, err := json.Marshal(rfcerr)
		if err != nil {
			http.Error(rw, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		rw.WriteHeader(rfcerr.Code)
		rw.Write(js)
	} else {
		// 200 OK
		rw.WriteHeader(http.StatusOK)
	}
}

func (f *Fosite) getOriginalClientCredentials(encoded string) (string, string, error) {
	c, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", err
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return "", "", ErrInvalidClient
	}
	return cs[:s], cs[s+1:], nil
}
