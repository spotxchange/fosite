package fosite_test

import (
	//"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewTokenMigrationRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	client := internal.NewMockClient(ctrl)
	originalClient := internal.NewMockClient(ctrl)
	handler := internal.NewMockTokenMigrationEndpointHandler(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	defer ctrl.Finish()

	fosite := &Fosite{Store: store, Hasher: hasher}

	for k, c := range []struct {
		description string
		header      http.Header
		form        url.Values
		setup       func()
		method      string
		expectErr   error
		handlers    MigrationHandlers
		session     Session
	}{
		// {
		// 	description: "requires a session",
		// 	setup:       func() {},
		// 	expectErr:   errors.New("Session must not be nil"),
		// },
		{
			description: "must be a POST",
			setup:       func() {},
			session:     new(DefaultSession),
			expectErr:   ErrInvalidRequest,
		},
		{
			description: "MUST be a POST",
			setup:       func() {},
			session:     new(DefaultSession),
			expectErr:   ErrInvalidRequest,
			method:      "GET",
		},
		{
			description: "requires a token to migrate",
			setup:       func() {},
			session:     new(DefaultSession),
			expectErr:   ErrInvalidTokenFormat,
			form:        url.Values{},
			method:      "POST",
		},
		{
			description: "requires a valid authorization",
			setup:       func() {},
			session:     new(DefaultSession),
			expectErr:   ErrInvalidRequest,
			form: url.Values{
				"token": {"foo"},
			},
			method: "POST",
		},
		{
			description: "requires the client be in the system",
			session:     new(DefaultSession),
			expectErr:   ErrInvalidClient,
			form: url.Values{
				"token": {"foo"},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(nil, errors.New(""))
			},
		},
		{
			description: "requires the client credentials match",
			session:     new(DefaultSession),
			expectErr:   ErrInvalidClient,
			form: url.Values{
				"token": {"foo"},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(errors.New(""))
			},
		},
		{
			description: "requires the original client be in the request",
			session:     new(DefaultSession),
			expectErr:   ErrInvalidClient,
			form: url.Values{
				"token": {"foo"},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				client.EXPECT().GetScopes().Return(Arguments{})
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)
			},
		},
		{
			description: "requires the original client be valid",
			session:     new(DefaultSession),
			expectErr:   ErrInvalidClient,
			form: url.Values{
				"token":  {"foo"},
				"client": {"notvalidencoding"},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				client.EXPECT().GetScopes().Return(Arguments{})
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)
			},
		},
		{
			description: "requires the original client be in the system",
			session:     new(DefaultSession),
			expectErr:   ErrInvalidClient,
			form: url.Values{
				"token":  {"foo"},
				"client": {basicAuth("tim", "secret")[6:]},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				client.EXPECT().GetScopes().Return(Arguments{})
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)

				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("tim")).Return(nil, errors.New(""))
			},
		},
		{
			description: "requires the original client credentials match",
			session:     new(DefaultSession),
			expectErr:   ErrInvalidClient,
			form: url.Values{
				"token":  {"foo"},
				"client": {basicAuth("tim", "secret")[6:]},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				client.EXPECT().GetScopes().Return(Arguments{})
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)

				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("tim")).Return(originalClient, nil)
				originalClient.EXPECT().IsPublic().Return(false)
				originalClient.EXPECT().GetHashedSecret().Return([]byte("secret"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("secret")), gomock.Eq([]byte("secret"))).Return(errors.New(""))
			},
		},
		{
			description: "requires handlers be present",
			session:     new(DefaultSession),
			expectErr:   ErrInvalidRequest,
			form: url.Values{
				"token":  {"foo"},
				"client": {basicAuth("tim", "secret")[6:]},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				client.EXPECT().GetScopes().Return(Arguments{})
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)

				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("tim")).Return(originalClient, nil)
				originalClient.EXPECT().IsPublic().Return(false)
				originalClient.EXPECT().GetHashedSecret().Return([]byte("secret"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("secret")), gomock.Eq([]byte("secret"))).Return(nil)
			},
			handlers: MigrationHandlers{},
		},
		{
			description: "requires handlers return succes",
			session:     new(DefaultSession),
			expectErr:   ErrInvalidRequest,
			form: url.Values{
				"token":  {"foo"},
				"client": {basicAuth("tim", "secret")[6:]},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				client.EXPECT().GetScopes().Return(Arguments{})
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)

				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("tim")).Return(originalClient, nil)
				originalClient.EXPECT().IsPublic().Return(false)
				originalClient.EXPECT().GetHashedSecret().Return([]byte("secret"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("secret")), gomock.Eq([]byte("secret"))).Return(nil)

				handler.EXPECT().MigrateToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrInvalidRequest)
			},
			handlers: MigrationHandlers{handler},
		},
		{
			description: "works with all the right inputs and success",
			session:     new(DefaultSession),
			expectErr:   nil,
			form: url.Values{
				"token":  {"foo"},
				"client": {basicAuth("tim", "secret")[6:]},
			},
			header: http.Header{
				"Authorization": {basicAuth("foo", "bar")},
			},
			method: "POST",
			setup: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("foo")).Return(client, nil)
				client.EXPECT().IsPublic().Return(false)
				client.EXPECT().GetHashedSecret().Return([]byte("bar"))
				client.EXPECT().GetScopes().Return(Arguments{})
				hasher.EXPECT().Compare(gomock.Eq([]byte("bar")), gomock.Eq([]byte("bar"))).Return(nil)

				store.EXPECT().GetClient(gomock.Any(), gomock.Eq("tim")).Return(originalClient, nil)
				originalClient.EXPECT().IsPublic().Return(false)
				originalClient.EXPECT().GetHashedSecret().Return([]byte("secret"))
				hasher.EXPECT().Compare(gomock.Eq([]byte("secret")), gomock.Eq([]byte("secret"))).Return(nil)

				handler.EXPECT().MigrateToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers: MigrationHandlers{handler},
		},
	} {
		r := &http.Request{
			Header:   c.header,
			PostForm: c.form,
			Form:     c.form,
			Method:   c.method,
		}
		c.setup()
		ctx := NewContext()
		fosite.MigrationHandlers = c.handlers
		err := fosite.NewTokenMigrationRequest(ctx, r, c.session)
		assert.True(t, errors.Cause(err) == c.expectErr, "(%d) %s\nwant: %s \ngot: %s", k, c.description, c.expectErr, err)
		t.Logf("Passed test case %d", k)
	}
}