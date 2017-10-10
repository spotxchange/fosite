package fosite_test

import (
	"testing"

	"context"

	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewAccessResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handler := internal.NewMockTokenEndpointHandler(ctrl)
	defer ctrl.Finish()

	f := &Fosite{}
	for k, c := range []struct {
		handlers  TokenEndpointHandlers
		mock      func()
		expectErr error
		expect    AccessResponder
	}{
		{
			mock:      func() {},
			handlers:  TokenEndpointHandlers{},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(ErrServerError)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, resp AccessResponder) {
					resp.SetAccessToken("foo")
				}).Return(nil)
			},
			handlers:  TokenEndpointHandlers{handler},
			expectErr: ErrServerError,
		},
		{
			mock: func() {
				handler.EXPECT().PopulateTokenEndpointResponse(gomock.Any(), gomock.Any(), gomock.Any()).Do(func(_ context.Context, _ AccessRequester, resp AccessResponder) {
					resp.SetAccessToken("foo")
					resp.SetTokenType("bar")
				}).Return(nil)
			},
			handlers: TokenEndpointHandlers{handler},
			expect: &AccessResponse{
				Extra:       map[string]interface{}{},
				AccessToken: "foo",
				TokenType:   "bar",
			},
		},
	} {
		f.TokenEndpointHandlers = c.handlers
		c.mock()
		ar, err := f.NewAccessResponse(nil, nil)
		assert.True(t, errors.Cause(err) == c.expectErr, "%d", k)
		assert.Equal(t, ar, c.expect)
		t.Logf("Passed test case %d", k)
	}
}
