package internal

import (
	context "context"

	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory/fosite"
)

// Mock of TokenEndpointHandler interface
type MockTokenMigrationEndpointHandler struct {
	ctrl     *gomock.Controller
	recorder *_MockTokenMigrationEndpointHandlerRecorder
}

// Recorder for MockTokenEndpointHandler (not exported)
type _MockTokenMigrationEndpointHandlerRecorder struct {
	mock *MockTokenMigrationEndpointHandler
}

func NewMockTokenMigrationEndpointHandler(ctrl *gomock.Controller) *MockTokenMigrationEndpointHandler {
	mock := &MockTokenMigrationEndpointHandler{ctrl: ctrl}
	mock.recorder = &_MockTokenMigrationEndpointHandlerRecorder{mock}
	return mock
}

func (_m *MockTokenMigrationEndpointHandler) EXPECT() *_MockTokenMigrationEndpointHandlerRecorder {
	return _m.recorder
}

func (_m *MockTokenMigrationEndpointHandler) MigrateToken(_param0 context.Context, _param1 fosite.AccessRequester, _param2 fosite.AccessResponder) error {
	ret := _m.ctrl.Call(_m, "MigrateToken", _param0, _param1, _param2)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockTokenMigrationEndpointHandlerRecorder) MigrateToken(_param0, _param1, _param2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "MigrateToken", _param0, _param1, _param2)
}
