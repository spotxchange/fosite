// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/ory/fosite (interfaces: AuthorizeResponder)

package internal

import (
	http "net/http"
	url "net/url"

	gomock "github.com/golang/mock/gomock"
)

// Mock of AuthorizeResponder interface
type MockAuthorizeResponder struct {
	ctrl     *gomock.Controller
	recorder *_MockAuthorizeResponderRecorder
}

// Recorder for MockAuthorizeResponder (not exported)
type _MockAuthorizeResponderRecorder struct {
	mock *MockAuthorizeResponder
}

func NewMockAuthorizeResponder(ctrl *gomock.Controller) *MockAuthorizeResponder {
	mock := &MockAuthorizeResponder{ctrl: ctrl}
	mock.recorder = &_MockAuthorizeResponderRecorder{mock}
	return mock
}

func (_m *MockAuthorizeResponder) EXPECT() *_MockAuthorizeResponderRecorder {
	return _m.recorder
}

func (_m *MockAuthorizeResponder) AddFragment(_param0 string, _param1 string) {
	_m.ctrl.Call(_m, "AddFragment", _param0, _param1)
}

func (_mr *_MockAuthorizeResponderRecorder) AddFragment(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddFragment", arg0, arg1)
}

func (_m *MockAuthorizeResponder) AddHeader(_param0 string, _param1 string) {
	_m.ctrl.Call(_m, "AddHeader", _param0, _param1)
}

func (_mr *_MockAuthorizeResponderRecorder) AddHeader(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddHeader", arg0, arg1)
}

func (_m *MockAuthorizeResponder) AddQuery(_param0 string, _param1 string) {
	_m.ctrl.Call(_m, "AddQuery", _param0, _param1)
}

func (_mr *_MockAuthorizeResponderRecorder) AddQuery(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddQuery", arg0, arg1)
}

func (_m *MockAuthorizeResponder) GetCode() string {
	ret := _m.ctrl.Call(_m, "GetCode")
	ret0, _ := ret[0].(string)
	return ret0
}

func (_mr *_MockAuthorizeResponderRecorder) GetCode() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetCode")
}

func (_m *MockAuthorizeResponder) GetFragment() url.Values {
	ret := _m.ctrl.Call(_m, "GetFragment")
	ret0, _ := ret[0].(url.Values)
	return ret0
}

func (_mr *_MockAuthorizeResponderRecorder) GetFragment() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetFragment")
}

func (_m *MockAuthorizeResponder) GetHeader() http.Header {
	ret := _m.ctrl.Call(_m, "GetHeader")
	ret0, _ := ret[0].(http.Header)
	return ret0
}

func (_mr *_MockAuthorizeResponderRecorder) GetHeader() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetHeader")
}

func (_m *MockAuthorizeResponder) GetQuery() url.Values {
	ret := _m.ctrl.Call(_m, "GetQuery")
	ret0, _ := ret[0].(url.Values)
	return ret0
}

func (_mr *_MockAuthorizeResponderRecorder) GetQuery() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetQuery")
}
