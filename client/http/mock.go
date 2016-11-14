package http

import (
	testify "github.com/stretchr/testify/mock"
)

func NewRequestMock() *RequestMock {
	return new(RequestMock)
}

type RequestMock struct {
	testify.Mock
}

func (r *RequestMock) Method() Method {
	args := r.Called()
	return args.Get(0).(Method)
}

func (r *RequestMock) URL() string {
	args := r.Called()
	return args.String(0)
}
func (r *RequestMock) Headers() map[string]string {
	args := r.Called()
	return args.Get(0).(map[string]string)
}
func (r *RequestMock) ContentType() ContentType {
	args := r.Called()
	return args.Get(0).(ContentType)
}
func (r *RequestMock) ContentLength() int {
	args := r.Called()
	return args.Int(0)
}
func (r *RequestMock) Body() []byte {
	args := r.Called()
	return args.Get(0).([]byte)
}

func NewResponseMock() *ResponseMock {
	return new(ResponseMock)
}

type ResponseMock struct {
	testify.Mock
}

func (r *ResponseMock) Headers() map[string]string {
	args := r.Called()
	headersMap := args.Get(0)
	if headersMap != nil {
		return headersMap.(map[string]string)
	}
	return nil
}

func (r *ResponseMock) ContentType() ContentType {
	args := r.Called()
	return args.Get(0).(ContentType)
}
func (r *ResponseMock) ContentLength() int {
	args := r.Called()
	return args.Int(0)
}
func (r *ResponseMock) Body() []byte {
	args := r.Called()
	body := args.Get(0)
	if body != nil {
		return body.([]byte)
	}
	return nil
}
func (r *ResponseMock) StatusCode() int {
	args := r.Called()
	return args.Int(0)
}

func NewClientMock() *ClientMock {
	return new(ClientMock)
}

type ClientMock struct {
	testify.Mock
}

func (c *ClientMock) Request(method Method, url string, body []byte, headers map[string]string) (Response, error) {
	args := c.Called(method, url, body, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *ClientMock) HEAD(url string, headers map[string]string) (Response, error) {
	args := c.Called(url, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *ClientMock) GET(url string, headers map[string]string) (Response, error) {
	args := c.Called(url, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *ClientMock) POST(url string, body []byte, headers map[string]string) (Response, error) {
	args := c.Called(url, body, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *ClientMock) PUT(url string, body []byte, headers map[string]string) (Response, error) {
	args := c.Called(url, body, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *ClientMock) DELETE(url string, body []byte, headers map[string]string) (Response, error) {
	args := c.Called(url, body, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *ClientMock) Close() error {
	args := c.Called()
	return args.Error(0)
}
