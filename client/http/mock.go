package http

import (
	testify "github.com/stretchr/testify/mock"
)

func NewMockRequest() Request {
	return &mockRequest{}
}

type mockRequest struct {
	testify.Mock
}

func (r *mockRequest) Method() Method {
	args := r.Called()
	return args.Get(0).(Method)
}

func (r *mockRequest) URL() string {
	args := r.Called()
	return args.String(0)
}
func (r *mockRequest) Headers() map[string]string {
	args := r.Called()
	return args.Get(0).(map[string]string)
}
func (r *mockRequest) ContentType() ContentType {
	args := r.Called()
	return args.Get(0).(ContentType)
}
func (r *mockRequest) ContentLength() int {
	args := r.Called()
	return args.Int(0)
}
func (r *mockRequest) Body() []byte {
	args := r.Called()
	return args.Get(0).([]byte)
}

func NewMockResponse() Response {
	return &mockResponse{}
}

type mockResponse struct {
	testify.Mock
}

func (r *mockResponse) Headers() map[string]string {
	args := r.Called()
	headersMap := args.Get(0)
	if headersMap != nil {
		return headersMap.(map[string]string)
	}
	return nil
}

func (r *mockResponse) ContentType() ContentType {
	args := r.Called()
	return args.Get(0).(ContentType)
}
func (r *mockResponse) ContentLength() int {
	args := r.Called()
	return args.Int(0)
}
func (r *mockResponse) Body() []byte {
	args := r.Called()
	body := args.Get(0)
	if body != nil {
		return body.([]byte)
	}
	return nil
}
func (r *mockResponse) StatusCode() int {
	args := r.Called()
	return args.Int(0)
}

func NewMockClient() Client {
	return &mockClient{}
}

type mockClient struct {
	testify.Mock
}

func (c *mockClient) Request(method Method, url string, body []byte, headers map[string]string) (Response, error) {
	args := c.Called(method, url, body, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *mockClient) HEAD(url string, headers map[string]string) (Response, error) {
	args := c.Called(url, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *mockClient) GET(url string, headers map[string]string) (Response, error) {
	args := c.Called(url, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *mockClient) POST(url string, body []byte, headers map[string]string) (Response, error) {
	args := c.Called(url, body, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *mockClient) PUT(url string, body []byte, headers map[string]string) (Response, error) {
	args := c.Called(url, body, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *mockClient) DELETE(url string, body []byte, headers map[string]string) (Response, error) {
	args := c.Called(url, body, headers)
	response := args.Get(0)
	if response != nil {
		return response.(Response), args.Error(1)
	}
	return nil, args.Error(1)
}
func (c *mockClient) Close() error {
	args := c.Called()
	return args.Error(0)
}
