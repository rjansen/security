package fast

import (
	"farm.e-pedion.com/repo/security/client/http"
	"github.com/valyala/bytebufferpool"
	"github.com/valyala/fasthttp"
)

type FastHTTPRequest struct {
	method        http.Method
	url           string
	headers       map[string]string
	contentType   http.ContentType
	contentLength int
	body          []byte
}

func (r *FastHTTPRequest) Method() http.Method {
	return r.method
}

func (r *FastHTTPRequest) URL() string {
	return r.url
}

func (r *FastHTTPRequest) Headers() map[string]string {
	return r.headers
}

func (r *FastHTTPRequest) ContentType() http.ContentType {
	return r.contentType
}

func (r *FastHTTPRequest) ContentLength() int {
	return r.contentLength
}

func (r *FastHTTPRequest) Body() []byte {
	return r.body
}

type FastHTTPResponse struct {
	statusCode    int
	headers       map[string]string
	contentType   http.ContentType
	contentLength int
	body          []byte
}

func (r *FastHTTPResponse) StatusCode() int {
	return r.statusCode
}

func (r *FastHTTPResponse) Headers() map[string]string {
	return r.headers
}

func (r *FastHTTPResponse) ContentType() http.ContentType {
	return r.contentType
}

func (r *FastHTTPResponse) ContentLength() int {
	return r.contentLength
}

func (r *FastHTTPResponse) Body() []byte {
	return r.body
}

func NewFastHTTPClient() http.Client {
	return &FastHTTPClient{
		client: &fasthttp.Client{
			MaxConnsPerHost: http.Config.MaxConnsPerHost,
		},
	}
}

type FastHTTPClient struct {
	client *fasthttp.Client
}

func (c *FastHTTPClient) do(request http.Request) (http.Response, error) {
	req, res := c.acquire()
	defer c.release(req, res)
	req.Header.SetMethodBytes(request.Method().Bytes())
	req.SetRequestURI(request.URL())
	bodyLen := len(request.Body())
	if request.Method() != http.GET && request.Method() != http.HEAD && bodyLen > 0 {
		req.SetBody(request.Body())
	}
	for k, v := range request.Headers() {
		req.Header.Set(k, v)
	}
	if err := c.client.DoTimeout(req, res, http.Config.RequestTimeout); err != nil {
		return nil, err
	}
	responseHeaders := make(map[string]string)
	res.Header.VisitAll(func(key []byte, value []byte) {
		responseHeaders[string(key)] = string(value)
	})
	var bodyBytes []byte
	if res.Header.ContentLength() > 0 {
		bodyBuffer := bytebufferpool.Get()
		defer bytebufferpool.Put(bodyBuffer)
		err := res.BodyWriteTo(bodyBuffer)
		if err != nil {
			return nil, err
		}
		bodyBytes = bodyBuffer.B
	}
	httpResponse := &FastHTTPResponse{
		statusCode:    res.StatusCode(),
		headers:       responseHeaders,
		contentLength: res.Header.ContentLength(),
		contentType:   http.ContentType(res.Header.ContentType()),
		body:          bodyBytes,
	}
	return httpResponse, nil
}

func (c *FastHTTPClient) acquire() (*fasthttp.Request, *fasthttp.Response) {
	return fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
}

func (c *FastHTTPClient) release(req *fasthttp.Request, res *fasthttp.Response) {
	fasthttp.ReleaseRequest(req)
	fasthttp.ReleaseResponse(res)
}

func (c FastHTTPClient) Request(method http.Method, url string, body []byte, headers map[string]string) (http.Response, error) {
	httpRequest := &FastHTTPRequest{
		method:  method,
		url:     url,
		body:    body,
		headers: headers,
	}
	return c.do(httpRequest)
}

func (c *FastHTTPClient) HEAD(url string, headers map[string]string) (http.Response, error) {
	httpRequest := &FastHTTPRequest{
		method:        http.HEAD,
		url:           url,
		headers:       headers,
		contentLength: 0,
	}
	return c.do(httpRequest)
}

func (c FastHTTPClient) GET(url string, headers map[string]string) (http.Response, error) {
	httpRequest := &FastHTTPRequest{
		method:        http.GET,
		url:           url,
		headers:       headers,
		contentLength: 0,
	}
	return c.do(httpRequest)
}

func (c FastHTTPClient) POST(url string, body []byte, headers map[string]string) (http.Response, error) {
	httpRequest := &FastHTTPRequest{
		method:  http.POST,
		url:     url,
		body:    body,
		headers: headers,
	}
	return c.do(httpRequest)
}

func (c FastHTTPClient) PUT(url string, body []byte, headers map[string]string) (http.Response, error) {
	httpRequest := &FastHTTPRequest{
		method:  http.PUT,
		url:     url,
		body:    body,
		headers: headers,
	}
	return c.do(httpRequest)
}

func (c FastHTTPClient) DELETE(url string, body []byte, headers map[string]string) (http.Response, error) {
	httpRequest := &FastHTTPRequest{
		method:  http.DELETE,
		url:     url,
		body:    body,
		headers: headers,
	}
	return c.do(httpRequest)
}

func (c *FastHTTPClient) Close() error {
	return nil
}
