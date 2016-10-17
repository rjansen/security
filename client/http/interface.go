package http

import (
	"farm.e-pedion.com/repo/security/config"
	"time"
)

const (
	GET    Method = "GET"
	POST          = "POST"
	PUT           = "PUT"
	HEAD          = "HEAD"
	DELETE        = "DELETE"

	JSON  ContentType = "application/json"
	PLAIN             = "text/plain"
	HTML              = "text/html"
	EMPTY             = ""

	StatusOK                  int = 200
	StatusCreated                 = 201
	StatusAccepted                = 202
	StatusBadRequest              = 400
	StatusNotFound                = 404
	StatusInternalServerError     = 500
)

var (
	requestTimeout  time.Duration
	maxConnxPerHost int
)

//Setup initializes the package
func Setup(config config.HTTPConfig) error {
	requestTimeout = time.Duration(config.RequestTimeout) * time.Millisecond
	maxConnxPerHost = config.MaxConnsPerHost
	return nil
}

//Method is a http method
type Method string

//Bytes transforms it into a string
func (h Method) String() string {
	return string(h)
}

//Bytes transforms it into a []byte
func (h Method) Bytes() []byte {
	return []byte(h)
}

//ContentType is a http content type header
type ContentType string

//Bytes transforms it into a string
func (h ContentType) String() string {
	return string(h)
}

//Bytes transforms it into a []byte
func (h ContentType) Bytes() []byte {
	return []byte(h)
}

//StatusCode is a http status code
type StatusCode int

//String transforms it into a string
func (h StatusCode) String() string {
	return string(h)
}

//Int transforms it into an int
func (h StatusCode) Int() int {
	return int(h)
}

//Request represents an http request
type Request interface {
	Method() Method
	URL() string
	Headers() map[string]interface{}
	ContentType() ContentType
	ContentLength() int
	Body() []byte
}

//Response represents an http response
type Response interface {
	Headers() map[string]interface{}
	ContentType() ContentType
	ContentLength() int
	Body() []byte
	StatusCode() int
}

//Client provides an interface for http actions
type Client interface {
	Request(method Method, url string, body []byte, headers map[string]interface{}) (Response, error)
	HEAD(url string, headers map[string]interface{}) (Response, error)
	GET(url string, headers map[string]interface{}) (Response, error)
	POST(url string, body []byte, headers map[string]interface{}) (Response, error)
	PUT(url string, body []byte, headers map[string]interface{}) (Response, error)
	DELETE(url string, body []byte, headers map[string]interface{}) (Response, error)
	Close() error
}
