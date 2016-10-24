package handler

import (
	"context"
	"farm.e-pedion.com/repo/security/client/cassandra"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"os"
	"testing"
	"time"
)

func init() {
	os.Args = append(os.Args, "-ecf", "../test/etc/security/security.yaml")
	if err := cassandra.Setup(); err != nil {
		panic(err)
	}
}

func TestDurationParse(t *testing.T) {
	d, err := time.ParseDuration("1m0s")
	assert.Nil(t, err)
	assert.Equal(t, time.Minute, d)
}

func TestGetTestHandlerSuccess(t *testing.T) {
	testHandler := NewLoadTestHandler()
	var ctx fasthttp.RequestCtx
	var req fasthttp.Request
	req.SetRequestURI("http://test/rjansen")
	req.Header.SetMethod("GET")
	ctx.Init(&req, nil, nil)
	c := context.Background()

	err := testHandler(c, &ctx)

	assert.Nil(t, err)
	assert.NotEmpty(t, ctx.Response.Body())
	assert.Equal(t, ctx.Response.StatusCode(), fasthttp.StatusOK)
}

func TestPostestHandlerSuccess(t *testing.T) {
	testHandler := NewLoadTestHandler()
	var ctx fasthttp.RequestCtx
	var req fasthttp.Request
	req.SetRequestURI("http://test/")
	req.Header.SetMethod("POST")
	req.SetBody([]byte(`{"username": "bench"}`))
	ctx.Init(&req, nil, nil)
	c := context.Background()

	err := testHandler(c, &ctx)

	assert.Nil(t, err)
	assert.NotEmpty(t, ctx.Response.Body())
	assert.Equal(t, ctx.Response.StatusCode(), fasthttp.StatusCreated)
}
