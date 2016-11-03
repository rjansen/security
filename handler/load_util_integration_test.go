package handler

import (
	"context"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/db/cassandra"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"os"
	"testing"
	"time"
)

var (
	log logger.Logger
)

func init() {
	os.Args = append(os.Args, "-ecf", "../test/etc/security/benchmark.yaml")
	log = logger.Get()
	log.Info("handler_test.init")
	if err := cassandra.Setup(); err != nil {
		panic(err)
	}
}

func TestDurationParse(t *testing.T) {
	d, err := time.ParseDuration("1m0s")
	assert.Nil(t, err)
	assert.Equal(t, time.Minute, d)
}

func TestGetHandlerSuccess(t *testing.T) {
	testHandler := NewLoadTestHandler()
	var ctx fasthttp.RequestCtx
	var req fasthttp.Request
	req.SetRequestURI("http://test/makefile1")
	req.Header.SetMethod("GET")
	ctx.Init(&req, nil, nil)
	c := context.Background()

	err := testHandler(c, &ctx)

	assert.Nil(t, err)
	assert.NotEmpty(t, ctx.Response.Body())
	assert.Equal(t, ctx.Response.StatusCode(), fasthttp.StatusOK)
}

func TestPostHandlerSuccess(t *testing.T) {
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
