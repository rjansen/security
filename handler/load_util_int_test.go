package handler

import (
	"context"

	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/persistence/cassandra"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"os"
	"testing"
)

var (
	log logger.Logger
)

func init() {
	os.Args = append(os.Args, "-ecf", "../test/etc/security/benchmark.yaml")
	logger.Info("handler_test.init")
	var cfg *cassandra.Configuration
	if err := config.UnmarshalKey("cassandra", &cfg); err != nil {
		panic(err)
	}
	if err := cassandra.Setup(cfg); err != nil {
		panic(err)
	}
}

func TestIntGetHandlerSuccess(t *testing.T) {
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

func TestIntPostHandlerSuccess(t *testing.T) {
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
