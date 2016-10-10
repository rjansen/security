package handler

import (
	"farm.e-pedion.com/repo/logger"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"testing"
)

func TestGetTestHandlerSuccess(t *testing.T) {
	log = logger.NewLoggerByConfig(logger.Configuration{})
	testHandler := NewLoadTestHandler()
	var ctx fasthttp.RequestCtx
	var req fasthttp.Request
	req.SetRequestURI("http://test/unit@email.com")
	ctx.Init(&req, nil, nil)

	testHandler.Get.HandleRequest(&ctx)

	assert.NotEmpty(t, ctx.Response.Body())
	assert.Equal(t, ctx.Response.StatusCode(), fasthttp.StatusOK)
}

func TestPostestHandlerSuccess(t *testing.T) {
	log = logger.NewLoggerByConfig(logger.Configuration{})
	testHandler := NewLoadTestHandler()
	var ctx fasthttp.RequestCtx
	var req fasthttp.Request
	req.SetRequestURI("http://test/")
	req.SetBody([]byte(`{"username": "bench"}`))
	ctx.Init(&req, nil, nil)

	testHandler.Post.HandleRequest(&ctx)

	assert.NotEmpty(t, ctx.Response.Body())
	assert.Equal(t, ctx.Response.StatusCode(), fasthttp.StatusCreated)
}
