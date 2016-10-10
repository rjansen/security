package handler

import (
	"bytes"
	"farm.e-pedion.com/repo/logger"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"strconv"
	"testing"
)

func BenchmarkGetTestHandler(b *testing.B) {
	log = logger.NewLoggerByConfig(logger.Configuration{Level: logger.ERROR, Out: logger.DISCARD})
	testHandler := NewLoadTestHandler()

	var times int
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var ctx fasthttp.RequestCtx
		var req fasthttp.Request
		for pb.Next() {
			times++
			username := "user" + strconv.Itoa(times)
			req.SetRequestURI("http://test/" + username)
			ctx.Init(&req, nil, nil)

			testHandler.Get.HandleRequest(&ctx)

			assert.NotEmpty(b, ctx.Response.Body())
			assert.True(b, bytes.Contains(ctx.Response.Body(), []byte(username)))
			assert.Equal(b, ctx.Response.StatusCode(), fasthttp.StatusOK)
		}
	})
}

func BenchmarkPostTestHandler(b *testing.B) {
	log = logger.NewLoggerByConfig(logger.Configuration{Level: logger.ERROR, Out: logger.DISCARD})
	testHandler := NewLoadTestHandler()

	var times int
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var ctx fasthttp.RequestCtx
		var req fasthttp.Request
		for pb.Next() {
			times++
			username := "user" + strconv.Itoa(times)
			req.SetRequestURI("http://test/")
			req.SetBody([]byte(`{"username": "` + username + `"}`))
			ctx.Init(&req, nil, nil)

			testHandler.Post.HandleRequest(&ctx)

			assert.NotEmpty(b, ctx.Response.Body())
			assert.True(b, bytes.Contains(ctx.Response.Body(), []byte(username)))
			assert.Equal(b, ctx.Response.StatusCode(), fasthttp.StatusCreated)
		}
	})
}
