package handler

import (
	"bytes"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/cassandra"
	"farm.e-pedion.com/repo/security/config"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"strconv"
	"testing"
)

func BenchmarkGetTestHandler(b *testing.B) {
	logSetupErr := logger.Setup(logger.Configuration{
		Provider: logger.LOGRUS,
		Level:    logger.DEBUG,
		Out:      logger.Out("./security.bench.log"),
	})
	if logSetupErr != nil {
		panic(logSetupErr)
	}
	log = logger.GetLogger()
	assert.Nil(b, cassandra.Setup(config.CassandraConfig{
		URL:      "127.0.0.1:9042",
		Keyspace: "fivecolors",
		Username: "fivecolors",
		Password: "fivecolors",
	}))
	testHandler := NewLoadTestHandler()

	var times int
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var ctx fasthttp.RequestCtx
		var req fasthttp.Request
		for pb.Next() {
			times++
			// username := "user" + strconv.Itoa(times)
			username := "darkside"
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
