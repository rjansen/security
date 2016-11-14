package main

import (
	"bytes"
	"context"
	"farm.e-pedion.com/repo/cache/memcached"
	"farm.e-pedion.com/repo/config"
	myFast "farm.e-pedion.com/repo/context/fast"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/persistence/cassandra"
	// "farm.e-pedion.com/repo/persistence"
	"farm.e-pedion.com/repo/security/client/http"
	myCfg "farm.e-pedion.com/repo/security/config"
	"farm.e-pedion.com/repo/security/handler"
	"farm.e-pedion.com/repo/security/model"
	"farm.e-pedion.com/repo/security/proxy"
	"github.com/valyala/fasthttp"
	"net/url"
	//"time"
)

func init() {
	logger.Info("security.init")
	var cfg *myCfg.Configuration
	var err error
	if err = config.Unmarshal(&cfg); err != nil {
		logger.Panic("security.ReadConfigErr", logger.Err(err))
	}
	if err = myCfg.Setup(cfg); err != nil {
		logger.Panic("security.SetupConfigErr", logger.Err(err))
	}
	if err = memcached.Setup(&myCfg.Config.Memcached); err != nil {
		logger.Panic("security.MemcachedSetupErr", logger.Err(err))
	}
	if err = cassandra.Setup(&myCfg.Config.Cassandra); err != nil {
		logger.Panic("security.CassandraSetupErr", logger.Err(err))
	}
	if err = model.Setup(&myCfg.Config.Proxy, &myCfg.Config.Security); err != nil {
		logger.Panic("security.ModelSetupErr", logger.Err(err))
	}
	if err = http.Setup(&myCfg.Config.HTTP); err != nil {
		logger.Panic("secueity.HTTPSetupErr", logger.Err(err))
	}
	logger.Info("security.Setted", logger.String("Config", myCfg.Config.String()))
}

func main() {
	webRemote, err := url.Parse(myCfg.Config.Proxy.WebURL)
	if err != nil {
		logger.Panic("security.WebURLInvalidErr", logger.Err(err))
	}
	apiRemote, err := url.Parse(myCfg.Config.Proxy.ApiURL)
	if err != nil {
		logger.Panic("security.ApiURLInvalidErr", logger.Err(err))
	}

	authHandler := handler.NewAuthHandler()
	logoutHandler := handler.NewLogoutHandler()
	sessionHandler := handler.NewGetSessionHandler()
	validateSessionHandler := handler.NewValidateSessionHandler()
	identityHandler := handler.NewLoginManagerHandler()
	webProxy := proxy.NewWebReverseProxy(webRemote)
	apiProxy := proxy.NewApiReverseProxy(apiRemote)

	// assetsFS := &fasthttp.FS{
	// 	// Path to directory to serve.
	// 	Root: "./",

	// 	// Generate index pages if client requests directory contents.
	// 	//GenerateIndexPages: true,

	// 	// Enable transparent compression to save network traffic.
	// 	Compress: true,
	// }
	// assets := assetsFS.NewRequestHandler()

	mainHandler := myFast.Log(
		myFast.Error(
			func(c context.Context, fc *fasthttp.RequestCtx) error {
				path := fc.Path()
				//switch string(ctx.Path()) {
				switch {
				case bytes.HasPrefix(path, []byte("/auth/login")):
					authHandler.HandleRequest(fc)
				case bytes.HasPrefix(path, []byte("/auth/logout")):
					logoutHandler.HandleRequest(fc)
				case bytes.HasPrefix(path, []byte("/identity/session")):
					sessionHandler.HandleRequest(fc)
				case bytes.HasPrefix(path, []byte("/identity/login/")):
					identityHandler.HandleRequest(fc)
				case bytes.HasPrefix(path, []byte("/identity")):
					validateSessionHandler.HandleRequest(fc)
				// case bytes.HasPrefix(path, []byte("/auth/login/asset/")):
				// 	ctx.URI().SetPathBytes(bytes.Replace(path, []byte("/auth/login"), []byte(""), -1))
				// 	assets(ctx)
				case bytes.HasPrefix(path, []byte("/api/")):
					apiProxy.HandleRequest(fc)
				case bytes.HasPrefix(path, []byte("/web/")):
					webProxy.HandleRequest(fc)
				default:
					fc.Error("404 - NotFound", fasthttp.StatusNotFound)
				}
				return nil
			},
		),
	)
	httpHandler := func(fc *fasthttp.RequestCtx) {
		c, cancel := context.WithCancel(context.Background())
		defer cancel()
		mainHandler(c, fc)
	}

	// loadTestHandler := handler.NewLoadTestHandler()

	// httpHandler := func(fc *fasthttp.RequestCtx) {
	// 	// ctx := context.Background()
	// 	// ctxFast.Log(ctxFast.Error(func(c context.Context, fc *fasthttp.RequestCtx) error {
	// 	// 	fc.Write([]byte("HandlerOK"))
	// 	// 	fc.SetStatusCode(fasthttp.StatusOK)
	// 	// 	return nil
	// 	// }))(nil, fc)
	// 	c := context.Background()
	// 	if err := loadTestHandler(c, fc); err != nil {
	// 		logger.Error("security.main.handlerErr", logger.Err(err))
	// 	}
	// 	// switch {
	// 	// case ctx.IsGet():
	// 	// 	myFast.LogHandler(myFast.ErrorHandler(loadTestHandler.Get.HandleRequest(container, ctx)))
	// 	// case ctx.IsPost(), ctx.IsPut():
	// 	// 	loadTestHandler.Post.HandleRequest(ctx)
	// 	// //case ctx.IsDelete():
	// 	// //	loadTestHandler.Delete.HandleRequest(ctx)
	// 	// default:
	// 	// 	ctx.Error("405 - MethodNotAllowed", fasthttp.StatusMethodNotAllowed)
	// 	// }
	// }

	logger.Info("security.starting",
		logger.String("Version", myCfg.Config.Version),
		logger.String("BindAddress", myCfg.Config.Handler.BindAddress),
	)
	err = fasthttp.ListenAndServe(myCfg.Config.Handler.BindAddress, httpHandler)
	if err != nil {
		logger.Panic("security.Err",
			logger.String("Version", myCfg.Config.Version),
			logger.String("BindAddress", myCfg.Config.Handler.BindAddress),
			logger.Err(err),
		)
	}
}
