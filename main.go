package main

import (
	//"bytes"
	//"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/config"
	"github.com/spf13/viper"
	//"farm.e-pedion.com/repo/security/client/cassandra"
	//"farm.e-pedion.com/repo/security/client/http"
	//"farm.e-pedion.com/repo/security/handler"
	//"farm.e-pedion.com/repo/security/proxy"
	"fmt"
	//"github.com/valyala/fasthttp"
	//"net/url"
)

func main() {
	if err := config.Setup(); err != nil {
		panic(err)
	}
	configuration := config.Get()
	fmt.Printf("ConfigLoaded[Configuration=%v Viper.Cassandra.Url=%v]\n", configuration, viper.GetString("cassandra.url"))
	//TODO: Change config acquire method name
	//cfg := config.BindConfiguration()

	loggerConfig := config.GetLoggerConfiguration()
	if err := logger.Setup(loggerConfig); err != nil {
		panic(err)
	}

	log := logger.NewLogger()
	log.Info("LoggerConfigured", logger.Struct("loggerConfig", loggerConfig))

	/*
		if err := cassandra.Setup(cfg.CassandraConfig); err != nil {
			log.Panicf("CassandraClientSetupErr[Message='%+v']", err)
		}

		if err := http.Setup(cfg.HTTPConfig); err != nil {
			log.Panicf("HTTPSetupErr[Message='%+v']", err)
		}

		if err := cache.Setup(cfg.CacheConfig); err != nil {
			log.Panicf("CacheSetupErr[Message='%+v']", err)
		}

		webRemote, err := url.Parse(cfg.WebURL)
		if err != nil {
			log.Panicf("WebURLCSetupErr[Message='%+v']", err)
		}
		apiRemote, err := url.Parse(cfg.ApiURL)
		if err != nil {
			log.Panicf("ApiURLSetupErr[Message='%+v']", err)
		}

		// http.Handle("/auth/login/", handler.NewLoginHandler())
		// http.Handle("/auth/login/asset/", http.StripPrefix("/auth/login/asset/", http.FileServer(http.Dir("asset/"))))
		// http.Handle("/auth/logout/", handler.NewLogoutHandler())
		// http.Handle("/identity/session/", handler.NewGetSessionHandler())
		// http.Handle("/identity/login/", handler.NewLoginManagerHandler())
		// http.Handle("/web/", proxy.NewWebReverseProxy(webRemote))
		// http.Handle("/api/", proxy.NewApiReverseProxy(apiRemote))
		// log.Infof("%s-ServerStarted: BindAddress[%s]", "0.0.1-100999", handlerConfig.BindAddress)
		// err = http.ListenAndServe(handlerConfig.BindAddress, nil)
		// if err != nil {
		// 	log.Panicf("HTTPStartupError: Message='%+v'", err)
		// }

		// assetsFS := &fasthttp.FS{
		// 	// Path to directory to serve.
		// 	Root: "./",

		// 	// Generate index pages if client requests directory contents.
		// 	//GenerateIndexPages: true,

		// 	// Enable transparent compression to save network traffic.
		// 	Compress: true,
		// }
		// assets := assetsFS.NewRequestHandler()

		authHandler := handler.NewAuthHandler()
		logoutHandler := handler.NewLogoutHandler()
		sessionHandler := handler.NewGetSessionHandler()
		validateSessionHandler := handler.NewValidateSessionHandler()
		identityHandler := handler.NewLoginManagerHandler()
		webProxy := proxy.NewWebReverseProxy(webRemote)
		apiProxy := proxy.NewApiReverseProxy(apiRemote)

		httpHandler := func(ctx *fasthttp.RequestCtx) {
			path := ctx.Path()
			//switch string(ctx.Path()) {
			switch {
			case bytes.HasPrefix(path, []byte("/auth/login")):
				authHandler.HandleRequest(ctx)
			case bytes.HasPrefix(path, []byte("/auth/logout")):
				logoutHandler.HandleRequest(ctx)
			case bytes.HasPrefix(path, []byte("/identity/session")):
				sessionHandler.HandleRequest(ctx)
			case bytes.HasPrefix(path, []byte("/identity/login/")):
				identityHandler.HandleRequest(ctx)
			case bytes.HasPrefix(path, []byte("/identity")):
				validateSessionHandler.HandleRequest(ctx)
			// case bytes.HasPrefix(path, []byte("/auth/login/asset/")):
			// 	ctx.URI().SetPathBytes(bytes.Replace(path, []byte("/auth/login"), []byte(""), -1))
			// 	assets(ctx)
			case bytes.HasPrefix(path, []byte("/api/")):
				apiProxy.HandleRequest(ctx)
			case bytes.HasPrefix(path, []byte("/web/")):
				webProxy.HandleRequest(ctx)
			default:
				log.Infof("security.HandlerNotFound[Method=%v Path=%v]", string(ctx.Method()), string(path))
				ctx.Error("404 - NotFound", fasthttp.StatusNotFound)
			}
		}

		log.Infof("%s-ServerStarted[BindAddress=%s]", "0.0.1-100999", cfg.HandlerConfig.BindAddress)
		err = fasthttp.ListenAndServe(cfg.HandlerConfig.BindAddress, httpHandler)
		if err != nil {
			log.Panicf("HTTPStartErr[Message='%+v']", err)
		}
	*/
}
