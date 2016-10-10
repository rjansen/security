package main

import (
	//"bytes"
	//"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/cassandra"
	//"farm.e-pedion.com/repo/security/client/http"
	"farm.e-pedion.com/repo/security/config"
	"farm.e-pedion.com/repo/security/handler"
	//"farm.e-pedion.com/repo/security/proxy"
	"fmt"
	"github.com/valyala/fasthttp"
	//"net/url"
	//"time"
)

func main() {
	var err error
	if err = config.Setup(); err != nil {
		panic(err)
	}
	configuration := config.Get()
	fmt.Printf("Security.Set[%s]\n", configuration.String())

	if err = logger.Setup(configuration.Logger); err != nil {
		panic(err)
	}

	log := logger.GetLogger()
	log.Info("Security.Set", logger.Struct("config", configuration))

	if err = handler.Setup(log); err != nil {
		log.Panic("HandlerSetupErr", logger.Error(err))
	}

	if err = cassandra.Setup(configuration.Cassandra); err != nil {
		log.Panic("CassandraClientSetupErr", logger.Error(err))
	}

	loadTestHandler := handler.NewLoadTestHandler()

	httpHandler := func(ctx *fasthttp.RequestCtx) {
		switch {
		case ctx.IsGet():
			loadTestHandler.Get.HandleRequest(ctx)
		case ctx.IsPost(), ctx.IsPut():
			loadTestHandler.Post.HandleRequest(ctx)
		//case ctx.IsDelete():
		//	loadTestHandler.Delete.HandleRequest(ctx)
		default:
			ctx.Error("405 - MethodNotAllowed", fasthttp.StatusMethodNotAllowed)
		}
	}

	fmt.Printf("SecurityStarting[Version=%s BindAddress=%s]\n", configuration.Version, configuration.Handler.BindAddress)
	err = fasthttp.ListenAndServe(configuration.Handler.BindAddress, httpHandler)
	if err != nil {
		fmt.Printf("SecurityStartErr[Version=%s BindAddress=%s Message='%+v']", configuration.Version, configuration.Handler.BindAddress, err)
		panic(err)
	}

	//for {
	//	time.Sleep(time.Second * 10)
	//	fmt.Printf("WakeUpAfterSleep\n")
	//}
	/*
		if err := logger.Setup(configuration.LoggerConfig); err != nil {
			panic(err)
		}

		log := logger.NewLogger()
		log.Info("LoggerConfigured", logger.Struct("loggerConfig", configuration.LoggerConfig))

		if err := cassandra.Setup(configuration.CassandraConfig); err != nil {
			log.Panic("CassandraClientSetupErr", logger.String("err", err.Error()))
		}

		if err := http.Setup(configuration.HTTPConfig); err != nil {
			log.Panic("HTTPSetupErr", logger.String("err", err.Error()))
		}

		//if err := cache.Setup(configuration.CacheConfig); err != nil {
		//	log.Panic("CacheSetupErr", logger.String("err", err.Error()))
		//}

		webRemote, err := url.Parse(configuration.WebURL)
		if err != nil {
			log.Panic("WebURLSetupErr", logger.String("err", err.Error()))
		}
		apiRemote, err := url.Parse(configuration.ApiURL)
		if err != nil {
			log.Panic("ApiURLSetupErr", logger.String("err", err.Error()))
		}
		/*
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
