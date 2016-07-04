package main

import (
	//"net/url"
	"bytes"
	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/database"
	"farm.e-pedion.com/repo/security/handler"
	// "farm.e-pedion.com/repo/security/proxy"
	"github.com/valyala/fasthttp"
)

func main() {
	config.Init()
	configuration := config.BindConfiguration()

	logger.Setup(configuration.LoggerConfig)
	defer logger.Close()

	log := logger.GetLogger("main")

	log.Infof("ConfigurationLoaded: %+v", configuration)

	if err := database.Setup(configuration.CassandraConfig); err != nil {
		log.Panicf("DatabaseClientSetupError: Message='%+v'", err)
	}
	if err := cache.Setup(configuration.CacheConfig); err != nil {
		log.Panicf("CacheClientSetupError: Message='%+v'", err)
	}
	// webRemote, err := url.Parse(configuration.WebURL)
	// if err != nil {
	// 	log.Panicf("WebURLCSetupError: Message='%+v'", err)
	// }
	// apiRemote, err := url.Parse(configuration.ApiURL)
	// if err != nil {
	// 	log.Panicf("ApiURLSetupError: Message='%+v'", err)
	// }

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

	assetsFS := &fasthttp.FS{
		// Path to directory to serve.
		Root: "./",

		// Generate index pages if client requests directory contents.
		//GenerateIndexPages: true,

		// Enable transparent compression to save network traffic.
		Compress: true,
	}
	assets := assetsFS.NewRequestHandler()
	handlerConfig := configuration.HandlerConfig

	authHandler := handler.NewAuthHandler()
	logoutHandler := handler.NewLogoutHandler()
	getSessionHandler := handler.NewGetSessionHandler()
	validateSessionHandler := handler.NewValidateSessionHandler()
	//securityProxy := proxy.NewSecurityProxy(apiRemote, webRemote)
	httpHandler := func(ctx *fasthttp.RequestCtx) {
		path := ctx.Path()
		//switch string(ctx.Path()) {
		switch {
		case bytes.HasPrefix(path, []byte("/auth/login")):
			authHandler.HandleRequest(ctx)
		case bytes.HasPrefix(path, []byte("/auth/logout")):
			logoutHandler.HandleRequest(ctx)
		case bytes.HasPrefix(path, []byte("/identity/session")):
			getSessionHandler.HandleRequest(ctx)
		case bytes.HasPrefix(path, []byte("/identity")):
			validateSessionHandler.HandleRequest(ctx)
		case bytes.HasPrefix(path, []byte("/auth/login/asset/")):
			ctx.URI().SetPathBytes(bytes.Replace(path, []byte("/auth/login"), []byte(""), -1))
			assets(ctx)
		//case "/identity/session/":
		//	identityHandler.GetSession(ctx)
		//case "/identity/login/":
		//	identityHandler.LoginManager(ctx)
		// case "/api/":
		// 	securityProxy.HandleApiRequest(ctx)
		// case "/web/":
		// 	securityProxy.HandleWebRequest(ctx)
		default:
			log.Infof("Security.HandlerNotFound[Method=%v Path=%v]", string(ctx.Method()), string(path))
			ctx.Error("404 - NotFound", fasthttp.StatusNotFound)
		}
	}

	log.Infof("%s-ServerStarted: BindAddress[%s]", "0.0.1-100999", handlerConfig.BindAddress)
	err := fasthttp.ListenAndServe(handlerConfig.BindAddress, httpHandler)
	if err != nil {
		log.Panicf("HTTPStartupError: Message='%+v'", err)
	}
}
