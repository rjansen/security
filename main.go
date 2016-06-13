package main

import (
	"net/http"
	"net/url"

	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/database"
	"farm.e-pedion.com/repo/security/handler"
	"farm.e-pedion.com/repo/security/proxy"
	_ "github.com/go-sql-driver/mysql"
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
	webRemote, err := url.Parse(configuration.WebURL)
	if err != nil {
		log.Panicf("WebURLCSetupError: Message='%+v'", err)
	}
	apiRemote, err := url.Parse(configuration.ApiURL)
	if err != nil {
		log.Panicf("ApiURLSetupError: Message='%+v'", err)
	}

	handlerConfig := configuration.HandlerConfig

	http.Handle("/auth/login/", handler.NewLoginHandler())
	http.Handle("/auth/login/asset/", http.StripPrefix("/auth/login/asset/", http.FileServer(http.Dir("asset/"))))
	http.Handle("/auth/logout/", handler.NewLogoutHandler())
	http.Handle("/identity/session/", handler.NewGetSessionHandler())
	http.Handle("/identity/login/", handler.NewLoginManagerHandler())
	http.Handle("/web/", proxy.NewWebReverseProxy(webRemote))
	http.Handle("/api/", proxy.NewApiReverseProxy(apiRemote))
	log.Infof("%s-ServerStarted: BindAddress[%s]", "0.0.1-100999", handlerConfig.BindAddress)
	err = http.ListenAndServe(handlerConfig.BindAddress, nil)
	if err != nil {
		log.Panicf("HTTPStartupError: Message='%+v'", err)
	}
}
