package main

import (
	"log"
	"net/http"
	"net/url"

	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/security/database"
	"farm.e-pedion.com/repo/security/handler"
	"farm.e-pedion.com/repo/security/proxy"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	configuration := config.BindConfiguration()
	handlerConfig := configuration.HandlerConfig
	config.Init()
	log.Printf("main.ConfigurationLoaded: %+v", configuration)
	if err := database.Setup(configuration.CassandraConfig); err != nil {
		panic(err)
	}
	if err := cache.Setup(configuration.CacheConfig); err != nil {
		panic(err)
	}
	webRemote, err := url.Parse(configuration.WebURL)
	if err != nil {
		panic(err)
	}
	apiRemote, err := url.Parse(configuration.ApiURL)
	if err != nil {
		panic(err)
	}

	http.Handle("/auth/login/", handler.NewLoginHandler())
	http.Handle("/auth/login/asset/", http.StripPrefix("/auth/login/asset/", http.FileServer(http.Dir("asset/"))))
	http.Handle("/auth/logout/", handler.NewLogoutHandler())
	http.Handle("/identity/session/", handler.NewGetSessionHandler())
	http.Handle("/identity/login/", handler.NewLoginManagerHandler())
	http.Handle("/web/", proxy.NewWebReverseProxy(webRemote))
	http.Handle("/api/", proxy.NewApiReverseProxy(apiRemote))
	log.Printf("%s-ServerStarted: BindAddress[%s]", "0.0.1-100999", handlerConfig.BindAddress)
	err = http.ListenAndServe(handlerConfig.BindAddress, nil)
	if err != nil {
		panic(err)
	}
}
