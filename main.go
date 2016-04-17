package main

import(
    "log"
    "net/url"
    "net/http"
    "farm.e-pedion.com/repo/security/config"
    "farm.e-pedion.com/repo/security/database"
    "farm.e-pedion.com/repo/security/proxy"
    "farm.e-pedion.com/repo/security/handler"
    //"farm.e-pedion.com/repo/security/identity"
)

func main() {
    configuration := config.BindConfiguration()
    config.Init()
    log.Printf("main.ConfigurationLoaded: %+v", configuration)
    database.Setup(configuration.DBConfig)

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
    http.Handle("/identity/session/", handler.NewSessionHandler())
    //http.Handle("/identity/login/", identity.NewLoginManagerHandler(identity.NewGetUserHandler(), identity.NewPostUserHandler()))
    http.Handle("/web/", proxy.NewWebReverseProxy(webRemote))
    http.Handle("/api/", proxy.NewApiReverseProxy(apiRemote))
    log.Printf("%s-ServerStarted: BindAddress[%s]", "0.0.1-100999", configuration.BindAddress)
    err = http.ListenAndServe(configuration.BindAddress, nil)
    if err != nil {
        panic(err)
    }
}
