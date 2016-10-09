package handler

import (
	"encoding/json"
	//"fmt"
	//"net/http"
	//"regexp"
	//"strings"
	//"time"

	//"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/data"

	//"farm.e-pedion.com/repo/security/asset"
	"github.com/valyala/fasthttp"
)

func NewLoadTestHandler() *LoadTestHandler {
	return &LoadTestHandler{
		Get:  &LoadGetTestHandler{},
		Post: &LoadPostTestHandler{},
	}
}

type LoadTestHandler struct {
	Get  *LoadGetTestHandler
	Post *LoadPostTestHandler
}

type LoadGetTestHandler struct {
}

func (h *LoadGetTestHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	if !ctx.IsGet() {
		ctx.Error("405 - MethodNotAllowed", fasthttp.StatusMethodNotAllowed)
		return
	}
	//log.Debug("LoadGetTestHandler", logger.String("URI", ctx.URI()))
	identifier := string(ctx.URI().LastPathSegment())

	login := data.Login{
		Username: identifier,
		Name:     "Load Get TestHandler das Couves",
		Password: "dummypwd",
		Roles:    []string{"role1", "role2", "role3", "roleN"},
	}
	// if err := login.Read(); err != nil {
	// 	log.Errorf("ReadLoginError[Username=%v Message='%v']", username, err)
	// 	ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
	// 	return
	// }

	err := json.NewEncoder(ctx).Encode(login)
	if err != nil {
		log.Error("handler.GetLoginHandler.WriteResponseError",
			logger.String("Username", login.Username),
			logger.Error(err),
		)
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetContentType("application/json; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusOK)
	// bytesWritten, err := ctx.Write(jsonData)
	// if err != nil {
	// 	log.Errorf("WriteResponseError[Username[%v] Error[%v]", username, err)
	// } else {
	// 	log.Infof("ResponseWritten: Username[%v] Bytes[%v]", username, bytesWritten)
	// }

}

type LoadPostTestHandler struct {
}

func (h *LoadPostTestHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	if !ctx.IsPost() && ctx.IsPut() {
		ctx.Error("405 - MethodNotAllowed", fasthttp.StatusMethodNotAllowed)
		return
	}
	//log.Debug("LoadPostTestHandler", logger.String("URI", ctx.URI()))
	var login data.Login
	err := json.Unmarshal(ctx.PostBody(), &login)
	if err != nil {
		log.Error("handler.LoadPostTestHandler.ReadRequestErr",
			logger.String("Username", login.Username),
			logger.Bytes("Body", ctx.PostBody()),
			logger.Error(err),
		)
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	login.Password = "dummypwd"
	// if err := login.Write(); err != nil {
	// 	log.Errorf("ReadLoginError[Username=%v Message='%v']", username, err)
	// 	ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
	// 	return
	// }

	err = json.NewEncoder(ctx).Encode(login)
	if err != nil {
		log.Error("handler.LoadPostTestHandler.WriteResponseError",
			logger.Struct("data.Login", login),
			logger.Error(err),
		)
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetContentType("application/json; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusCreated)
	// bytesWritten, err := ctx.Write(jsonData)
	// if err != nil {
	// 	log.Errorf("WriteResponseError[Username[%v] Error[%v]", username, err)
	// } else {
	// 	log.Infof("ResponseWritten: Username[%v] Bytes[%v]", username, bytesWritten)
	// }

}
