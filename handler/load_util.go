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
	"farm.e-pedion.com/repo/security/client/cassandra"
	"farm.e-pedion.com/repo/security/data"

	//"farm.e-pedion.com/repo/security/asset"
	"github.com/valyala/fasthttp"
)

func NewLoadTestHandler() *LoadTestHandler {
	return &LoadTestHandler{
		Get: &LoadGetTestHandler{
			client: cassandra.NewClient(),
		},
		Post: &LoadPostTestHandler{},
	}
}

type LoadTestHandler struct {
	Get  *LoadGetTestHandler
	Post *LoadPostTestHandler
}

type LoadGetTestHandler struct {
	client cassandra.Client
}

func (h *LoadGetTestHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	if !ctx.IsGet() {
		ctx.Error("405 - MethodNotAllowed", fasthttp.StatusMethodNotAllowed)
		return
	}
	log.Info("LoadGetTestHandler.Request",
		logger.Bytes("Method", ctx.Method()),
		logger.String("URI", ctx.URI().String()),
	)
	identifier := string(ctx.URI().LastPathSegment())

	login := data.Login{
		Client:   h.client,
		Username: identifier,
		Name:     "Load Get TestHandler das Couves",
		Password: "dummypwd",
		Roles:    []string{"role1", "role2", "role3", "roleN"},
	}
	if err := login.Read(); err != nil {
		log.Error("ReadLoginError ",
			logger.String("Username", identifier),
			logger.Error(err),
		)
		if err == data.NotFoundErr {
			ctx.Error("404 - NotFound", fasthttp.StatusNotFound)
			return
		}
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}

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
	log.Info("LoadGetTestHandler.Response",
		logger.String("Content-Type", "application/json; charset=utf-8"),
		logger.Int("Status", fasthttp.StatusOK),
	)
}

type LoadPostTestHandler struct {
}

func (h *LoadPostTestHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	if !ctx.IsPost() && ctx.IsPut() {
		ctx.Error("405 - MethodNotAllowed", fasthttp.StatusMethodNotAllowed)
		return
	}
	log.Debug("LoadPostTestHandler.Request",
		logger.Bytes("Method", ctx.Method()),
		logger.String("URI", ctx.URI().String()),
	)
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
	log.Debug("LoadPostTestHandler.Response",
		logger.String("Content-Type", "application/json; charset=utf-8"),
		logger.Int("Status", fasthttp.StatusCreated),
	)
}
