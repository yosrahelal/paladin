package router

import (
	"context"
	"net"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/kaleido-io/paladin/config/pkg/pldconf"
	"github.com/kaleido-io/paladin/toolkit/pkg/httpserver"
)

type Router interface {
	Start() error
	Stop()
	Addr() net.Addr

	HandleFunc(path string, f func(http.ResponseWriter, *http.Request))
	PathPrefixHandleFunc(path string, f func(http.ResponseWriter, *http.Request))
}

func NewRouter(ctx context.Context, description string, conf *pldconf.HTTPServerConfig) (_ *router, err error) {
	r := &router{
		ctx:    ctx,
		router: mux.NewRouter(),
	}

	r.server, err = httpserver.NewServer(ctx, description, conf, r.router)
	return r, err
}

// rpcServer implements the RPCServer interface
var _ Router = &router{}

type router struct {
	ctx    context.Context
	router *mux.Router
	server httpserver.Server
}

func (r *router) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	r.router.HandleFunc(path, f)
}

func (r *router) PathPrefixHandleFunc(path string, f func(http.ResponseWriter, *http.Request)) {
	r.router.PathPrefix(path).HandlerFunc(f)
}

func (r *router) Addr() (a net.Addr) {
	if r.server != nil {
		a = r.server.Addr()
	}
	return a
}

func (r *router) Start() (err error) {
	if r.server != nil {
		return r.server.Start()
	}
	return nil
}

func (r *router) Stop() {
	if r.server != nil {
		r.server.Stop()
	}
}
