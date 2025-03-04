// Copyright 2019 ChainSafe Systems (ON) Corp.
// This file is part of gossamer.
//
// The gossamer library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The gossamer library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the gossamer library. If not, see <http://www.gnu.org/licenses/>.

package rpc

import (
	"fmt"
	"net/http"

	"github.com/ChainSafe/gossamer/internal/api"
	log "github.com/ChainSafe/log15"
)

// Config contains eneral RPC configuration options
type Config struct {
	Port    uint32       // Listening port
	Host    string       // Listening hostname
	Modules []api.Module // Enabled modules
}

// HttpServer acts as gateway to an RPC server
type HttpServer struct {
	cfg       *Config // Associated config
	rpcServer *Server // Actual RPC call handler
}

// NewHttpServer creates a new http server and registers an associated rpc server
func NewHttpServer(api *api.Api, codec Codec, cfg *Config) *HttpServer {
	server := &HttpServer{
		cfg:       cfg,
		rpcServer: NewApiServer(cfg.Modules, api),
	}

	server.rpcServer.RegisterCodec(codec)

	return server
}

// Start registers the rpc handler function and starts the server listening on `h.port`
func (h *HttpServer) Start() {
	log.Debug("[rpc] Starting HTTP Server...", "port", h.cfg.Port)
	http.HandleFunc("/rpc", h.rpcServer.ServeHTTP)

	go func() {
		err := http.ListenAndServe(fmt.Sprintf("%s:%d", h.cfg.Host, h.cfg.Port), nil)
		if err != nil {
			log.Error("[rpc] http error", "err", err)
		}
	}()
}
