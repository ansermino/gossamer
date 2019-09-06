package api

import (
	log "github.com/ChainSafe/log15"
	peer "github.com/libp2p/go-libp2p-peer"
)

type systemModule struct {
	p2p     P2pApi
	runtime RuntimeApi
}

func NewSystemModule(p2p P2pApi, rt RuntimeApi) *systemModule {
	return &systemModule{
		p2p,
		rt,
	}
}

// Release version
func (m *systemModule) Version() string {
	log.Debug("[rpc] Executing System.Version", "params", nil)
	//TODO: Replace with dynamic version
	return "0.0.1"
}

// System Chain not implemented yet
// func (m *systemModule) chain() string {
// 	log.Debug("[rpc] Executing System.Chain", "params", nil)
// 	return m.runtime.Chain()
// }

// Health of the node
func (m *systemModule) Health() SystemHealthResponse {
	log.Debug("[rpc] Executing System.Health", "params", nil)
	health := SystemHealthResponse{
		IsSyncing:       false,
		Peers:           int(len(m.Peers())),
		ShouldHavePeers: (len(m.Peers()) != 0),
	}
	return health
}

func (m *systemModule) Name() string {
	log.Debug("[rpc] Executing System.Name", "params", nil)
	//TODO: Replace with dynamic name
	return "Gossamer"
}

func (m *systemModule) NetworkState() SystemNetworkStateResponse {
	log.Debug("[rpc] Executing System.networkState", "params", nil)
	return m.p2p.NetworkState()
}

// Peers of the node
func (m *systemModule) Peers() []peer.ID {
	log.Debug("[rpc] Executing System.Peers", "params", nil)
	return m.p2p.Peers()
}

// System Properties not implemented yet
// func (m *systemModule) properties() string {
// 	log.Debug("[rpc] Executing System.Properties", "params", nil)
// 	return m.runtime.properties()
// }

// TODO: Move to 'p2p' module
func (m *systemModule) PeerCount() int {
	log.Debug("[rpc] Executing System.PeerCount", "params", nil)
	return m.p2p.PeerCount()
}
