// Package routing implements BGP routing and VIP management adapters.
package routing

import (
	"context"
	"fmt"
	"log/slog"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	"google.golang.org/protobuf/types/known/anypb"
)

// GoBGPAdapter implements the RoutingEngine port using the GoBGP library.
type GoBGPAdapter struct {
	bgpServer *server.BgpServer
	logger    *slog.Logger
}

// NewGoBGPAdapter initializes a new GoBGPAdapter.
func NewGoBGPAdapter(logger *slog.Logger) *GoBGPAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &GoBGPAdapter{
		bgpServer: server.NewBgpServer(),
		logger:    logger,
	}
}

// Start initializes the GoBGP server and establishes a peering session.
func (a *GoBGPAdapter) Start(ctx context.Context, localASN, peerASN uint32, peerIP string) error {
	go a.bgpServer.Serve()

	// 1. Global Config
	if err := a.bgpServer.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        localASN,
			RouterId:   "127.0.0.1", // Default, should be configurable or auto-detected
			ListenPort: 179,
		},
	}); err != nil {
		return fmt.Errorf("failed to start BGP server: %w", err)
	}

	// 2. Add Peer
	if err := a.bgpServer.AddPeer(ctx, &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerIP,
				PeerAsn:         peerASN,
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to add BGP peer: %w", err)
	}

	a.logger.Info("GoBGP speaker started", "local_asn", localASN, "peer_asn", peerASN, "peer_ip", peerIP)
	return nil
}

// Announce advertises a VIP prefix via BGP.
func (a *GoBGPAdapter) Announce(ctx context.Context, vip string) error {
	nlri, _ := anypb.New(&api.IPAddressPrefix{
		Prefix:    vip,
		PrefixLen: 32,
	})
	
	attrs, _ := anypb.New(&api.NextHopAttribute{
		NextHop: "127.0.0.1", // Self
	})

	_, err := a.bgpServer.AddPath(ctx, &api.AddPathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlri,
			Pattrs: []*anypb.Any{attrs},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to announce route %s: %w", vip, err)
	}

	a.logger.Info("announced anycast VIP", "vip", vip)
	return nil
}

// Withdraw removes a VIP advertisement from BGP.
func (a *GoBGPAdapter) Withdraw(ctx context.Context, vip string) error {
	nlri, _ := anypb.New(&api.IPAddressPrefix{
		Prefix:    vip,
		PrefixLen: 32,
	})

	err := a.bgpServer.DeletePath(ctx, &api.DeletePathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlri,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to withdraw route %s: %w", vip, err)
	}

	a.logger.Warn("withdrew anycast VIP", "vip", vip)
	return nil
}

// Stop gracefully shuts down the BGP server.
func (a *GoBGPAdapter) Stop() error {
	return a.bgpServer.StopBgp(context.Background(), &api.StopBgpRequest{})
}

var _ ports.RoutingEngine = (*GoBGPAdapter)(nil)
