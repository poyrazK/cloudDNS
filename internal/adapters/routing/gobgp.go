package routing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	pb "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
)

// BGPBackend defines the subset of GoBGP server methods we use,
// allowing us to mock it for testing.
type BGPBackend interface {
	Serve()
	Stop()
	StartBgp(ctx context.Context, r *pb.StartBgpRequest) error
	AddPeer(ctx context.Context, r *pb.AddPeerRequest) error
	AddPath(req apiutil.AddPathRequest) ([]apiutil.AddPathResponse, error)
	DeletePath(req apiutil.DeletePathRequest) error
}

// GoBGPAdapter implements the RoutingEngine port using GoBGP.
type GoBGPAdapter struct {
	bgpServer  BGPBackend
	logger     *slog.Logger
	routerID   string
	listenPort int32
	nextHop    string
}

// NewGoBGPAdapter initializes a new GoBGPAdapter with a real GoBGP server.
func NewGoBGPAdapter(logger *slog.Logger) *GoBGPAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &GoBGPAdapter{
		bgpServer:  server.NewBgpServer(),
		logger:     logger,
		routerID:   "127.0.0.1",
		listenPort: 179,
		nextHop:    "127.0.0.1",
	}
}

// SetConfig updates the BGP configuration.
func (a *GoBGPAdapter) SetConfig(routerID string, listenPort int32, nextHop string) {
	if routerID != "" {
		a.routerID = routerID
	}
	if listenPort != 0 {
		a.listenPort = listenPort
	}
	if nextHop != "" {
		a.nextHop = nextHop
	}
}

// Start begins the BGP process and establishes peering.
func (a *GoBGPAdapter) Start(ctx context.Context, localASN, peerASN uint32, peerIP string) error {
	a.logger.Info("starting GoBGP engine", "router_id", a.routerID, "local_asn", localASN, "peer_asn", peerASN, "peer_ip", peerIP)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				a.logger.Error("GoBGP server panicked", "recover", r)
			}
		}()
		a.bgpServer.Serve()
	}()

	// 1. Global Configuration
	global := &pb.Global{
		Asn:        localASN,
		RouterId:   a.routerID,
		ListenPort: a.listenPort,
	}
	if err := a.bgpServer.StartBgp(ctx, &pb.StartBgpRequest{Global: global}); err != nil {
		a.bgpServer.Stop()
		return fmt.Errorf("failed to start BGP global: %w", err)
	}

	// 2. Add Peer
	peer := &pb.Peer{
		Conf: &pb.PeerConf{
			NeighborAddress: peerIP,
			PeerAsn:         peerASN,
		},
	}
	if err := a.bgpServer.AddPeer(ctx, &pb.AddPeerRequest{Peer: peer}); err != nil {
		a.bgpServer.Stop()
		return fmt.Errorf("failed to add BGP peer: %w", err)
	}

	return nil
}

// Announce advertises a VIP via BGP.
func (a *GoBGPAdapter) Announce(_ context.Context, vip string) error {
	if a.bgpServer == nil {
		return errors.New("BGP server not started")
	}

	a.logger.Info("announcing anycast VIP", "vip", vip)

	// Build native types for GoBGP v4
	prefix, err := netip.ParsePrefix(vip + "/32")
	if err != nil {
		return fmt.Errorf("failed to parse vip %s: %w", vip, err)
	}
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return fmt.Errorf("failed to create native nlri for vip %s: %w", vip, err)
	}

	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0), // IGP
	}
	
	nh := a.nextHop
	if nh == "" {
		nh = a.routerID
	}
	if nhIP, err := netip.ParseAddr(nh); err == nil {
		nhAttr, errNH := bgp.NewPathAttributeNextHop(nhIP)
		if errNH == nil {
			attrs = append(attrs, nhAttr)
		}
	}

	path := &apiutil.Path{
		Nlri:   nlri,
		Attrs:  attrs,
		Family: bgp.RF_IPv4_UC,
	}

	req := apiutil.AddPathRequest{
		Paths: []*apiutil.Path{path},
	}

	if _, err := a.bgpServer.AddPath(req); err != nil {
		return fmt.Errorf("failed to add path for vip %s: %w", vip, err)
	}

	return nil
}

// Withdraw removes a VIP advertisement from BGP.
func (a *GoBGPAdapter) Withdraw(_ context.Context, vip string) error {
	if a.bgpServer == nil {
		return errors.New("BGP server not started")
	}

	a.logger.Info("withdrawing anycast VIP", "vip", vip)

	prefix, err := netip.ParsePrefix(vip + "/32")
	if err != nil {
		return fmt.Errorf("failed to parse vip %s: %w", vip, err)
	}
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		return fmt.Errorf("failed to create native nlri for withdrawal of vip %s: %w", vip, err)
	}

	req := apiutil.DeletePathRequest{
		Paths: []*apiutil.Path{
			{
				Nlri:   nlri,
				Family: bgp.RF_IPv4_UC,
			},
		},
	}

	if err := a.bgpServer.DeletePath(req); err != nil {
		return fmt.Errorf("failed to delete path for vip %s: %w", vip, err)
	}

	return nil
}

// Stop gracefully shuts down the BGP engine.
func (a *GoBGPAdapter) Stop() error {
	if a.bgpServer != nil {
		a.bgpServer.Stop()
	}
	return nil
}

var _ ports.RoutingEngine = (*GoBGPAdapter)(nil)
