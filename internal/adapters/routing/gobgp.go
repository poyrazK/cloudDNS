package routing

import (
	"context"
	"errors"
	"log/slog"

	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/poyrazK/cloudDNS/internal/core/ports"
	pb "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"
)

// BGPBackend defines the subset of GoBGP server methods we use,
// allowing us to mock it for testing.
type BGPBackend interface {
	Serve()
	Stop()
	AddPeer(ctx context.Context, r *pb.AddPeerRequest) error
	AddPath(ctx context.Context, r *pb.AddPathRequest) (*pb.AddPathResponse, error)
	DeletePath(ctx context.Context, r *pb.DeletePathRequest) error
}

// GoBGPAdapter implements the RoutingEngine port using GoBGP.
type GoBGPAdapter struct {
	bgpServer BGPBackend
	logger    *slog.Logger
}

// NewGoBGPAdapter initializes a new GoBGPAdapter with a real GoBGP server.
func NewGoBGPAdapter(logger *slog.Logger) *GoBGPAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &GoBGPAdapter{
		bgpServer: server.NewBgpServer(),
		logger:    logger,
	}
}

// Start begins the BGP process and establishes peering.
func (a *GoBGPAdapter) Start(ctx context.Context, localASN, peerASN uint32, peerIP string) error {
	a.logger.Info("starting GoBGP engine", "local_asn", localASN, "peer_asn", peerASN, "peer_ip", peerIP)
	
	go a.bgpServer.Serve()

	// Add Peer
	peer := &pb.Peer{
		Conf: &pb.PeerConf{
			NeighborAddress: peerIP,
			PeerAsn:         peerASN,
		},
	}
	if err := a.bgpServer.AddPeer(ctx, &pb.AddPeerRequest{Peer: peer}); err != nil {
		return err
	}

	return nil
}

// Announce advertises a VIP via BGP.
func (a *GoBGPAdapter) Announce(ctx context.Context, vip string) error {
	if a.bgpServer == nil {
		return errors.New("BGP server not started")
	}

	a.logger.Info("announcing anycast VIP", "vip", vip)

	// Build NLRI
	nlri, _ := anypb.New(&pb.IPAddressPrefix{
		Prefix:    vip,
		PrefixLen: 32,
	})

	// Origin Attribute
	origin, _ := anypb.New(&pb.OriginAttribute{
		Origin: 0, // IGP
	})

	path := &pb.Path{
		Nlri:   nlri,
		Pattrs: []*anypb.Any{origin},
		Family: &pb.Family{Afi: pb.Family_AFI_IP, Safi: pb.Family_SAFI_UNICAST},
	}

	if _, err := a.bgpServer.AddPath(ctx, &pb.AddPathRequest{Path: path}); err != nil {
		return err
	}

	return nil
}

// Withdraw removes a VIP advertisement from BGP.
func (a *GoBGPAdapter) Withdraw(ctx context.Context, vip string) error {
	if a.bgpServer == nil {
		return errors.New("BGP server not started")
	}

	a.logger.Info("withdrawing anycast VIP", "vip", vip)

	nlri, _ := anypb.New(&pb.IPAddressPrefix{
		Prefix:    vip,
		PrefixLen: 32,
	})

	path := &pb.Path{
		Nlri:   nlri,
		Family: &pb.Family{Afi: pb.Family_AFI_IP, Safi: pb.Family_SAFI_UNICAST},
	}

	if err := a.bgpServer.DeletePath(ctx, &pb.DeletePathRequest{Path: path}); err != nil {
		return err
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
