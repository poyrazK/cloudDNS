// Package routing provides BGP routing integration for anycast
// DNS deployments using GoBGP.
package routing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

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
// It tracks its goroutines for graceful shutdown and attempts peer reconnection
// on disconnect.
type GoBGPAdapter struct {
	bgpServer  BGPBackend
	logger     *slog.Logger
	routerID   string
	listenPort int32
	nextHop    string

	localASN uint32
	peerASN  uint32
	peerIP   string

	wg          sync.WaitGroup
	stopCh      chan struct{}
	mu          sync.Mutex

	// Track active VIPs so Stop() can withdraw them
	announcedVIPs map[string]bool
	announcedMu   sync.Mutex
}

// NewGoBGPAdapter initializes a new GoBGPAdapter with a real GoBGP server.
func NewGoBGPAdapter(logger *slog.Logger) *GoBGPAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &GoBGPAdapter{
		bgpServer:      server.NewBgpServer(),
		logger:         logger,
		routerID:       "127.0.0.1",
		listenPort:     179,
		nextHop:        "127.0.0.1",
		announcedVIPs: make(map[string]bool),
	}
}

// SetConfig updates the BGP configuration.
func (a *GoBGPAdapter) SetConfig(routerID string, listenPort int32, nextHop string) {
	a.mu.Lock()
	defer a.mu.Unlock()
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

// Start begins the BGP process, establishes peering, and starts a background
// goroutine to monitor peer state and attempt reconnection on disconnect.
func (a *GoBGPAdapter) Start(ctx context.Context, localASN, peerASN uint32, peerIP string) error {
	a.mu.Lock()
	a.localASN = localASN
	a.peerASN = peerASN
	a.peerIP = peerIP
	a.stopCh = make(chan struct{})
	a.mu.Unlock()

	a.logger.Info("starting GoBGP engine", "router_id", a.routerID, "local_asn", localASN, "peer_asn", peerASN, "peer_ip", peerIP)

	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
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
	if err := a.addPeer(ctx, peerASN, peerIP); err != nil {
		a.bgpServer.Stop()
		return fmt.Errorf("failed to add BGP peer: %w", err)
	}

	// 3. Start peer monitor goroutine for reconnection
	a.wg.Add(1)
	go a.monitorPeer(ctx)

	return nil
}

// addPeer adds a BGP peer with the given configuration.
func (a *GoBGPAdapter) addPeer(ctx context.Context, peerASN uint32, peerIP string) error {
	peer := &pb.Peer{
		Conf: &pb.PeerConf{
			NeighborAddress: peerIP,
			PeerAsn:         peerASN,
		},
	}
	return a.bgpServer.AddPeer(ctx, &pb.AddPeerRequest{Peer: peer})
}

// Announce advertises a VIP via BGP.
func (a *GoBGPAdapter) Announce(_ context.Context, vip string) error {
	if a.bgpServer == nil {
		return errors.New("BGP server not started")
	}

	a.logger.Info("announcing anycast VIP", "vip", vip)

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

	// Track announced VIP for later withdrawal on Stop()
	a.announcedMu.Lock()
	a.announcedVIPs[vip] = true
	a.announcedMu.Unlock()

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

	// Include same path attributes as Announce (ORIGIN + NEXT_HOP) per RFC 4271
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0), // IGP
	}
	nh := a.nextHop
	if nh == "" {
		nh = a.routerID
	}
	if nhIP, err := netip.ParseAddr(nh); err == nil {
		if nhAttr, errNH := bgp.NewPathAttributeNextHop(nhIP); errNH == nil {
			attrs = append(attrs, nhAttr)
		}
	}

	req := apiutil.DeletePathRequest{
		Paths: []*apiutil.Path{
			{
				Nlri:   nlri,
				Attrs:  attrs,
				Family: bgp.RF_IPv4_UC,
			},
		},
	}

	if err := a.bgpServer.DeletePath(req); err != nil {
		return fmt.Errorf("failed to delete path for vip %s: %w", vip, err)
	}

	// Remove from tracked VIPs
	a.announcedMu.Lock()
	delete(a.announcedVIPs, vip)
	a.announcedMu.Unlock()

	return nil
}

// Stop gracefully shuts down the BGP engine.
// It signals the monitor goroutine to stop, waits for all goroutines to complete,
// and stops the BGP server. All active VIPs are withdrawn before shutdown.
func (a *GoBGPAdapter) Stop() error {
	a.mu.Lock()
	if a.stopCh != nil {
		close(a.stopCh)
	}
	a.mu.Unlock()

	// Wait for all tracked goroutines to complete
	a.wg.Wait()

	// Withdraw all active VIPs before stopping BGP server
	a.announcedMu.Lock()
	for vip := range a.announcedVIPs {
		prefix, err := netip.ParsePrefix(vip + "/32")
		if err != nil {
			continue
		}
		nlri, err := bgp.NewIPAddrPrefix(prefix)
		if err != nil {
			continue
		}
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
		nh := a.nextHop
		if nh == "" {
			nh = a.routerID
		}
		if nhIP, err := netip.ParseAddr(nh); err == nil {
			if nhAttr, _ := bgp.NewPathAttributeNextHop(nhIP); nhAttr != nil {
				attrs = append(attrs, nhAttr)
			}
		}
		if err := a.bgpServer.DeletePath(apiutil.DeletePathRequest{
			Paths: []*apiutil.Path{{Nlri: nlri, Attrs: attrs, Family: bgp.RF_IPv4_UC}},
		}); err != nil {
			a.logger.Warn("failed to withdraw VIP during shutdown", "vip", vip, "error", err)
		}
	}
	a.announcedVIPs = make(map[string]bool)
	a.announcedMu.Unlock()

	if a.bgpServer != nil {
		a.bgpServer.Stop()
	}
	return nil
}

// monitorPeer watches for peer disconnection and attempts reconnection.
// It polls the peer every 30 seconds by attempting to re-add it. On failure,
// it restarts the BGP server and re-adds the peer. The gobgp library version
// in use does not expose a direct peer state callback API.
func (a *GoBGPAdapter) monitorPeer(ctx context.Context) {
	defer a.wg.Done()

	a.mu.Lock()
	peerIP := a.peerIP
	peerASN := a.peerASN
	a.mu.Unlock()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
			a.logger.Info("peer monitor shutting down")
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.addPeer(ctx, peerASN, peerIP); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					a.logger.Debug("peer health check OK", "peer", peerIP)
				} else {
					a.logger.Warn("peer unhealthy, attempting reconnect", "peer", peerIP, "error", err)
					// Restart BGP server and peer
					a.mu.Lock()
					a.bgpServer.Stop()
					a.bgpServer = server.NewBgpServer()

					global := &pb.Global{
						Asn:        a.localASN,
						RouterId:   a.routerID,
						ListenPort:  a.listenPort,
					}
					bgpCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					if err := a.bgpServer.StartBgp(bgpCtx, &pb.StartBgpRequest{Global: global}); err != nil {
						a.logger.Error("failed to restart BGP after peer failure", "error", err)
						cancel()
						a.mu.Unlock()
						return
					}
					cancel()

					// Only spawn Serve goroutine after successful StartBgp
					// to avoid orphaning a goroutine if StartBgp fails
					a.wg.Add(1)
					go func() {
						defer a.wg.Done()
						a.bgpServer.Serve()
					}()

					if err := a.addPeer(bgpCtx, peerASN, peerIP); err != nil {
						a.logger.Error("failed to re-add peer after restart", "error", err)
					}
					a.mu.Unlock()
				}
			}
		}
	}
}

var _ ports.RoutingEngine = (*GoBGPAdapter)(nil)
