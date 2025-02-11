package tunnel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/dht"
	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"
	"sort"
	"time"
)

func init() {
	tl.Register(OverlayKey{}, "adnlTunnel.overlayKey paymentNode:int256 = adnlTunnel.OverlayKey")
}

type OverlayKey struct {
	PaymentNode []byte `tl:"int256"`
}

func (g *Gateway) updateDHT(ctx context.Context, ttlSeconds int64) error {
	addr := g.gate.GetAddressList()
	stored, _, err := g.dht.StoreAddress(ctx, addr, time.Duration(ttlSeconds)*time.Second, g.key, 0)
	if err != nil && stored == 0 {
		return fmt.Errorf("failed to store address: %w", err)
	}

	pn := g.paymentNode
	if len(pn) == 0 {
		pn = make([]byte, 32)
	}

	overlayKey, err := tl.Hash(OverlayKey{
		PaymentNode: pn,
	})
	if err != nil {
		return fmt.Errorf("failed to serialize key for dht overlay: %w", err)
	}

	nodesList, _, err := g.dht.FindOverlayNodes(ctx, overlayKey)
	if err != nil && !errors.Is(err, dht.ErrDHTValueIsNotFound) {
		return fmt.Errorf("failed to find overlay nodes: %w", err)
	}

	if nodesList == nil {
		nodesList = &overlay.NodesList{}
	}

	node, err := overlay.NewNode(overlayKey, g.key)
	if err != nil {
		return fmt.Errorf("failed creating overlay node: %w", err)
	}

	refreshed := false
	var newList []overlay.Node
	// refresh if already exists
	for i := range nodesList.List {
		id, ok := nodesList.List[i].ID.(adnl.PublicKeyED25519)
		if ok && id.Key.Equal(node.ID.(adnl.PublicKeyED25519).Key) {
			newList = append(newList, *node)
			refreshed = true
			break
		}

		// cleanup outdated ???
		if uint32(nodesList.List[i].Version) > uint32(time.Now().Unix()-ttlSeconds) {
			newList = append(newList, nodesList.List[i])
		}
	}
	nodesList.List = newList

	if !refreshed {
		// create if no records
		if len(nodesList.List) == 0 {
			nodesList = &overlay.NodesList{
				List: []overlay.Node{*node},
			}
			refreshed = true
		} else {
			if len(nodesList.List) >= 5 {
				sort.Slice(nodesList.List, func(i, j int) bool {
					return nodesList.List[i].Version < nodesList.List[j].Version
				})

				// replace oldest
				nodesList.List[0] = *node
				refreshed = true
			} else {
				// add our node if < 5 in list
				nodesList.List = append(nodesList.List, *node)
				refreshed = true
			}
		}
	}

	ovStored, _, err := g.dht.StoreOverlayNodes(ctx, overlayKey, nodesList, time.Duration(ttlSeconds)*time.Second, 0)
	if err != nil {
		return fmt.Errorf("failed to store overlay nodes: %w", err)
	}

	g.log.Debug().Int("addr_nodes", stored).Int("overlay_nodes", ovStored).Msg("dht records updated")

	return nil
}

func (g *Gateway) DiscoverNodes(ctx context.Context) ([]ed25519.PublicKey, error) {
	pn := g.paymentNode
	if len(pn) == 0 {
		pn = make([]byte, 32)
	}

	overlayKey, err := tl.Hash(OverlayKey{
		PaymentNode: pn,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize key for dht overlay: %w", err)
	}

	nodesList, _, err := g.dht.FindOverlayNodes(ctx, overlayKey)
	if err != nil && !errors.Is(err, dht.ErrDHTValueIsNotFound) {
		return nil, fmt.Errorf("failed to find overlay nodes: %w", err)
	}

	if nodesList == nil {
		return nil, nil
	}

	var keys []ed25519.PublicKey
	for _, node := range nodesList.List {
		id, ok := node.ID.(adnl.PublicKeyED25519)
		if ok {
			keys = append(keys, id.Key)
		}
	}

	return keys, nil
}
