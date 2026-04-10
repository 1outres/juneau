package bird

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"text/template"

	bgptypes "github.com/1outres/juneau/bgp-speaker/internal/types"
)

type ConfigBuilder interface {
	Build(cfg *bgptypes.DesiredConfig) (string, error)
}

type PlaceholderBuilder struct {
	nodeName string
	nodeIP   string
}

func NewPlaceholderBuilder(nodeName string, nodeIP string) *PlaceholderBuilder {
	return &PlaceholderBuilder{
		nodeName: nodeName,
		nodeIP:   nodeIP,
	}
}

type templateParams struct {
	NodeIP string
	Peers  []templateParamsPeer
}

type templateParamsPeer struct {
	ID        string
	LocalASN  uint32
	RemoteIP  string
	RemoteASN uint32
	Prefixes  []string
}

const configTemplate = `router id {{ .NodeIP }};{{ $nodeIP := .NodeIP }}

protocol device {}

{{ range $peer := .Peers }}
ipv4 table bgp_{{ $peer.ID }};
protocol static static_bgp_{{ $peer.ID }} {
  ipv4 {
    table bgp_{{ $peer.ID }};
    import filter {
      accept; };
    export none;
  };
  {{ range $prefix := $peer.Prefixes }}route {{ $prefix }} blackhole;{{ end }}
}
protocol bgp peer_{{ $peer.ID }} {
  local {{ $nodeIP }} as {{ $peer.LocalASN }};
  neighbor {{ $peer.RemoteIP }} as {{ $peer.RemoteASN }};
  ipv4 {
    table bgp_{{ $peer.ID }};
    import filter {
      reject;
    };
    export filter {
      accept;
    };
  };
}
{{ end }}
`

func (b *PlaceholderBuilder) Build(cfg *bgptypes.DesiredConfig) (string, error) {
	if b.nodeIP == "" {
		return "", fmt.Errorf("node IP is empty")
	}

	params := templateParams{
		NodeIP: b.nodeIP,
	}

	if cfg != nil {
		params.Peers = make([]templateParamsPeer, 0, len(cfg.Peers))
		for _, peer := range cfg.Peers {
			if peer == nil {
				continue
			}
			id := formatPeerID(b.nodeIP, peer.LocalASN, peer.RemoteIP, peer.RemoteASN)
			prefixes := normalizePrefixes(peer.Prefixes)

			params.Peers = append(params.Peers, templateParamsPeer{
				ID:        id,
				LocalASN:  peer.LocalASN,
				RemoteIP:  peer.RemoteIP,
				RemoteASN: peer.RemoteASN,
				Prefixes:  prefixes,
			})
		}
	}

	sort.Slice(params.Peers, func(i, j int) bool {
		if params.Peers[i].RemoteIP != params.Peers[j].RemoteIP {
			return params.Peers[i].RemoteIP < params.Peers[j].RemoteIP
		}
		if params.Peers[i].RemoteASN != params.Peers[j].RemoteASN {
			return params.Peers[i].RemoteASN < params.Peers[j].RemoteASN
		}
		return params.Peers[i].LocalASN < params.Peers[j].LocalASN
	})

	tmpl, err := template.New("bird").Parse(configTemplate)
	if err != nil {
		return "", fmt.Errorf("parse config template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", fmt.Errorf("render config template: %w", err)
	}

	return buf.String(), nil
}

func normalizePrefixes(prefixes []*net.IPNet) []string {
	unique := make(map[string]struct{})
	for _, prefix := range prefixes {
		if prefix == nil {
			continue
		}
		unique[prefix.String()] = struct{}{}
	}

	out := make([]string, 0, len(unique))
	for prefix := range unique {
		out = append(out, prefix)
	}
	sort.Strings(out)
	return out
}

func formatPeerID(nodeIP string, localASN uint32, remoteIP string, remoteASN uint32) string {
	input := fmt.Sprintf("%s:%d:%s:%d", nodeIP, localASN, remoteIP, remoteASN)
	hash := sha256.Sum256([]byte(input))
	encoded := hex.EncodeToString(hash[:])
	if len(encoded) > 31 {
		return encoded[:31]
	}
	return encoded
}
