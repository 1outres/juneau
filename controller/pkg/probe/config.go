package probe

import (
	"encoding/json"
	"fmt"
)

const (
	AnnotationRewriteVersion       = "juneau.loutres.me/probe-rewrite-version"
	AnnotationConfigs              = "juneau.loutres.me/probe-configs"
	RewriteVersion                 = "v1"
	DefaultProxyPort         int32 = 9911
	EndpointPathPrefix             = "/v1/probes/"
)

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Config struct {
	Type        string   `json:"type"`
	Port        int32    `json:"port"`
	Path        string   `json:"path,omitempty"`
	Scheme      string   `json:"scheme,omitempty"`
	Headers     []Header `json:"headers,omitempty"`
	GRPCService string   `json:"grpcService,omitempty"`
	Timeout     int32    `json:"timeout"`
}

type Configs map[string]Config

func Parse(value string) (Configs, error) {
	if value == "" {
		return Configs{}, nil
	}
	var configs Configs
	if err := json.Unmarshal([]byte(value), &configs); err != nil {
		return nil, fmt.Errorf("parse probe configs: %w", err)
	}
	if configs == nil {
		configs = Configs{}
	}
	return configs, nil
}

func Encode(configs Configs) (string, error) {
	data, err := json.Marshal(configs)
	if err != nil {
		return "", fmt.Errorf("encode probe configs: %w", err)
	}
	return string(data), nil
}
