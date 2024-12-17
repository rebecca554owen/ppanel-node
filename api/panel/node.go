package panel

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/goccy/go-json"
)

type NodeInfo struct {
	Id           int
	Type         string
	PushInterval time.Duration
	PullInterval time.Duration
	Common       *CommonNode
}

type CommonNode struct {
	Basic    *BasicConfig `json:"basic"`
	Protocol string       `json:"protocol"`

	Config      json.RawMessage `json:"config"`
	Vless       *VlessNode
	Vmess       *VmessNode
	Shadowsocks *ShadowsocksNode
	Trojan      *TrojanNode
	Tuic        *TuicNode
	Hysteria2   *Hysteria2Node
}

type BasicConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

type SecurityConfig struct {
	SNI                  string `json:"sni"`
	AllowInsecure        *bool  `json:"allow_insecure"`
	Fingerprint          string `json:"fingerprint"`
	RealityServerAddress string `json:"reality_server_addr"`
	RealityServerPort    int    `json:"reality_server_port"`
	RealityPrivateKey    string `json:"reality_private_key"`
	RealityPublicKey     string `json:"reality_public_key"`
	RealityShortId       string `json:"reality_short_id"`
}

type TransportConfig struct {
	Path        string `json:"path"`
	Host        string `json:"host"`
	ServiceName string `json:"service_name"`
}

type VlessNode struct {
	Port            int              `json:"port"`
	Flow            string           `json:"flow"`
	Network         string           `json:"transport"`
	TransportConfig *TransportConfig `json:"transport_config"`
	Security        string           `json:"security"`
	SecurityConfig  *SecurityConfig  `json:"security_config"`
}

type VmessNode struct {
	Port            int              `json:"port"`
	Network         string           `json:"transport"`
	TransportConfig *TransportConfig `json:"transport_config"`
	Security        string           `json:"security"`
	SecurityConfig  *SecurityConfig  `json:"security_config"`
}

type ShadowsocksNode struct {
	Port      int    `json:"port"`
	Cipher    string `json:"method"`
	ServerKey string `json:"server_key"`
}

type TrojanNode struct {
	Port            int              `json:"port"`
	Network         string           `json:"transport"`
	TransportConfig *TransportConfig `json:"transport_config"`
	Security        string           `json:"security"`
	SecurityConfig  *SecurityConfig  `json:"security_config"`
}

type TuicNode struct {
	Port           int             `json:"port"`
	SecurityConfig *SecurityConfig `json:"security_config"`
}

type Hysteria2Node struct {
	Port           int             `json:"port"`
	HopPorts       string          `json:"hop_ports"`
	HopInterval    int             `json:"hop_interval"`
	ObfsPassword   string          `json:"obfs_password"`
	SecurityConfig *SecurityConfig `json:"security_config"`
}

type ServerPushStatusRequest struct {
	Cpu       float64 `json:"cpu"`
	Mem       float64 `json:"mem"`
	Disk      float64 `json:"disk"`
	UpdatedAt int64   `json:"updated_at"`
}

type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

func (c *Client) GetNodeInfo() (node *NodeInfo, err error) {
	const path = "/v1/server/config"
	r, err := c.client.
		R().
		SetHeader("If-None-Match", c.nodeEtag).
		ForceContentType("application/json").
		Get(path)

	if r.StatusCode() == 304 {
		return nil, nil
	}
	c.nodeEtag = r.Header().Get("ETag")
	if err = c.checkResponse(r, path, err); err != nil {
		return nil, err
	}

	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("received nil response")
	}
	node = &NodeInfo{
		Id:     c.NodeId,
		Type:   c.NodeType,
		Common: &CommonNode{},
	}
	// parse protocol params
	err = json.Unmarshal(r.Body(), node.Common)
	if err != nil {
		return nil, fmt.Errorf("decode node params error: %s", err)
	}
	// set interval
	node.PushInterval = intervalToTime(node.Common.Basic.PushInterval)
	node.PullInterval = intervalToTime(node.Common.Basic.PullInterval)

	switch node.Common.Protocol {
	case "vless":
		node.Common.Vless = &VlessNode{}
		err = json.Unmarshal(node.Common.Config, node.Common.Vless)
	case "vmess":
		node.Common.Vmess = &VmessNode{}
		err = json.Unmarshal(node.Common.Config, node.Common.Vmess)
	case "trojan":
		node.Common.Trojan = &TrojanNode{}
		err = json.Unmarshal(node.Common.Config, node.Common.Trojan)
	case "shadowsocks":
		node.Common.Shadowsocks = &ShadowsocksNode{}
		err = json.Unmarshal(node.Common.Config, node.Common.Shadowsocks)
	case "tuic":
		node.Common.Tuic = &TuicNode{}
		err = json.Unmarshal(node.Common.Config, node.Common.Tuic)
	case "hysteria2":
		node.Common.Hysteria2 = &Hysteria2Node{}
		err = json.Unmarshal(node.Common.Config, node.Common.Hysteria2)
	default:
		err = fmt.Errorf("unknown protocol:%s", node.Common.Protocol)
	}

	if err != nil {
		return nil, fmt.Errorf("decode node config error: %s", err)
	}

	return node, nil
}

func intervalToTime(i interface{}) time.Duration {
	switch reflect.TypeOf(i).Kind() {
	case reflect.Int:
		return time.Duration(i.(int)) * time.Second
	case reflect.String:
		i, _ := strconv.Atoi(i.(string))
		return time.Duration(i) * time.Second
	case reflect.Float64:
		return time.Duration(i.(float64)) * time.Second
	default:
		return time.Duration(reflect.ValueOf(i).Int()) * time.Second
	}
}

func (c *Client) ReportNodeStatus(nodeStatus *NodeStatus) (err error) {
	path := "/v1/server/status"
	status := ServerPushStatusRequest{
		Cpu:       nodeStatus.CPU,
		Mem:       nodeStatus.Mem,
		Disk:      nodeStatus.Disk,
		UpdatedAt: time.Now().UnixMilli(),
	}
	if _, err = c.client.R().SetBody(status).ForceContentType("application/json").Post(path); err != nil {
		return fmt.Errorf("request %s failed: %v", c.assembleURL(path), err.Error())
	}
	return nil
}
