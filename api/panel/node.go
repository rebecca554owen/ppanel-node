package panel

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-json"
)

// Security type
const (
	None    = 0
	Tls     = 1
	Reality = 2
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
	//Routes     []Route      `json:"routes"`

	Vless       *VAllssNode      `json:"vless,omitempty"`
	Vmess       *VAllssNode      `json:"vmess,omitempty"`
	Shadowsocks *ShadowsocksNode `json:"shadowsocks,omitempty"`
	Trojan      *TrojanNode      `json:"trojan,omitempty"`
	Hysteria    *HysteriaNode    `json:"hysteria,omitempty"`
	Hysteria2   *Hysteria2Node   `json:"hysteria2,omitempty"`
}

type BasicConfig struct {
	PushInterval any `json:"push_interval"`
	PullInterval any `json:"pull_interval"`
}

// VAllssNode is vmess and vless node info
type VAllssNode struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Network           string `json:"network"`
	TransportRAW      string `json:"transport"`
	Transport         json.RawMessage
	Security          string `json:"security"`
	SecurityConfigRAW string `json:"security_config"`
	SecurityConfig    SecurityConfig
	// vless only
	XTLS string `json:"xtls"`
}

type SecurityConfig struct {
	ServerAddress string `json:"server_address"`
	ServerName    string `json:"server_name"`
	ServerPort    int    `json:"server_port"`
	Fingerprint   string `json:"fingerprint"`
	ProxyProtocol string `json:"proxy_protocol"`
	PrivateKey    string `json:"private_key"`
	PublicKey     string `json:"public_key"`
	ShortID       string `json:"short_id"`
	Insecure      bool   `json:"allow_insecure"`
}

type ShadowsocksNode struct {
	Port      int    `json:"port"`
	Cipher    string `json:"method"`
	ServerKey string `json:"server_key"`
}

type TrojanNode struct {
	Host           string          `json:"host"`
	Port           int             `json:"port"`
	Network        string          `json:"network"`
	Transport      json.RawMessage `json:"transport"`
	Security       string          `json:"security"`
	SecurityConfig SecurityConfig  `json:"security_config"`
}

type HysteriaNode struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	ServerName string `json:"server_name"`
	UpMbps     int    `json:"up_mbps"`
	DownMbps   int    `json:"down_mbps"`
	Obfs       string `json:"obfs"`
}

type Hysteria2Node struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ServerName   string `json:"server_name"`
	UpMbps       int    `json:"up_mbps"`
	DownMbps     int    `json:"down_mbps"`
	ObfsType     string `json:"obfs"`
	ObfsPassword string `json:"obfs-password"`
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

	if node.Common.Vless != nil {
		securityConfigJSON := strings.ReplaceAll(node.Common.Vless.SecurityConfigRAW, "\\\"", "\"")
		securityConfigJSON = strings.Trim(securityConfigJSON, "\"")
		transportJSON := strings.ReplaceAll(node.Common.Vless.TransportRAW, "\\\"", "\"")

		if err = json.Unmarshal([]byte(securityConfigJSON), &node.Common.Vless.SecurityConfig); err != nil {
			return nil, fmt.Errorf("Error parsing SecurityConfig: %s", err)
		}
		if err = json.Unmarshal([]byte(transportJSON), &node.Common.Vless.Transport); err != nil {
			return nil, fmt.Errorf("Error parsing Transport: %s", err)
		}
	}
	// set interval
	node.PushInterval = intervalToTime(node.Common.Basic.PushInterval)
	node.PullInterval = intervalToTime(node.Common.Basic.PullInterval)

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
