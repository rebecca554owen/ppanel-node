package sing

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/sagernet/sing-box/inbound"
	"github.com/sagernet/sing-box/option"
	F "github.com/sagernet/sing/common/format"
)

type HttpNetworkConfig struct {
	Header struct {
		Type     string           `json:"type"`
		Request  *json.RawMessage `json:"request"`
		Response *json.RawMessage `json:"response"`
	} `json:"header"`
}

type HttpRequest struct {
	Version string   `json:"version"`
	Method  string   `json:"method"`
	Path    []string `json:"path"`
	Headers struct {
		Host []string `json:"Host"`
	} `json:"headers"`
}

type WsNetworkConfig struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type GrpcNetworkConfig struct {
	ServiceName string `json:"serviceName"`
}

type HttpupgradeNetworkConfig struct {
	Path string `json:"path"`
	Host string `json:"host"`
}

func getInboundOptions(tag string, info *panel.NodeInfo, c *conf.Options) (option.Inbound, error) {
	addr, err := netip.ParseAddr(c.ListenIP)
	if err != nil {
		return option.Inbound{}, fmt.Errorf("the listen ip not vail")
	}
	var (
		port       uint16
		security   string
		servername string
		network    string
		transport  json.RawMessage
	)

	switch info.Common.Protocol {
	case "Vless":
		port = uint16(info.Common.Vless.Port)
		security = info.Common.Vless.Security
		servername = info.Common.Vless.SecurityConfig.ServerName
		network = info.Common.Vless.Network
		transport = info.Common.Vless.Transport
	case "Vmess":
		port = uint16(info.Common.Vmess.Port)
		security = info.Common.Vmess.Security
		servername = info.Common.Vmess.SecurityConfig.ServerName
		network = info.Common.Vmess.Network
		transport = info.Common.Vmess.Transport
	case "Trojan":
		port = uint16(info.Common.Trojan.Port)
		security = info.Common.Trojan.Security
		servername = info.Common.Trojan.SecurityConfig.ServerName
	case "Shadowsocks":
		port = uint16(info.Common.Shadowsocks.Port)
		security = ""
	case "Hysteria":
		port = uint16(info.Common.Hysteria.Port)
		security = "tls"
		servername = info.Common.Hysteria.ServerName
	case "Hysteria2":
		port = uint16(info.Common.Hysteria2.Port)
		security = "tls"
		servername = info.Common.Hysteria2.ServerName

	default:
		fmt.Println("Unknown protocol:", info.Common.Protocol)
	}

	var domainStrategy option.DomainStrategy
	if c.SingOptions.EnableDNS {
		domainStrategy = c.SingOptions.DomainStrategy
	}
	listen := option.ListenOptions{
		Listen:      (*option.ListenAddress)(&addr),
		ListenPort:  port,
		TCPFastOpen: c.SingOptions.TCPFastOpen,
		InboundOptions: option.InboundOptions{
			SniffEnabled:             c.SingOptions.SniffEnabled,
			SniffOverrideDestination: c.SingOptions.SniffOverrideDestination,
			DomainStrategy:           domainStrategy,
		},
	}
	var multiplex *option.InboundMultiplexOptions
	if c.SingOptions.Multiplex != nil {
		multiplexOption := option.InboundMultiplexOptions{
			Enabled: c.SingOptions.Multiplex.Enabled,
			Padding: c.SingOptions.Multiplex.Padding,
			Brutal: &option.BrutalOptions{
				Enabled:  c.SingOptions.Multiplex.Brutal.Enabled,
				UpMbps:   c.SingOptions.Multiplex.Brutal.UpMbps,
				DownMbps: c.SingOptions.Multiplex.Brutal.DownMbps,
			},
		}
		multiplex = &multiplexOption
	}
	var tls option.InboundTLSOptions
	switch security {
	case "tls":
		if c.CertConfig == nil {
			return option.Inbound{}, fmt.Errorf("the CertConfig is not vail")
		}
		switch c.CertConfig.CertMode {
		case "none", "":
			break // disable
		default:
			tls.Enabled = true
			tls.CertificatePath = c.CertConfig.CertFile
			tls.KeyPath = c.CertConfig.KeyFile
		}
	case "reality":
		tls.Enabled = true
		tls.ServerName = servername
		v := info.Common.Vless.SecurityConfig
		var dest string
		if v.ServerAddress != "" {
			dest = v.ServerAddress
		} else {
			dest = tls.ServerName
		}
		xver, _ := strconv.Atoi(v.ProxyProtocol)

		tls.Reality = &option.InboundRealityOptions{
			Enabled:    true,
			ShortID:    []string{v.ShortID},
			PrivateKey: v.PrivateKey,
			Xver:       uint8(xver),
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     dest,
					ServerPort: uint16(v.ServerPort),
				},
			},
		}
	}
	in := option.Inbound{
		Tag: tag,
	}
	switch info.Type {
	case "vmess", "vless":
		t := option.V2RayTransportOptions{
			Type: network,
		}
		switch network {
		case "tcp":
			if len(transport) != 0 {
				networkconfig := HttpNetworkConfig{}
				err := json.Unmarshal(transport, &networkconfig)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				//Todo fix http options
				if networkconfig.Header.Type == "http" {
					t.Type = networkconfig.Header.Type
					var request HttpRequest
					if networkconfig.Header.Request != nil {
						err = json.Unmarshal(*networkconfig.Header.Request, &request)
						if err != nil {
							return option.Inbound{}, fmt.Errorf("decode HttpRequest error: %s", err)
						}
						t.HTTPOptions.Host = request.Headers.Host
						t.HTTPOptions.Path = request.Path[0]
						t.HTTPOptions.Method = request.Method
					}
				} else {
					t.Type = ""
				}
			} else {
				t.Type = ""
			}
		case "ws":
			var (
				path    string
				ed      int
				headers map[string]option.Listable[string]
			)
			if len(transport) != 0 {
				networkconfig := WsNetworkConfig{}
				err := json.Unmarshal(transport, &networkconfig)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				var u *url.URL
				u, err = url.Parse(networkconfig.Path)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("parse path error: %s", err)
				}
				path = u.Path
				ed, _ = strconv.Atoi(u.Query().Get("ed"))
				headers = make(map[string]option.Listable[string], len(networkconfig.Headers))
				for k, v := range networkconfig.Headers {
					headers[k] = option.Listable[string]{
						v,
					}
				}
			}
			t.WebsocketOptions = option.V2RayWebsocketOptions{
				Path:                path,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
				MaxEarlyData:        uint32(ed),
				Headers:             headers,
			}
		case "grpc":
			networkconfig := GrpcNetworkConfig{}
			if len(transport) != 0 {
				err := json.Unmarshal(transport, &networkconfig)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.GRPCOptions = option.V2RayGRPCOptions{
				ServiceName: networkconfig.ServiceName,
			}
		case "httpupgrade":
			networkconfig := HttpupgradeNetworkConfig{}
			if len(transport) != 0 {
				err := json.Unmarshal(transport, &networkconfig)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.HTTPUpgradeOptions = option.V2RayHTTPUpgradeOptions{
				Path: networkconfig.Path,
				Host: networkconfig.Host,
			}
		}
		if info.Type == "vless" {
			in.Type = "vless"
			in.VLESSOptions = option.VLESSInboundOptions{
				ListenOptions: listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &tls,
				},
				Transport: &t,
				Multiplex: multiplex,
			}
		} else {
			in.Type = "vmess"
			in.VMessOptions = option.VMessInboundOptions{
				ListenOptions: listen,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &tls,
				},
				Transport: &t,
				Multiplex: multiplex,
			}
		}
	case "shadowsocks":
		in.Type = "shadowsocks"
		var keyLength int
		switch info.Common.Shadowsocks.Cipher {
		case "2022-blake3-aes-128-gcm":
			keyLength = 16
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
			keyLength = 32
		default:
			keyLength = 16
		}
		in.ShadowsocksOptions = option.ShadowsocksInboundOptions{
			ListenOptions: listen,
			Method:        info.Common.Shadowsocks.Cipher,
			Multiplex:     multiplex,
		}
		p := make([]byte, keyLength)
		_, _ = rand.Read(p)
		randomPasswd := string(p)
		if strings.Contains(info.Common.Shadowsocks.Cipher, "2022") {
			in.ShadowsocksOptions.Password = info.Common.Shadowsocks.ServerKey
			randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		}
		in.ShadowsocksOptions.Users = []option.ShadowsocksUser{{
			Password: randomPasswd,
		}}
	case "trojan":
		n := info.Common.Trojan
		t := option.V2RayTransportOptions{
			Type: n.Network,
		}
		switch n.Network {
		case "tcp":
			t.Type = ""
		case "ws":
			var (
				path    string
				ed      int
				headers map[string]option.Listable[string]
			)
			if len(n.Transport) != 0 {
				networkconfig := WsNetworkConfig{}
				err := json.Unmarshal(n.Transport, &networkconfig)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
				var u *url.URL
				u, err = url.Parse(networkconfig.Path)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("parse path error: %s", err)
				}
				path = u.Path
				ed, _ = strconv.Atoi(u.Query().Get("ed"))
				headers = make(map[string]option.Listable[string], len(networkconfig.Headers))
				for k, v := range networkconfig.Headers {
					headers[k] = option.Listable[string]{
						v,
					}
				}
			}
			t.WebsocketOptions = option.V2RayWebsocketOptions{
				Path:                path,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
				MaxEarlyData:        uint32(ed),
				Headers:             headers,
			}
		case "grpc":
			networkconfig := GrpcNetworkConfig{}
			if len(n.Transport) != 0 {
				err := json.Unmarshal(n.Transport, &networkconfig)
				if err != nil {
					return option.Inbound{}, fmt.Errorf("decode NetworkSettings error: %s", err)
				}
			}
			t.GRPCOptions = option.V2RayGRPCOptions{
				ServiceName: networkconfig.ServiceName,
			}
		default:
			t.Type = ""
		}
		in.Type = "trojan"
		in.TrojanOptions = option.TrojanInboundOptions{
			ListenOptions: listen,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
			Transport: &t,
			Multiplex: multiplex,
		}
		if c.SingOptions.FallBackConfigs != nil {
			// fallback handling
			fallback := c.SingOptions.FallBackConfigs.FallBack
			fallbackPort, err := strconv.Atoi(fallback.ServerPort)
			if err == nil {
				in.TrojanOptions.Fallback = &option.ServerOptions{
					Server:     fallback.Server,
					ServerPort: uint16(fallbackPort),
				}
			}
			fallbackForALPNMap := c.SingOptions.FallBackConfigs.FallBackForALPN
			fallbackForALPN := make(map[string]*option.ServerOptions, len(fallbackForALPNMap))
			if err := processFallback(c, fallbackForALPN); err == nil {
				in.TrojanOptions.FallbackForALPN = fallbackForALPN
			}
		}
	case "hysteria":
		in.Type = "hysteria"
		in.HysteriaOptions = option.HysteriaInboundOptions{
			ListenOptions: listen,
			UpMbps:        info.Common.Hysteria.UpMbps,
			DownMbps:      info.Common.Hysteria.DownMbps,
			Obfs:          info.Common.Hysteria.Obfs,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	case "hysteria2":
		in.Type = "hysteria2"
		var obfs *option.Hysteria2Obfs
		if info.Common.Hysteria2.ObfsType != "" && info.Common.Hysteria2.ObfsPassword != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     info.Common.Hysteria2.ObfsType,
				Password: info.Common.Hysteria2.ObfsPassword,
			}
		} else if info.Common.Hysteria2.ObfsType != "" {
			obfs = &option.Hysteria2Obfs{
				Type:     "salamander",
				Password: info.Common.Hysteria2.ObfsType,
			}
		}
		in.Hysteria2Options = option.Hysteria2InboundOptions{
			ListenOptions: listen,
			UpMbps:        info.Common.Hysteria2.UpMbps,
			DownMbps:      info.Common.Hysteria2.DownMbps,
			Obfs:          obfs,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &tls,
			},
		}
	}
	return in, nil
}

func (b *Sing) AddNode(tag string, info *panel.NodeInfo, config *conf.Options) error {
	c, err := getInboundOptions(tag, info, config)
	if err != nil {
		return err
	}

	in, err := inbound.New(
		b.ctx,
		b.box.Router(),
		b.logFactory.NewLogger(F.ToString("inbound/", c.Type, "[", tag, "]")),
		tag,
		c,
		nil,
	)
	if err != nil {
		return fmt.Errorf("init inbound error： %s", err)
	}
	err = in.Start()
	if err != nil {
		return fmt.Errorf("start inbound error: %s", err)
	}
	b.inbounds[tag] = in
	err = b.router.AddInbound(in)
	if err != nil {
		return fmt.Errorf("add inbound error: %s", err)
	}
	return nil
}

func (b *Sing) DelNode(tag string) error {
	err := b.inbounds[tag].Close()
	if err != nil {
		return fmt.Errorf("close inbound error: %s", err)
	}
	err = b.router.DelInbound(tag)
	if err != nil {
		return fmt.Errorf("delete inbound error: %s", err)
	}
	return nil
}
