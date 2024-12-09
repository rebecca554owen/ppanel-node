package xray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/goccy/go-json"
	"github.com/perfect-panel/ppanel-node/api/panel"
	"github.com/perfect-panel/ppanel-node/conf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// BuildInbound build Inbound config for different protocol
func buildInbound(option *conf.Options, nodeInfo *panel.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	in := &coreConf.InboundDetourConfig{}
	var err error
	var (
		port     uint16
		security string
		network  string
	)

	switch nodeInfo.Common.Protocol {
	case "Vless":
		port = uint16(nodeInfo.Common.Vless.Port)
		security = nodeInfo.Common.Vless.Security
		network = nodeInfo.Common.Vless.Network
	case "Vmess":
		port = uint16(nodeInfo.Common.Vmess.Port)
		security = nodeInfo.Common.Vmess.Security
		network = nodeInfo.Common.Vmess.Network
	case "Trojan":
		port = uint16(nodeInfo.Common.Trojan.Port)
		security = nodeInfo.Common.Trojan.Security
	case "Shadowsocks":
		port = uint16(nodeInfo.Common.Shadowsocks.Port)
		security = ""
	case "Hysteria":
		port = uint16(nodeInfo.Common.Hysteria.Port)
		security = "tls"
	case "Hysteria2":
		port = uint16(nodeInfo.Common.Hysteria2.Port)
		security = "tls"
	default:
		fmt.Println("Unknown protocol:", nodeInfo.Common.Protocol)
	}
	switch nodeInfo.Type {
	case "vless":
		err = buildV2ray(option, nodeInfo, in)
		network = nodeInfo.Common.Vless.Network
	case "vmess":
		err = buildV2ray(option, nodeInfo, in)
		network = nodeInfo.Common.Vmess.Network
	case "trojan":
		err = buildTrojan(option, nodeInfo, in)
		if nodeInfo.Common.Trojan.Network != "" {
			network = nodeInfo.Common.Trojan.Network
		} else {
			network = "tcp"
		}
	case "shadowsocks":
		err = buildShadowsocks(option, nodeInfo, in)
		network = "tcp"
	default:
		return nil, fmt.Errorf("unsupported node type: %s, Only support: V2ray, Trojan, Shadowsocks", nodeInfo.Type)
	}
	if err != nil {
		return nil, err
	}
	// Set network protocol
	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: uint32(port),
				To:   uint32(port),
			}},
	}
	// Set Listen IP address
	ipAddress := net.ParseAddress(option.ListenIP)
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig
	sniffingConfig := &coreConf.SniffingConfig{
		Enabled:      true,
		DestOverride: &coreConf.StringList{"http", "tls"},
	}
	if option.XrayOptions.DisableSniffing {
		sniffingConfig.Enabled = false
	}
	in.SniffingConfig = sniffingConfig
	switch network {
	case "tcp":
		if in.StreamSetting.TCPSettings != nil {
			in.StreamSetting.TCPSettings.AcceptProxyProtocol = option.XrayOptions.EnableProxyProtocol
		} else {
			tcpSetting := &coreConf.TCPConfig{
				AcceptProxyProtocol: option.XrayOptions.EnableProxyProtocol,
			} //Enable proxy protocol
			in.StreamSetting.TCPSettings = tcpSetting
		}
	case "ws":
		if in.StreamSetting.WSSettings != nil {
			in.StreamSetting.WSSettings.AcceptProxyProtocol = option.XrayOptions.EnableProxyProtocol
		} else {
			in.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
				AcceptProxyProtocol: option.XrayOptions.EnableProxyProtocol,
			} //Enable proxy protocol
		}
	default:
		socketConfig := &coreConf.SocketConfig{
			AcceptProxyProtocol: option.XrayOptions.EnableProxyProtocol,
			TFO:                 option.XrayOptions.EnableTFO,
		} //Enable proxy protocol
		in.StreamSetting.SocketSettings = socketConfig
	}
	// Set TLS or Reality settings
	switch security {
	case "tls":
		// Normal tls
		if option.CertConfig == nil {
			return nil, errors.New("the CertConfig is not vail")
		}
		switch option.CertConfig.CertMode {
		case "none", "":
			break // disable
		default:
			in.StreamSetting.Security = "tls"
			in.StreamSetting.TLSSettings = &coreConf.TLSConfig{
				Certs: []*coreConf.TLSCertConfig{
					{
						CertFile:     option.CertConfig.CertFile,
						KeyFile:      option.CertConfig.KeyFile,
						OcspStapling: 3600,
					},
				},
				RejectUnknownSNI: option.CertConfig.RejectUnknownSni,
			}
		}
	case "reality":
		// Reality
		in.StreamSetting.Security = "reality"
		v := nodeInfo.Common.Vless
		dest := v.SecurityConfig.ServerAddress
		if dest == "" {
			dest = v.SecurityConfig.ServerName
		}
		xver, _ := strconv.Atoi(v.SecurityConfig.ProxyProtocol)

		d, err := json.Marshal(fmt.Sprintf(
			"%s:%d",
			dest,
			v.SecurityConfig.ServerPort))
		if err != nil {
			return nil, fmt.Errorf("marshal reality dest error: %s", err)
		}
		in.StreamSetting.REALITYSettings = &coreConf.REALITYConfig{
			Dest:        d,
			Xver:        uint64(xver),
			ServerNames: []string{v.SecurityConfig.ServerName},
			PrivateKey:  v.SecurityConfig.PrivateKey,
			ShortIds:    []string{v.SecurityConfig.ShortID},
		}
	default:
		break
	}
	in.Tag = tag
	return in.Build()
}

func buildV2ray(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	var v *panel.VAllssNode
	if nodeInfo.Type == "vless" {
		v = nodeInfo.Common.Vless
		//Set vless
		inbound.Protocol = "vless"
		if config.XrayOptions.EnableFallback {
			// Set fallback
			fallbackConfigs, err := buildVlessFallbacks(config.XrayOptions.FallBackConfigs)
			if err != nil {
				return err
			}
			s, err := json.Marshal(&coreConf.VLessInboundConfig{
				Decryption: "none",
				Fallbacks:  fallbackConfigs,
			})
			if err != nil {
				return fmt.Errorf("marshal vless fallback config error: %s", err)
			}
			inbound.Settings = (*json.RawMessage)(&s)
		} else {
			var err error
			s, err := json.Marshal(&coreConf.VLessInboundConfig{
				Decryption: "none",
			})
			if err != nil {
				return fmt.Errorf("marshal vless config error: %s", err)
			}
			inbound.Settings = (*json.RawMessage)(&s)
		}
	} else {
		// Set vmess
		inbound.Protocol = "vmess"
		v = nodeInfo.Common.Vmess
		var err error
		s, err := json.Marshal(&coreConf.VMessInboundConfig{})
		if err != nil {
			return fmt.Errorf("marshal vmess settings error: %s", err)
		}
		inbound.Settings = (*json.RawMessage)(&s)
	}
	if len(v.Transport) == 0 {
		return nil
	}

	t := coreConf.TransportProtocol(v.Network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch v.Network {
	case "tcp":
		err := json.Unmarshal(v.Transport, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.Transport, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.Transport, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	case "httpupgrade":
		err := json.Unmarshal(v.Transport, &inbound.StreamSetting.HTTPUPGRADESettings)
		if err != nil {
			return fmt.Errorf("unmarshal httpupgrade settings error: %s", err)
		}
	case "splithttp", "xhttp":
		err := json.Unmarshal(v.Transport, &inbound.StreamSetting.SplitHTTPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal xhttp settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildTrojan(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "trojan"
	v := nodeInfo.Common.Trojan
	if config.XrayOptions.EnableFallback {
		// Set fallback
		fallbackConfigs, err := buildTrojanFallbacks(config.XrayOptions.FallBackConfigs)
		if err != nil {
			return err
		}
		s, err := json.Marshal(&coreConf.TrojanServerConfig{
			Fallbacks: fallbackConfigs,
		})
		inbound.Settings = (*json.RawMessage)(&s)
		if err != nil {
			return fmt.Errorf("marshal trojan fallback config error: %s", err)
		}
	} else {
		s := []byte("{}")
		inbound.Settings = (*json.RawMessage)(&s)
	}
	network := v.Network
	if network == "" {
		network = "tcp"
	}
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch network {
	case "tcp":
		err := json.Unmarshal(v.Transport, &inbound.StreamSetting.TCPSettings)
		if err != nil {
			return fmt.Errorf("unmarshal tcp settings error: %s", err)
		}
	case "ws":
		err := json.Unmarshal(v.Transport, &inbound.StreamSetting.WSSettings)
		if err != nil {
			return fmt.Errorf("unmarshal ws settings error: %s", err)
		}
	case "grpc":
		err := json.Unmarshal(v.Transport, &inbound.StreamSetting.GRPCSettings)
		if err != nil {
			return fmt.Errorf("unmarshal grpc settings error: %s", err)
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildShadowsocks(config *conf.Options, nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	s := nodeInfo.Common.Shadowsocks
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: s.Cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)
	cipher := s.Cipher
	if s.ServerKey != "" {
		settings.Password = s.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}
	settings.IVCheck = true
	if config.XrayOptions.DisableIVCheck {
		settings.IVCheck = false
	}
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}

func buildVlessFallbacks(fallbackConfigs []conf.FallBackConfigForXray) ([]*coreConf.VLessInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}
	vlessFallBacks := make([]*coreConf.VLessInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {
		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback fialed")
		}
		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		vlessFallBacks[i] = &coreConf.VLessInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return vlessFallBacks, nil
}

func buildTrojanFallbacks(fallbackConfigs []conf.FallBackConfigForXray) ([]*coreConf.TrojanInboundFallback, error) {
	if fallbackConfigs == nil {
		return nil, fmt.Errorf("you must provide FallBackConfigs")
	}

	trojanFallBacks := make([]*coreConf.TrojanInboundFallback, len(fallbackConfigs))
	for i, c := range fallbackConfigs {

		if c.Dest == "" {
			return nil, fmt.Errorf("dest is required for fallback fialed")
		}

		var dest json.RawMessage
		dest, err := json.Marshal(c.Dest)
		if err != nil {
			return nil, fmt.Errorf("marshal dest %s config fialed: %s", dest, err)
		}
		trojanFallBacks[i] = &coreConf.TrojanInboundFallback{
			Name: c.SNI,
			Alpn: c.Alpn,
			Path: c.Path,
			Dest: dest,
			Xver: c.ProxyProtocolVer,
		}
	}
	return trojanFallBacks, nil
}
