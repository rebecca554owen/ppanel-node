package sing

import (
	"context"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/log"

	"github.com/goccy/go-json"
	"github.com/perfect-panel/ppanel-node/conf"
	vCore "github.com/perfect-panel/ppanel-node/core"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

var _ vCore.Core = (*Sing)(nil)

type DNSConfig struct {
	Servers []map[string]interface{} `json:"servers"`
	Rules   []map[string]interface{} `json:"rules"`
}

type Sing struct {
	box        *box.Box
	ctx        context.Context
	hookServer *HookServer
	router     adapter.Router
	logFactory log.Factory
	inbounds   map[string]adapter.Inbound
}

func init() {
	vCore.RegisterCore("sing", New)
}

func New(c *conf.CoreConfig) (vCore.Core, error) {
	options := option.Options{}
	if len(c.SingConfig.OriginalPath) != 0 {
		data, err := os.ReadFile(c.SingConfig.OriginalPath)
		if err != nil {
			return nil, fmt.Errorf("read original config error: %s", err)
		}
		err = json.Unmarshal(data, &options)
		if err != nil {
			return nil, fmt.Errorf("unmarshal original config error: %s", err)
		}
	}
	options.Log = &option.LogOptions{
		Disabled:  c.SingConfig.LogConfig.Disabled,
		Level:     c.SingConfig.LogConfig.Level,
		Timestamp: c.SingConfig.LogConfig.Timestamp,
		Output:    c.SingConfig.LogConfig.Output,
	}
	options.NTP = &option.NTPOptions{
		Enabled:       c.SingConfig.NtpConfig.Enable,
		WriteToSystem: true,
		ServerOptions: option.ServerOptions{
			Server:     c.SingConfig.NtpConfig.Server,
			ServerPort: c.SingConfig.NtpConfig.ServerPort,
		},
	}
	os.Setenv("SING_DNS_PATH", "")
	b, err := box.New(box.Options{
		Context: context.Background(),
		Options: options,
	})
	if err != nil {
		return nil, err
	}
	hs := NewHookServer(b.Router().GetCtx(), c.SingConfig.EnableConnClear)
	b.Router().SetClashServer(hs)
	return &Sing{
		ctx:        b.Router().GetCtx(),
		box:        b,
		hookServer: hs,
		router:     b.Router(),
		logFactory: b.LogFactory(),
		inbounds:   make(map[string]adapter.Inbound),
	}, nil
}

func (b *Sing) Start() error {
	return b.box.Start()
}

func (b *Sing) Close() error {
	return b.box.Close()
}

func (b *Sing) Protocols() []string {
	return []string{
		"vmess",
		"vless",
		"shadowsocks",
		"trojan",
		"hysteria",
		"hysteria2",
	}
}

func (b *Sing) Type() string {
	return "sing"
}
