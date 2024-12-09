package sing

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/common/urltest"

	"github.com/perfect-panel/ppanel-node/common/format"
	"github.com/perfect-panel/ppanel-node/common/rate"

	"github.com/perfect-panel/ppanel-node/limiter"

	"github.com/perfect-panel/ppanel-node/common/counter"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var _ adapter.ClashServer = (*HookServer)(nil)

type HookServer struct {
	ctx             context.Context
	urlTestHistory  *urltest.HistoryStorage
	EnableConnClear bool
	counter         sync.Map
	connClears      sync.Map
}

type ConnClear struct {
	lock  sync.RWMutex
	conns map[int]io.Closer
}

func (c *ConnClear) AddConn(cn io.Closer) (key int) {
	c.lock.Lock()
	defer c.lock.Unlock()
	key = len(c.conns)
	c.conns[key] = cn
	return
}

func (c *ConnClear) DelConn(key int) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.conns, key)
}

func (c *ConnClear) ClearConn() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, c := range c.conns {
		c.Close()
	}
}

func (h *HookServer) ModeList() []string {
	return nil
}

func NewHookServer(ctx context.Context, enableClear bool) *HookServer {
	server := &HookServer{
		ctx:             ctx,
		EnableConnClear: enableClear,
		counter:         sync.Map{},
		connClears:      sync.Map{},
	}
	server.urlTestHistory = service.PtrFromContext[urltest.HistoryStorage](ctx)
	if server.urlTestHistory == nil {
		server.urlTestHistory = urltest.NewHistoryStorage()
	}
	return server
}

func (h *HookServer) Start() error {
	return nil
}

func (h *HookServer) Close() error {
	h.urlTestHistory.Close()
	return nil
}

func (h *HookServer) PreStart() error {
	return nil
}

func (h *HookServer) RoutedConnection(_ context.Context, conn net.Conn, m adapter.InboundContext, _ adapter.Rule) (net.Conn, adapter.Tracker) {
	t := &Tracker{}
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		return conn, t
	}
	ip := m.Source.Addr.String()
	if b, r := l.CheckLimit(format.UserTag(m.Inbound, m.User), ip, true, true); r {
		conn.Close()
		log.Error("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return conn, t
	} else if b != nil {
		conn = rate.NewConnRateLimiter(conn, b)
	}
	t.AddLeave(func() {
		l.ConnLimiter.DelConnCount(m.User, ip)
	})
	if h.EnableConnClear {
		var key int
		cc := &ConnClear{
			conns: map[int]io.Closer{
				0: conn,
			},
		}
		if v, ok := h.connClears.LoadOrStore(m.Inbound+m.User, cc); ok {
			cc = v.(*ConnClear)
			key = cc.AddConn(conn)
		}
		t.AddLeave(func() {
			cc.DelConn(key)
		})
	}
	if c, ok := h.counter.Load(m.Inbound); ok {
		return counter.NewConnCounter(conn, c.(*counter.TrafficCounter).GetCounter(m.User)), t
	} else {
		c := counter.NewTrafficCounter()
		h.counter.Store(m.Inbound, c)
		return counter.NewConnCounter(conn, c.GetCounter(m.User)), t
	}
}

func (h *HookServer) RoutedPacketConnection(_ context.Context, conn N.PacketConn, m adapter.InboundContext, _ adapter.Rule) (N.PacketConn, adapter.Tracker) {
	t := &Tracker{}
	l, err := limiter.GetLimiter(m.Inbound)
	if err != nil {
		log.Warn("get limiter for ", m.Inbound, " error: ", err)
		return conn, t
	}
	ip := m.Source.Addr.String()
	if b, r := l.CheckLimit(format.UserTag(m.Inbound, m.User), ip, false, false); r {
		conn.Close()
		log.Error("[", m.Inbound, "] ", "Limited ", m.User, " by ip or conn")
		return conn, t
	} else if b != nil {
		//conn = rate.NewPacketConnCounter(conn, b)
	}
	if h.EnableConnClear {
		var key int
		cc := &ConnClear{
			conns: map[int]io.Closer{
				0: conn,
			},
		}
		if v, ok := h.connClears.LoadOrStore(m.Inbound+m.User, cc); ok {
			cc = v.(*ConnClear)
			key = cc.AddConn(conn)
		}
		t.AddLeave(func() {
			cc.DelConn(key)
		})
	}
	if c, ok := h.counter.Load(m.Inbound); ok {
		return counter.NewPacketConnCounter(conn, c.(*counter.TrafficCounter).GetCounter(m.User)), t
	} else {
		c := counter.NewTrafficCounter()
		h.counter.Store(m.Inbound, c)
		return counter.NewPacketConnCounter(conn, c.GetCounter(m.User)), t
	}
}

// not need

func (h *HookServer) Mode() string {
	return ""
}
func (h *HookServer) StoreSelected() bool {
	return false
}
func (h *HookServer) CacheFile() adapter.CacheFile {
	return nil
}
func (h *HookServer) HistoryStorage() *urltest.HistoryStorage {
	return h.urlTestHistory
}

func (h *HookServer) StoreFakeIP() bool {
	return false
}

func (h *HookServer) ClearConn(inbound string, user string) {
	if v, ok := h.connClears.Load(inbound + user); ok {
		v.(*ConnClear).ClearConn()
		h.connClears.Delete(inbound + user)
	}
}

type Tracker struct {
	l []func()
}

func (t *Tracker) AddLeave(f func()) {
	t.l = append(t.l, f)
}

func (t *Tracker) Leave() {
	for i := range t.l {
		t.l[i]()
	}
}
