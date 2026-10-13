package socks

import (
	"context"
	"io"
	gonet "net"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

// TestNetworkIncludesUnix 断言 Network() 同时声明 TCP 与 UNIX。
// proxyman 正是依据这个列表决定是否为该 inbound 创建 Unix Domain Socket 监听
// worker（见 app/proxyman/inbound/always.go），漏掉 UNIX 的话，UDS 上的连接
// 根本不会走到 Process。
func TestNetworkIncludesUnix(t *testing.T) {
	s := &Server{}
	networks := s.Network()

	if !net.HasNetwork(networks, net.Network_TCP) {
		t.Error("Network() 应当包含 TCP")
	}
	if !net.HasNetwork(networks, net.Network_UNIX) {
		t.Error("Network() 应当包含 UNIX")
	}
}

// recordingDispatcher 只把 DispatchLink 收到的目标记下来，供用例断言。
type recordingDispatcher struct {
	dest chan net.Destination
}

func (*recordingDispatcher) Type() interface{} { return routing.DispatcherType() }

func (*recordingDispatcher) Start() error { return nil }

func (*recordingDispatcher) Close() error { return nil }

func (*recordingDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	return nil, errors.New("Dispatch 在本用例中不应被调用")
}

func (d *recordingDispatcher) DispatchLink(_ context.Context, dest net.Destination, _ *transport.Link) error {
	d.dest <- dest
	return nil
}

// TestProcessOverUnixSocket 覆盖 UDS 入站全链路：
// 真实的 unix socket 连接 → Process(Network_UNIX) → socks5 握手 → DispatchLink。
// 它同时守住 processTCP 中「按 LocalAddr 实际类型取本端地址」那一分支——
// 若退回对 *net.TCPAddr 的强转，这里会直接 panic。
func TestProcessOverUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "socks.sock")
	ln, err := gonet.Listen("unix", socketPath)
	common.Must(err)
	defer ln.Close()

	s := &Server{
		config:        &ServerConfig{},
		policyManager: policy.DefaultManager{},
	}
	disp := &recordingDispatcher{dest: make(chan net.Destination, 1)}

	accepted := make(chan gonet.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	client, err := gonet.Dial("unix", socketPath)
	common.Must(err)
	defer client.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Name:    "socks",
		Gateway: net.TCPDestination(net.LocalHostIP, 1080),
		Source:  net.UnixDestination(net.ParseAddress(socketPath)),
	})

	// 客户端在另一条 goroutine 中走完 socks5 协商：
	// 方法选择（无认证）→ 读取方法响应 → CONNECT 127.0.0.1:8080 → 读取 CONNECT 响应。
	go func() {
		if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return
		}
		if _, err := io.ReadFull(client, make([]byte, 2)); err != nil {
			return
		}
		if _, err := client.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90}); err != nil {
			return
		}
		// IPv4 的 CONNECT 响应为 10 字节：VER + REP + RSV + ATYP + BND.ADDR(4) + BND.PORT(2)
		_, _ = io.ReadFull(client, make([]byte, 10))
	}()

	if err := s.Process(ctx, net.Network_UNIX, serverConn, disp); err != nil {
		t.Fatal("UDS 上的 socks 处理失败: ", err)
	}

	select {
	case dest := <-disp.dest:
		if dest.Address.String() != "127.0.0.1" || dest.Port != 8080 {
			t.Fatalf("期望分发到 127.0.0.1:8080，实际 %v", dest)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("超时未收到 DispatchLink 调用")
	}
}
