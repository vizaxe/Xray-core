package dns_test

import (
	"context"
	"encoding/binary"
	"io"
	gonet "net"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

// answerUnixQuery 解析查询并构造应答，只认 example.com 的 A/AAAA。
// 用例因此完全闭环在本地，不依赖外网 DNS，CI 与沙箱环境都能稳定通过。
func answerUnixQuery(query []byte) ([]byte, error) {
	req := new(dns.Msg)
	if err := req.Unpack(query); err != nil {
		return nil, err
	}

	ans := new(dns.Msg)
	// SetReply 会回填 Id 与 Question，比手工抄 Id 更不容易出错
	ans.SetReply(req)

	for _, q := range req.Question {
		switch {
		case q.Name == "example.com." && q.Qtype == dns.TypeA:
			rr, err := dns.NewRR("example.com. IN A 192.0.2.1")
			if err != nil {
				return nil, err
			}
			ans.Answer = append(ans.Answer, rr)
		case q.Name == "example.com." && q.Qtype == dns.TypeAAAA:
			rr, err := dns.NewRR("example.com. IN AAAA 2001:db8::1")
			if err != nil {
				return nil, err
			}
			ans.Answer = append(ans.Answer, rr)
		}
	}

	return ans.Pack()
}

// startUnixgramDNSServer 拉起一个 unixgram 服务端，返回 socket 路径。
//
// 这里刻意不用 miekg/dns 的 dns.Server：它的 ListenAndServe 只认 tcp/udp 系列，
// 对 unix / unixgram 会直接返回 "bad network"，NotifyStartedFunc 也就永远不会触发。
func startUnixgramDNSServer(t *testing.T) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "dns.sock")
	conn, err := gonet.ListenUnixgram("unixgram", &gonet.UnixAddr{Name: socketPath, Net: "unixgram"})
	common.Must(err)
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		query := make([]byte, 4096)
		for {
			n, remote, err := conn.ReadFromUnix(query)
			if err != nil {
				// socket 关闭即退出，测试收尾阶段无需上报
				return
			}
			resp, err := answerUnixQuery(query[:n])
			if err != nil {
				continue
			}
			if _, err := conn.WriteToUnix(resp, remote); err != nil {
				return
			}
		}
	}()

	return socketPath
}

// startUnixStreamDNSServer 拉起一个流式 unix socket 服务端，返回 socket 路径。
// 载荷沿用 DNS-over-TCP 的格式：2 字节大端长度前缀 + 报文。
func startUnixStreamDNSServer(t *testing.T) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "dns.sock")
	ln, err := gonet.Listen("unix", socketPath)
	common.Must(err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// listener 关闭即退出
				return
			}
			go func(c gonet.Conn) {
				defer c.Close()
				for {
					var length uint16
					if err := binary.Read(c, binary.BigEndian, &length); err != nil {
						return
					}
					query := make([]byte, length)
					if _, err := io.ReadFull(c, query); err != nil {
						return
					}
					resp, err := answerUnixQuery(query)
					if err != nil {
						return
					}
					if err := binary.Write(c, binary.BigEndian, uint16(len(resp))); err != nil {
						return
					}
					if _, err := c.Write(resp); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return socketPath
}

// TestUnixUDPNameServer 覆盖 unix+udp:// 这一路（DNS-over-UDP via Unix Domain Socket）。
// 它走自己实现的 UnixUDPNameServer：直接用 unixgram 拨号，不经过 dispatcher。
func TestUnixUDPNameServer(t *testing.T) {
	socketPath := startUnixgramDNSServer(t)

	u, err := url.Parse("unix+udp://" + socketPath)
	common.Must(err)
	s, err := NewUnixUDPNameServer(u, false, false, 0, net.IP(nil))
	common.Must(err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, _, err := s.QueryIP(ctx, "example.com", dns_feature.IPOption{IPv4Enable: true})
	common.Must(err)
	if len(ips) == 0 {
		t.Fatal("期望至少返回一个 IP，实际为 0")
	}
	if !ips[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("期望 192.0.2.1，实际 %v", ips[0])
	}
}

// TestUnixTCPNameServer 覆盖 unix:// 这一路（DNS-over-TCP via Unix Domain Socket）。
// 它复用上游 TCPNameServer，只把目标地址换成 UDS 路径，因此也顺带验证了
// DefaultSystemDialer 对 Network_UNIX 的拨号支持。
func TestUnixTCPNameServer(t *testing.T) {
	socketPath := startUnixStreamDNSServer(t)

	u, err := url.Parse("unix://" + socketPath)
	common.Must(err)
	s, err := NewUnixTCPNameServer(u, false, false, 0, net.IP(nil))
	common.Must(err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, _, err := s.QueryIP(ctx, "example.com", dns_feature.IPOption{IPv4Enable: true})
	common.Must(err)
	if len(ips) == 0 {
		t.Fatal("期望至少返回一个 IP，实际为 0")
	}
	if !ips[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("期望 192.0.2.1，实际 %v", ips[0])
	}
}
