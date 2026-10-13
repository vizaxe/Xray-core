package dns

import (
	"context"
	"fmt"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/dns"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/transport/internet"
)

// NewUnixTCPNameServer creates DNS over TCP (RFC 7766) client via Unix Domain Socket
// for local resolving. 与 NewUnixUDPNameServer 的差别只在传输层：本函数复用上游
// TCPNameServer 的报文/缓存逻辑，仅把目标地址换成 UDS 路径。
func NewUnixTCPNameServer(url *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*TCPNameServer, error) {
	// url.Path 形如 /var/run/dns.sock；抽象命名空间（如 @dns.sock）同样由
	// ParseAddress + UnixDestination 承接，无需在此特殊处理。
	dest := net.UnixDestination(net.ParseAddress(url.Path))
	s := &TCPNameServer{
		cacheController: NewCacheController("TCPUNIX//"+url.Path, disableCache, serveStale, serveExpiredTTL),
		destination:     &dest,
		clientIP:        clientIP,
	}
	// 与 tcp+local:// 一样走本机系统拨号；UDS 由 DefaultSystemDialer 统一处理，
	// 这里不必也不能再分支出专用逻辑。
	s.dial = func(ctx context.Context) (net.Conn, error) {
		return internet.DialSystem(ctx, dest, nil)
	}
	errors.LogInfo(context.Background(), "DNS: created Unix Domain Socket TCP client initialized for ", url.String())
	return s, nil
}

// UnixUDPNameServer implemented UDP DNS over Unix Domain Socket.
type UnixUDPNameServer struct {
	cacheController *CacheController
	path            string
	reqID           uint32
	clientIP        net.IP
}

// NewUnixUDPNameServer creates UDP over Unix Domain Socket client for local resolving.
func NewUnixUDPNameServer(u *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*UnixUDPNameServer, error) {
	s := &UnixUDPNameServer{
		cacheController: NewCacheController("UNIXUDP//"+u.Path, disableCache, serveStale, serveExpiredTTL),
		path:            u.Path,
		clientIP:        clientIP,
	}
	errors.LogInfo(context.Background(), "DNS: created Unix Domain Socket UDP client initialized for ", u.String())
	return s, nil
}

// Name implements Server.
func (s *UnixUDPNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *UnixUDPNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

// getCacheController implements CachedNameserver.
func (s *UnixUDPNameServer) getCacheController() *CacheController {
	return s.cacheController
}

func (s *UnixUDPNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

// sendQuery implements CachedNameserver.
func (s *UnixUDPNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying DNS for: ", fqdn)

	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		if noResponseErrCh != nil {
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			var cancel context.CancelFunc
			dnsCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()

			b, err := dns.PackMessage(r.msg)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack dns query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			defer b.Release()

			raddr := net.UnixAddr{Name: s.path, Net: "unixgram"}
			laddr := net.UnixAddr{Name: fmt.Sprintf("@xray-dns-%s-%d", s.path, s.newReqID()), Net: "unixgram"}
			conn, err := net.DialUnix("unixgram", &laddr, &raddr)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to dial unix domain socket")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			defer conn.Close()

			if dl, ok := dnsCtx.Deadline(); ok {
				conn.SetDeadline(dl)
			}

			_, err = conn.Write(b.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to send query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			respBuf := buf.New()
			defer respBuf.Release()
			_, err = respBuf.ReadFrom(conn)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to read response")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			rec, err := parseResponse(respBuf.Bytes())
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to parse DNS response")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			s.cacheController.updateRecord(r, rec)
		}(req)
	}
}

// QueryIP implements Server.
func (s *UnixUDPNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
