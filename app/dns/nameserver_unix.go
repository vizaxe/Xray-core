package dns

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol/dns"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

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

	reqs := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))

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
