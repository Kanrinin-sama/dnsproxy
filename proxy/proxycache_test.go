package proxy

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// mustCIDR parses s as a CIDR notation IP address and prefix length, failing
// tb on error.
func mustCIDR(tb testing.TB, s string) (n *net.IPNet) {
	tb.Helper()

	_, n, err := net.ParseCIDR(s)
	require.NoError(tb, err)

	return n
}

// newA returns a new A resource record with the given name and addr, failing
// tb on error.
func newA(tb testing.TB, name, addr string) (rr dns.RR) {
	tb.Helper()

	rr, err := dns.NewRR(name + " 300 IN A " + addr)
	require.NoError(tb, err)

	return rr
}

func TestCacheResp_scopeZero_keysOnRequestSubnet(t *testing.T) {
	p := mustNew(t, &Config{
		Logger:                 testLogger,
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheSizeBytes:         64 * 1024,
		TrustUpstreamScope:     false,
		CacheECSPrefix4:        24,
	})

	req := (&dns.Msg{}).SetQuestion("example.com.", dns.TypeA)
	resp := (&dns.Msg{}).SetReply(req)
	resp.Answer = []dns.RR{newA(t, "example.com.", "1.2.3.4")}

	// Client A in 203.0.113.0/24 — upstream returns no ECS (SCOPE unusable).
	dA := &DNSContext{Req: req, Res: resp, ReqECS: mustCIDR(t, "203.0.113.0/24")}
	p.cacheResp(dA)

	// Client B in 198.51.100.0/24 must NOT see A's entry.
	dB := &DNSContext{Req: req, ReqECS: mustCIDR(t, "198.51.100.0/24")}
	require.False(t, p.replyFromCache(dB), "client B must not hit client A's cache entry")

	// Client A must still hit its own.
	dA2 := &DNSContext{Req: req, ReqECS: mustCIDR(t, "203.0.113.0/24")}
	require.True(t, p.replyFromCache(dA2), "client A must hit its own cache entry")
}

func TestCacheResp_trustScope_keepsWildcard(t *testing.T) {
	p := mustNew(t, &Config{
		Logger:                 testLogger,
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheSizeBytes:         64 * 1024,
		TrustUpstreamScope:     true,
	})

	req := (&dns.Msg{}).SetQuestion("example.com.", dns.TypeA)
	resp := (&dns.Msg{}).SetReply(req)
	resp.Answer = []dns.RR{newA(t, "example.com.", "1.2.3.4")}

	p.cacheResp(&DNSContext{Req: req, Res: resp, ReqECS: mustCIDR(t, "203.0.113.0/24")})

	// With scope trusted, any subnet hits the wildcard entry.
	dB := &DNSContext{Req: req, ReqECS: mustCIDR(t, "198.51.100.0/24")}
	require.True(t, p.replyFromCache(dB), "wildcard entry must be visible to all clients")
}

func TestTruncateECS(t *testing.T) {
	got := truncateECS(mustCIDR(t, "203.0.113.55/32"), 24, 56)
	require.Equal(t, "203.0.113.0/24", got.String())

	// Never widens.  mustCIDR/[net.ParseCIDR] already masks the IP down to
	// the network address for the given prefix, hence 203.0.0.0, not
	// 203.0.113.0.
	got = truncateECS(mustCIDR(t, "203.0.113.0/16"), 24, 56)
	require.Equal(t, "203.0.0.0/16", got.String())

	// IPv6 uses prefix6, not prefix4, and family is detected from the
	// existing mask's bit length rather than assumed.
	got = truncateECS(mustCIDR(t, "2001:db8:1234:5678::/64"), 24, 56)
	require.Equal(t, "2001:db8:1234:5600::/56", got.String())

	// Never widens, IPv6 case.
	got = truncateECS(mustCIDR(t, "2001:db8::/32"), 24, 56)
	require.Equal(t, "2001:db8::/32", got.String())
}
