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

func TestCacheResp_echoedScopeZero_keysOnRequestSubnet(t *testing.T) {
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

	// Client A in 203.0.113.0/24 — upstream echoes the SUBNET option with
	// SOURCE=24 (matching the request, as [setECS] always does for IPv4) but
	// SCOPE=0, which RFC 7871 Section 7.3.1 defines as "valid for all
	// addresses".  This is the shape Quad9 (9.9.9.11) actually returns.
	resp := (&dns.Msg{}).SetReply(req)
	resp.Answer = []dns.RR{newA(t, "example.com.", "1.2.3.4")}
	setECS(resp, net.ParseIP("203.0.113.0"), 0)

	dA := &DNSContext{Req: req, Res: resp, ReqECS: mustCIDR(t, "203.0.113.0/24")}
	p.cacheResp(dA)

	// Client B in 198.51.100.0/24 must NOT see A's entry.
	dB := &DNSContext{Req: req, ReqECS: mustCIDR(t, "198.51.100.0/24")}
	require.False(t, p.replyFromCache(dB), "client B must not hit client A's cache entry")

	// Client A must still hit its own.
	dA2 := &DNSContext{Req: req, ReqECS: mustCIDR(t, "203.0.113.0/24")}
	require.True(t, p.replyFromCache(dA2), "client A must hit its own cache entry")
}

func TestCacheResp_honestPartialScope_stillWidens(t *testing.T) {
	p := mustNew(t, &Config{
		Logger:                 testLogger,
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheSizeBytes:         64 * 1024,
		// Must not matter: a non-zero scope is trusted regardless of this
		// setting.
		TrustUpstreamScope: false,
		CacheECSPrefix4:    24,
	})

	req := (&dns.Msg{}).SetQuestion("example.com.", dns.TypeA)

	// Client A in 203.0.113.0/24 — upstream reports an honest partial scope
	// of /23, one bit broader than the request (e.g. Google returns
	// /24/23).  This must widen exactly as it did before TrustUpstreamScope
	// existed; a non-zero scope is not the "valid for all addresses" claim.
	resp := (&dns.Msg{}).SetReply(req)
	resp.Answer = []dns.RR{newA(t, "example.com.", "1.2.3.4")}
	setECS(resp, net.ParseIP("203.0.113.0"), 23)

	dA := &DNSContext{Req: req, Res: resp, ReqECS: mustCIDR(t, "203.0.113.0/24")}
	p.cacheResp(dA)

	// A neighbouring /24 that falls within the reported /23 must see the
	// entry.
	dC := &DNSContext{Req: req, ReqECS: mustCIDR(t, "203.0.112.0/24")}
	require.True(t, p.replyFromCache(dC), "neighbouring /24 within the reported /23 scope must hit the entry")
}

// TestCacheResp_longReqPrefix_truncatedKeyIsReadable makes sure a response
// stored under the truncated request subnet is reachable by the
// longest-prefix walk of [cache.getWithSubnet], which starts from the
// untruncated request subnet.  The walk used to keep the high bit of the last
// significant octet when it crossed a byte boundary, so for roughly half of
// all addresses it never probed the key [Proxy.cacheResp] had written.
func TestCacheResp_longReqPrefix_truncatedKeyIsReadable(t *testing.T) {
	testCases := []struct {
		name   string
		reqECS string
	}{{
		name: "ipv4",
		// The last octet is 200, i.e. its high bit is set, so the /25 probe
		// leaves 203.0.113.128 behind when descending to /24.
		reqECS: "203.0.113.200/32",
	}, {
		name: "ipv6",
		// Likewise, the eighth octet is 0xFF, so the /57 probe leaves
		// 2001:db8:1234:5680:: behind when descending to /56.
		reqECS: "2001:db8:1234:56ff::1/128",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustNew(t, &Config{
				Logger:                 testLogger,
				UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
				EnableEDNSClientSubnet: true,
				CacheEnabled:           true,
				CacheSizeBytes:         64 * 1024,
				TrustUpstreamScope:     false,
			})

			req := (&dns.Msg{}).SetQuestion("example.com.", dns.TypeA)
			resp := (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{newA(t, "example.com.", "1.2.3.4")}

			p.cacheResp(&DNSContext{Req: req, Res: resp, ReqECS: mustCIDR(t, tc.reqECS)})

			d := &DNSContext{Req: req, ReqECS: mustCIDR(t, tc.reqECS)}
			require.True(t, p.replyFromCache(d), "the truncated key must be readable")
		})
	}
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

func TestCache_perClientECSOverridesGlobal(t *testing.T) {
	// Global ECS on, but this client has it off: it must use the general
	// cache, not the subnet cache.
	p := mustNew(t, &Config{
		Logger:                 testLogger,
		UpstreamConfig:         newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		EnableEDNSClientSubnet: true,
		CacheEnabled:           true,
		CacheSizeBytes:         64 * 1024,
	})

	cfg := NewCustomUpstreamConfig(nil, true, 64*1024, false, "")
	require.False(t, p.ecsForContext(&DNSContext{CustomUpstreamConfig: cfg}))
	require.True(t, p.ecsForContext(&DNSContext{}))
}
