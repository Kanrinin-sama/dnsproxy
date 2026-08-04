package proxy

import (
	"context"
	"net"
	"slices"
)

// cacheForContext returns cache object for the given context.  d must not be nil.
func (p *Proxy) cacheForContext(d *DNSContext) (c *cache) {
	if d.CustomUpstreamConfig != nil && d.CustomUpstreamConfig.cache != nil {
		return d.CustomUpstreamConfig.cache
	}

	return p.cache
}

// ecsForContext reports whether ECS handling applies to d, preferring the
// client's own setting over the proxy-wide one.
func (p *Proxy) ecsForContext(d *DNSContext) (ok bool) {
	if d.CustomUpstreamConfig != nil {
		return d.CustomUpstreamConfig.ECSEnabled()
	}

	return p.enableEDNSClientSubnet
}

// replyFromCache tries to get the response from general or subnet cache.  In
// case the cache is present in d, it's used first.  Returns true on success.  d
// must not be nil.
func (p *Proxy) replyFromCache(ctx context.Context, d *DNSContext) (hit bool) {
	dctxCache := p.cacheForContext(d)

	var ci *cacheItem
	var cacheSource string
	var expired bool
	var key []byte

	ecsEnabled := p.ecsForContext(d)
	if ecsEnabled && d.ReqECS != nil {
		ci, expired, key = dctxCache.getWithSubnet(d.Req, d.ReqECS)
		cacheSource = "subnet cache"
	} else {
		ci, expired, key = dctxCache.get(d.Req)
		cacheSource = "general cache"
	}

	if hit = ci != nil; !hit {
		return hit
	}

	d.Res = ci.m
	d.queryStatistics = cachedQueryStatistics(ci.u)

	p.logger.DebugContext(
		ctx,
		"replying from cache",
		"source", cacheSource,
		"ecs_enabled", ecsEnabled,
	)

	if dctxCache.optimistic && expired {
		// Build a reduced clone of the current context to avoid data race.
		minCtxClone := &DNSContext{
			// It is only read inside the optimistic resolver.
			CustomUpstreamConfig: d.CustomUpstreamConfig,
			ReqECS:               cloneIPNet(d.ReqECS),
			IsPrivateClient:      d.IsPrivateClient,
		}
		if d.Req != nil {
			minCtxClone.Req = d.Req.Copy()
		}

		go p.shortFlighter.resolveOnce(ctx, minCtxClone, key, p.logger)
	}

	return hit
}

// cloneIPNet returns a deep clone of n.
func cloneIPNet(n *net.IPNet) (clone *net.IPNet) {
	if n == nil {
		return nil
	}

	return &net.IPNet{
		IP:   slices.Clone(n.IP),
		Mask: slices.Clone(n.Mask),
	}
}

// cacheResp stores the response from d in general or subnet cache.  In case the
// cache is present in d, it's used first.  d must not be nil.
func (p *Proxy) cacheResp(d *DNSContext) {
	dctxCache := p.cacheForContext(d)

	if !p.ecsForContext(d) {
		dctxCache.set(d.Req, d.Res, d.Upstream, p.logger)

		return
	}

	switch ecs, scope := ecsFromMsg(d.Res); {
	case ecs != nil && d.ReqECS != nil:
		ones, bits := ecs.Mask.Size()
		reqOnes, _ := d.ReqECS.Mask.Size()

		// If FAMILY, SOURCE PREFIX-LENGTH, and SOURCE PREFIX-LENGTH bits of
		// ADDRESS in the response don't match the non-zero fields in the
		// corresponding query, the full response MUST be dropped.
		//
		// See RFC 7871 Section 7.3.
		//
		// TODO(a.meshkov):  The whole response MUST be dropped if ECS in it
		// doesn't correspond.
		if !ecs.IP.Mask(ecs.Mask).Equal(d.ReqECS.IP.Mask(d.ReqECS.Mask)) || ones != reqOnes {
			p.logger.Debug(
				"not caching response; subnet mismatch",
				"ecs", ecs,
				"req_ecs", d.ReqECS,
			)

			return
		}

		// A SCOPE PREFIX-LENGTH of zero is RFC 7871 Section 7.3.1's "valid for
		// all addresses" claim.  Forwarding resolvers that echo it while
		// still answering geo-specifically (Quad9 does) make that claim
		// unsafe to trust by default; key on the request's own subnet
		// instead.  A non-zero scope narrower than the request is a bounded,
		// honest claim and is always honoured below, regardless of
		// [Config.TrustUpstreamScope].
		if scope == 0 && !p.TrustUpstreamScope {
			key := truncateECS(d.ReqECS, p.CacheECSPrefix4, p.CacheECSPrefix6)
			p.logger.Debug("caching response keyed on request subnet", "ecs", key)
			dctxCache.setWithSubnet(d.Req, d.Res, d.Upstream, key, p.logger)

			break
		}

		// If SCOPE PREFIX-LENGTH is not longer than SOURCE PREFIX-LENGTH, store
		// SCOPE PREFIX-LENGTH bits of ADDRESS, and then mark the response as
		// valid for all addresses that fall within that range.
		//
		// See RFC 7871 Section 7.3.1.
		if scope < reqOnes {
			ecs.Mask = net.CIDRMask(scope, bits)
			ecs.IP = ecs.IP.Mask(ecs.Mask)
		}

		p.logger.Debug("caching response", "ecs", ecs)

		dctxCache.setWithSubnet(d.Req, d.Res, d.Upstream, ecs, p.logger)
	case d.ReqECS != nil:
		// The upstream's response carries no EDNS Client Subnet option at
		// all, so there's no SCOPE PREFIX-LENGTH to go by.  A response that
		// does echo the option, even with SCOPE=0, is handled above — this
		// case is strictly "the upstream said nothing".
		if p.TrustUpstreamScope {
			// Treat the absence of scope information the same way an
			// explicit SCOPE PREFIX-LENGTH of zero is treated above: valid
			// for all addresses.  This is the pre-existing behavior, but it
			// is not the default: [Config.TrustUpstreamScope] defaults to
			// false, so an existing configuration with ECS enabled starts
			// keying such responses on the request's own subnet.  That only
			// ever narrows the cache key, so the cost is hit rate, never a
			// wrong answer.
			dctxCache.setWithSubnet(d.Req, d.Res, d.Upstream, &net.IPNet{IP: nil, Mask: nil}, p.logger)

			break
		}

		// Key on the request's own subnet instead of caching for everyone;
		// see [Config.TrustUpstreamScope].
		key := truncateECS(d.ReqECS, p.CacheECSPrefix4, p.CacheECSPrefix6)
		p.logger.Debug("caching response keyed on request subnet", "ecs", key)
		dctxCache.setWithSubnet(d.Req, d.Res, d.Upstream, key, p.logger)
	default:
		dctxCache.set(d.Req, d.Res, d.Upstream, p.logger)
	}
}

// truncateECS returns n narrowed to the configured prefix length for its
// family.  It never widens: a request already narrower than the configured
// prefix is returned unchanged.
func truncateECS(n *net.IPNet, prefix4, prefix6 uint8) (out *net.IPNet) {
	ones, bits := n.Mask.Size()

	want := int(prefix4)
	if bits > net.IPv4len*8 {
		want = int(prefix6)
	}

	if ones <= want {
		return n
	}

	mask := net.CIDRMask(want, bits)

	return &net.IPNet{IP: n.IP.Mask(mask), Mask: mask}
}

// ClearCache clears the DNS cache of p.
func (p *Proxy) ClearCache() {
	if p.cache == nil {
		return
	}

	p.cache.clearItems()
	p.cache.clearItemsWithSubnet()
	p.logger.Debug("cache cleared")
}
