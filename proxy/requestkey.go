package proxy

type requestKey struct {
	upstreams *CustomUpstreamConfig
	query     string
}

func newRequestKey(d *DNSContext, query []byte) (key requestKey) {
	key.query = string(query)
	if d != nil {
		key.upstreams = d.CustomUpstreamConfig
	}
	return key
}

func pendingRequestKey(d *DNSContext) requestKey {
	if d.ReqECS != nil {
		ones, _ := d.ReqECS.Mask.Size()
		return newRequestKey(d, msgToKeyWithSubnet(d.Req, d.ReqECS.IP, ones))
	}
	return newRequestKey(d, msgToKey(d.Req))
}
