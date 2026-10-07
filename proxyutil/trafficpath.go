package proxyutil

import "context"

type TrafficPath string

const (
	TrafficPathLAN TrafficPath = "lan"
	TrafficPathWAN TrafficPath = "wan"
)

type trafficPathContextKey struct{}

func ContextWithTrafficPath(ctx context.Context, path TrafficPath) context.Context {
	return context.WithValue(ctx, trafficPathContextKey{}, path)
}

func TrafficPathFromContext(ctx context.Context) TrafficPath {
	if ctx == nil {
		return ""
	}
	path, _ := ctx.Value(trafficPathContextKey{}).(TrafficPath)
	return path
}

func (p TrafficPath) networkLabel() string {
	switch p {
	case TrafficPathLAN:
		return "LAN"
	case TrafficPathWAN:
		return "WAN"
	default:
		return "SYSTEM"
	}
}
