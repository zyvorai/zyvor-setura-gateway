package gateway

// kind names the transport a port group needs, so a reload can tell when a
// bound socket must be replaced.
func (pg *PortGroup) kind() string {
	switch {
	case pg.L4 != "":
		return pg.L4
	case pg.Passthrough:
		return "tls"
	case pg.TLS:
		return "https"
	}
	return "http"
}

// stampGenerations gives resources that carry no metadata.generation (snapshot
// files) the reload counter as their generation, like Gateways and routes.
func (c *Config) stampGenerations(seq int64) {
	for _, r := range c.ListenerSets {
		if r.Generation == 0 {
			r.Generation = seq
		}
	}
	for _, r := range c.BackendTLS {
		if r.Generation == 0 {
			r.Generation = seq
		}
	}
	for _, r := range c.TCPRoutes {
		if r.Generation == 0 {
			r.Generation = seq
		}
	}
	for _, r := range c.UDPRoutes {
		if r.Generation == 0 {
			r.Generation = seq
		}
	}
}
