package gateway

// carryState moves health, ejection and probe state from the table being
// replaced into the new one, for every endpoint that still exists. An
// endpoint is identified by its backend key and its address (scheme and
// host:port), so a reload that merely edits a route, adds a backend or
// reorders endpoints no longer resets what the gateway has learned. The new
// backend adopts the old endpoint object itself, together with the mutex that
// guards its state, so requests still in flight on the old table and requests
// on the new one update the same counters. Circuit breakers, retry budgets
// and counters are keyed by backend in the resilience state and already
// survive a reload.
func (s *Server) carryState(old, next *Table) {
	if old == nil || next == nil {
		return
	}
	now := s.res.now()
	for key, nb := range next.Backends {
		ob := old.Backends[key]
		if ob == nil {
			continue
		}
		nb.hmu = ob.hmu
		byAddr := make(map[string]*Endpoint, len(ob.Eps))
		for _, e := range ob.Eps {
			byAddr[e.URL.String()] = e
		}
		checked := s.healthConfigFor(nb) != nil
		nb.hmu.Lock()
		for i, e := range nb.Eps {
			prev := byAddr[e.URL.String()]
			if prev == nil {
				e.added = now // slow start for an endpoint that joined a running gateway
				continue
			}
			prev.weight, prev.Zone, prev.Priority = e.weight, e.Zone, e.Priority // the new configuration wins
			if !checked {
				// No active check to ever flip it back: drop a stale "down".
				prev.healthy.Store(true)
				prev.st.actFail, prev.st.actOK = 0, 0
			}
			nb.Eps[i] = prev
		}
		nb.hmu.Unlock()
		nb.rr.Store(ob.rr.Load())
		nb.indexTiers()
	}
}
