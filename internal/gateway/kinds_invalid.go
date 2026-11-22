package gateway

// invalidKinds names the allowedRoutes.kinds entries the listener's protocol
// cannot carry (Gateway API reason InvalidRouteKinds).
func (l *RTListener) invalidKinds() []string {
	ar := l.L.AllowedRoutes
	if ar == nil {
		return nil
	}
	var bad []string
	for _, k := range ar.Kinds {
		ok := false
		if k.Group == "" || k.Group == APIGroup {
			for _, pk := range protocolKinds(l.L.Protocol) {
				ok = ok || pk == k.Kind
			}
		}
		if !ok {
			bad = append(bad, k.Kind)
		}
	}
	return bad
}
