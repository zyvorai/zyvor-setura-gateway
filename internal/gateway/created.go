package gateway

import (
	"fmt"
	"time"
)

// creationMeta lets a snapshot or config file give a route a creation time,
// which breaks otherwise exact ties (Gateway API: the oldest route wins).
// metadata.creationTimestamp is read first, then a top-level creationTimestamp,
// both RFC 3339 as in a Kubernetes object. Without either the zero time is
// used, which sorts before any real time, and name order decides among routes
// that have none.
type creationMeta struct {
	Metadata struct {
		CreationTimestamp string `json:"creationTimestamp"`
	} `json:"metadata"`
	CreationTimestamp string `json:"creationTimestamp"`
}

func (c creationMeta) created() (time.Time, error) {
	v, field := c.Metadata.CreationTimestamp, "metadata.creationTimestamp"
	if v == "" {
		v, field = c.CreationTimestamp, "creationTimestamp"
	}
	if v == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %q is not an RFC 3339 time", field, v)
	}
	return t, nil
}
