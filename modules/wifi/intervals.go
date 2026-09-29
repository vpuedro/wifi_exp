package wifi

import "time"

// Station freshness thresholds, inlined from the former net_recon module so the
// WiFi backend stands alone. Values match net_recon's originals.
const (
	AliveTimeInterval      = time.Duration(10) * time.Second
	PresentTimeInterval    = time.Duration(1) * time.Minute
	JustJoinedTimeInterval = time.Duration(10) * time.Second
)
