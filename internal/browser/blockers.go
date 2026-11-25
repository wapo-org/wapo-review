package browser

type Blocker struct {
	Kind              string `json:"kind"`
	Summary           string `json:"summary"`
	Evidence          string `json:"evidence,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
}
type RunTelemetry struct {
	BrowserCheckExecutions int
	BrowserCheckFailures   int
	ScreenshotsCaptured    int
	ContactSheetCaptured   bool
	Rollbacks              int
}

func SuppressFalseBlockers(blockers []Blocker, telemetry RunTelemetry) (kept, suppressed []Blocker) {
	validated := telemetry.BrowserCheckExecutions > telemetry.BrowserCheckFailures || telemetry.ContactSheetCaptured
	for _, b := range blockers {
		if validated && (b.Kind == "browser_runtime" || b.Kind == "development_preview" || b.Kind == "test_account") {
			b.SuppressionReason = "validated browser or contact-sheet evidence exists"
			suppressed = append(suppressed, b)
		} else {
			kept = append(kept, b)
		}
	}
	return
}
