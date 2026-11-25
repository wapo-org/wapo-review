package branding

import (
	"os"
	"regexp"
	"strings"
)

const (
	ProductName         = "Wapo Review"
	ServiceName         = "wapo-review"
	BotSlug             = "wapo-review"
	PrimaryCommand      = "/wapo-review"
	FindingMarkerPrefix = "<!-- wapo-review-finding:"
)

var ConfigFilenames = []string{".wapo-review.yml", ".wapo-review.yaml"}

func CommandPatternFor(botSlug string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(?:^|\s)/` + regexp.QuoteMeta(strings.TrimPrefix(botSlug, "/")) + `(?:\s|$)`)
}

func StateDir() string        { return envOr("WAPO_REVIEW_STATE_DIR", ".wapo-review") }
func CredentialsPath() string { return envOr("WAPO_REVIEW_CREDENTIALS_PATH", "") }
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
