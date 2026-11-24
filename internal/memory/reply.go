package memory

import (
	"regexp"
	"strings"
)

var remember = regexp.MustCompile(`(?is)^\s*remember(?:\s*\(\s*([a-z_]+)\s*\))?\s*:\s*(.*?)\s*$`)

func ParseRememberCommand(instructions string) (string, string, bool) {
	m := remember.FindStringSubmatch(instructions)
	if m == nil {
		return "", "", false
	}
	scope := strings.ToLower(m[1])
	if scope == "" {
		scope = "all"
	}
	text := strings.Join(strings.Fields(m[2]), " ")
	valid := false
	for _, v := range ValidScopes {
		valid = valid || v == scope
	}
	return scope, text, valid && text != ""
}

var acknowledgements = regexp.MustCompile(`(?i)^(fixed|done|thanks?|thank you|lgtm|good catch|ok|pushed|resolved|will fix|addressed)[.!\s]*$`)
var durable = regexp.MustCompile(`(?i)\b(remember|note for future|for future reviews|from now on|keep in mind|always|never|do not flag|don't flag|do not report|don't report|by design|intentional|in this repo|in this repository|we use|prefer)\b`)

func ExtractMemoryFromReply(body string, isInlineReviewReply bool) (string, string, bool) {
	if scope, text, ok := ParseRememberCommand(body); ok {
		return scope, text, true
	}
	lines := strings.Split(body, "\n")
	clean := make([]string, 0, len(lines))
	for _, l := range lines {
		if !strings.HasPrefix(strings.TrimSpace(l), ">") {
			clean = append(clean, l)
		}
	}
	text := strings.Join(strings.Fields(strings.Join(clean, " ")), " ")
	if len(text) < 12 || acknowledgements.MatchString(text) || !durable.MatchString(text) || strings.HasSuffix(text, "?") {
		return "", "", false
	}
	low := strings.ToLower(text)
	scope := "all"
	if strings.Contains(low, "preview") || strings.Contains(low, "browser") || strings.Contains(low, "playwright") || strings.Contains(low, "vault") {
		scope = "hands_on"
	} else if strings.Contains(low, "screenshot") || strings.Contains(low, "visual") {
		scope = "visual_review"
	} else if isInlineReviewReply {
		scope = "code_review"
	}
	return scope, truncateRunes(text, MaxNoteChars), true
}
