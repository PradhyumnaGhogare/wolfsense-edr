package intel

import (
	"strings"

	"edr-platform/detection-engine/internal/model"
)

func MatchIndicators(feed map[string]model.ThreatIndicator, event model.TelemetryEvent) []model.ThreatIndicator {
	seen := map[string]struct{}{}
	var matches []model.ThreatIndicator

	for _, indicator := range extractIndicators(event) {
		normalized := strings.ToLower(strings.TrimSpace(indicator))
		if normalized == "" {
			continue
		}
		if item, ok := feed[normalized]; ok {
			if _, exists := seen[item.ID]; exists {
				continue
			}
			seen[item.ID] = struct{}{}
			matches = append(matches, item)
		}
	}

	return matches
}

func HighestSeverity(base string, matches []model.ThreatIndicator) string {
	severity := base
	for _, match := range matches {
		if severityRank(match.Severity) > severityRank(severity) {
			severity = match.Severity
		}
	}
	return severity
}

func extractIndicators(event model.TelemetryEvent) []string {
	indicators := []string{}
	if event.Network != nil {
		indicators = append(indicators, event.Network.RemoteIP)
	}
	if event.File != nil {
		indicators = append(indicators, event.File.HashSHA256)
	}
	return indicators
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
