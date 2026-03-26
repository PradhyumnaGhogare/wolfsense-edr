package rules

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"time"

	"edr-platform/detection-engine/internal/intel"
	"edr-platform/detection-engine/internal/model"
)

const (
	ruleKindTelemetryMatch   = "telemetry_match"
	ruleKindThreatIntelMatch = "threat_intel_match"
)

type ruleEvaluator func(rule model.DetectionRule, event model.TelemetryEvent, indicatorMatches []model.ThreatIndicator) (model.Alert, bool)

func defaultEvaluators() map[string]ruleEvaluator {
	return map[string]ruleEvaluator{
		ruleKindTelemetryMatch:   evaluateTelemetryRule,
		ruleKindThreatIntelMatch: evaluateThreatIntelRule,
	}
}

func evaluateTelemetryRule(rule model.DetectionRule, event model.TelemetryEvent, indicatorMatches []model.ThreatIndicator) (model.Alert, bool) {
	if !matchesRule(rule, event) {
		return model.Alert{}, false
	}

	alert := buildAlert(rule, event, intel.HighestSeverity(rule.Severity, indicatorMatches))
	alert.Evidence = defaultEvidence(event)
	alert.Enrichment = defaultEnrichment(indicatorMatches)
	return alert, true
}

func evaluateThreatIntelRule(rule model.DetectionRule, event model.TelemetryEvent, indicatorMatches []model.ThreatIndicator) (model.Alert, bool) {
	if event.Network == nil || len(indicatorMatches) == 0 {
		return model.Alert{}, false
	}

	if !matchesRule(rule, event) {
		return model.Alert{}, false
	}

	alert := buildAlert(rule, event, intel.HighestSeverity(rule.Severity, indicatorMatches))
	alert.Evidence = map[string]any{
		"event_id":    event.ID,
		"remote_ip":   event.Network.RemoteIP,
		"remote_port": event.Network.RemotePort,
	}
	alert.Enrichment = defaultEnrichment(indicatorMatches)
	return alert, true
}

func buildAlert(rule model.DetectionRule, event model.TelemetryEvent, severity string) model.Alert {
	return model.Alert{
		ID:               alertID(event, rule.ID),
		DedupeKey:        dedupeKey(event, rule.ID),
		OccurredAt:       event.OccurredAt.UTC(),
		Hostname:         event.Hostname,
		EndpointID:       event.EndpointID,
		Title:            rule.Title,
		Summary:          rule.Description,
		Detector:         rule.Detector,
		Process:          event.ProcessName,
		ParentProcess:    event.ParentProcessName,
		CommandLine:      event.CommandLine,
		MITRETactic:      rule.MITRETactic,
		MITRETechnique:   rule.MITRETechnique,
		MITRETechniqueID: rule.MITRETechniqueID,
		Severity:         severity,
		Status:           "open",
		Confidence:       rule.Confidence,
		ProcessTree:      event.ProcessTree,
		Evidence:         map[string]any{},
		Enrichment:       map[string]any{},
	}
}

func defaultEvidence(event model.TelemetryEvent) map[string]any {
	return map[string]any{
		"event_id":        event.ID,
		"event_type":      event.EventType,
		"integrity_level": event.IntegrityLevel,
		"labels":          event.Labels,
		"network":         event.Network,
		"file":            event.File,
	}
}

func defaultEnrichment(indicatorMatches []model.ThreatIndicator) map[string]any {
	return map[string]any{
		"threat_intel_matches": indicatorMatches,
	}
}

func matchesRule(rule model.DetectionRule, event model.TelemetryEvent) bool {
	if len(rule.EventTypes) > 0 && !contains(rule.EventTypes, event.EventType) {
		return false
	}
	if len(rule.ProcessNames) > 0 && !contains(rule.ProcessNames, event.ProcessName) {
		return false
	}
	if len(rule.ParentProcessNames) > 0 && !contains(rule.ParentProcessNames, event.ParentProcessName) {
		return false
	}
	if len(rule.CommandLineContains) > 0 && !containsSubstring(rule.CommandLineContains, event.CommandLine) {
		return false
	}
	if len(rule.ProcessTreeSequence) > 0 && !matchesSequence(rule.ProcessTreeSequence, event.ProcessTree) {
		return false
	}
	return true
}

func contains(values []string, candidate string) bool {
	candidate = strings.ToLower(candidate)
	for _, value := range values {
		if strings.ToLower(value) == candidate {
			return true
		}
	}
	return false
}

func containsSubstring(values []string, candidate string) bool {
	candidate = strings.ToLower(candidate)
	for _, value := range values {
		if strings.Contains(candidate, strings.ToLower(value)) {
			return true
		}
	}
	return false
}

func matchesSequence(sequence []string, tree []model.ProcessNode) bool {
	if len(sequence) == 0 {
		return true
	}

	index := 0
	for _, node := range tree {
		if strings.EqualFold(node.Name, sequence[index]) {
			index++
			if index == len(sequence) {
				return true
			}
		}
	}
	return false
}

func dedupeKey(event model.TelemetryEvent, ruleID string) string {
	return strings.ToLower(strings.Join([]string{
		event.EndpointID,
		ruleID,
		event.ProcessName,
		event.ParentProcessName,
		event.CommandLine,
	}, "|"))
}

func alertID(event model.TelemetryEvent, ruleID string) string {
	digest := sha1.Sum([]byte(strings.Join([]string{
		event.ID,
		ruleID,
		time.Now().UTC().Format(time.RFC3339Nano),
	}, "|")))
	return "alert-" + hex.EncodeToString(digest[:8])
}
