package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"edr-platform/detection-engine/internal/model"
)

type Engine struct {
	rules      []model.DetectionRule
	evaluators map[string]ruleEvaluator
}

func NewEngine(ruleSet []model.DetectionRule) *Engine {
	if len(ruleSet) == 0 {
		ruleSet = defaultRules()
	}

	return &Engine{
		rules:      normalizeRules(ruleSet),
		evaluators: defaultEvaluators(),
	}
}

func LoadFromFile(path string) (*Engine, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return NewEngine(defaultRules()), nil
	}

	var rules []model.DetectionRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("unmarshal rules: %w", err)
	}

	if len(rules) == 0 {
		rules = defaultRules()
	}

	return NewEngine(rules), nil
}

func (e *Engine) Evaluate(event model.TelemetryEvent, indicatorMatches []model.ThreatIndicator) []model.Alert {
	alerts := make([]model.Alert, 0, len(e.rules))

	for _, rule := range e.rules {
		evaluator := e.evaluatorFor(rule.Kind)
		alert, matched := evaluator(rule, event, indicatorMatches)
		if !matched {
			continue
		}

		alerts = append(alerts, alert)
	}

	return alerts
}

func (e *Engine) evaluatorFor(kind string) ruleEvaluator {
	normalizedKind := normalizeRuleKind(kind)
	if evaluator, ok := e.evaluators[normalizedKind]; ok {
		return evaluator
	}

	return e.evaluators[ruleKindTelemetryMatch]
}

func normalizeRules(ruleSet []model.DetectionRule) []model.DetectionRule {
	normalized := make([]model.DetectionRule, 0, len(ruleSet)+len(systemRules()))
	seenRuleIDs := make(map[string]struct{}, len(ruleSet))

	for _, rule := range ruleSet {
		safeRule := rule
		safeRule.Kind = normalizeRuleKind(rule.Kind)
		normalized = append(normalized, safeRule)

		if safeRule.ID != "" {
			seenRuleIDs[safeRule.ID] = struct{}{}
		}
	}

	for _, rule := range systemRules() {
		if _, exists := seenRuleIDs[rule.ID]; exists {
			continue
		}

		normalized = append(normalized, rule)
	}

	return normalized
}

func normalizeRuleKind(kind string) string {
	normalized := strings.ToLower(strings.TrimSpace(kind))
	if normalized == "" {
		return ruleKindTelemetryMatch
	}

	return normalized
}
