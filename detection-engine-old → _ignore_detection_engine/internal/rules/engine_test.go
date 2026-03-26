package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"edr-platform/detection-engine/internal/model"
)

func TestNewEngine_DefaultsLegacyRuleKindToTelemetryMatch(t *testing.T) {
	engine := NewEngine([]model.DetectionRule{
		{
			ID:                  "CUSTOM-PS-001",
			Title:               "Legacy PowerShell Rule",
			Description:         "legacy rule without kind should still work",
			Detector:            "legacy-engine",
			EventTypes:          []string{"process_create"},
			ProcessNames:        []string{"powershell.exe"},
			CommandLineContains: []string{"-enc"},
			Severity:            "high",
			MITRETactic:         "Execution",
			MITRETechnique:      "Command and Scripting Interpreter: PowerShell",
			MITRETechniqueID:    "T1059.001",
			Confidence:          0.91,
		},
	})

	alerts := engine.Evaluate(sampleEvent(), nil)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	alert := alerts[0]
	if alert.Title != "Legacy PowerShell Rule" {
		t.Fatalf("expected legacy rule title, got %q", alert.Title)
	}
	if alert.Detector != "legacy-engine" {
		t.Fatalf("expected detector to be preserved, got %q", alert.Detector)
	}
	if alert.Process != "powershell.exe" {
		t.Fatalf("expected process to be carried from event, got %q", alert.Process)
	}
}

func TestNewEngine_AppendsSystemThreatIntelRule(t *testing.T) {
	engine := NewEngine([]model.DetectionRule{
		{
			ID:               "CUSTOM-NO-MATCH",
			Title:            "Custom Non Matching Rule",
			Description:      "does not match the sample event",
			Detector:         "custom",
			ProcessNames:     []string{"cmd.exe"},
			Severity:         "low",
			MITRETactic:      "Execution",
			MITRETechnique:   "Command and Scripting Interpreter",
			MITRETechniqueID: "T1059",
			Confidence:       0.5,
		},
	})

	event := sampleEvent()
	event.Network = &model.NetworkContext{
		Protocol:   "tcp",
		RemoteIP:   "45.155.205.233",
		RemotePort: 443,
	}

	alerts := engine.Evaluate(event, []model.ThreatIndicator{
		{
			ID:        "ti-1",
			Indicator: "45.155.205.233",
			Severity:  "critical",
		},
	})

	if len(alerts) != 1 {
		t.Fatalf("expected 1 threat-intel alert, got %d", len(alerts))
	}

	alert := alerts[0]
	if alert.DedupeKey == "" {
		t.Fatal("expected dedupe key to be populated")
	}
	if alert.Title != "Threat Intelligence Match" {
		t.Fatalf("expected built-in threat intel rule to fire, got %q", alert.Title)
	}
	if alert.Detector != "threat-intel-enrichment" {
		t.Fatalf("expected threat intel detector, got %q", alert.Detector)
	}
	if alert.Severity != "critical" {
		t.Fatalf("expected severity to inherit highest indicator severity, got %q", alert.Severity)
	}
}

func TestLoadFromFile_EmptyRuleFileFallsBackToDefaults(t *testing.T) {
	tempDir := t.TempDir()
	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write temp rules file: %v", err)
	}

	engine, err := LoadFromFile(rulesPath)
	if err != nil {
		t.Fatalf("load rules from temp file: %v", err)
	}

	alerts := engine.Evaluate(sampleEvent(), nil)
	if len(alerts) != 1 {
		t.Fatalf("expected default rule set to produce 1 alert, got %d", len(alerts))
	}

	if alerts[0].Title != "PowerShell Encoded Command" {
		t.Fatalf("expected default powershell rule, got %q", alerts[0].Title)
	}
}

func sampleEvent() model.TelemetryEvent {
	return model.TelemetryEvent{
		ID:                "evt-1001",
		OrganizationID:    "org-1",
		EndpointID:        "endpoint-finance-042",
		Hostname:          "FIN-WS-042",
		Username:          "j.smith",
		EventType:         "process_create",
		OccurredAt:        time.Date(2026, time.March, 23, 12, 0, 0, 0, time.UTC),
		ProcessName:       "powershell.exe",
		ProcessPath:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ProcessID:         5532,
		ParentProcessName: "cmd.exe",
		ParentProcessID:   5528,
		CommandLine:       "powershell.exe -enc ZQBjAGgAbwAgAHQAZQBzAHQ=",
		IntegrityLevel:    "high",
		ProcessTree: []model.ProcessNode{
			{Name: "winword.exe", PID: 4210, PPID: 3024, CommandLine: `WINWORD.EXE C:\Users\j.smith\Downloads\invoice.docm`},
			{Name: "cmd.exe", PID: 5528, PPID: 4210, CommandLine: "cmd.exe /c powershell.exe -enc ZQBjAGgAbwAgAHQAZQBzAHQ="},
			{Name: "powershell.exe", PID: 5532, PPID: 5528, CommandLine: "powershell.exe -enc ZQBjAGgAbwAgAHQAZQBzAHQ="},
		},
		Labels: map[string]string{
			"source": "unit-test",
		},
	}
}
