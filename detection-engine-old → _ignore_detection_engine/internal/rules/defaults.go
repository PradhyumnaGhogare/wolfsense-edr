package rules

import "edr-platform/detection-engine/internal/model"

func defaultRules() []model.DetectionRule {
	rules := []model.DetectionRule{
		{
			ID:                  "R-PS-001",
			Kind:                ruleKindTelemetryMatch,
			Title:               "PowerShell Encoded Command",
			Description:         "Detects encoded PowerShell execution commonly used for staged payload delivery and defense evasion.",
			Detector:            "mitre-rule-engine",
			EventTypes:          []string{"process_create"},
			ProcessNames:        []string{"powershell.exe", "pwsh.exe"},
			CommandLineContains: []string{"-encodedcommand", "-enc"},
			Severity:            "high",
			MITRETactic:         "Execution",
			MITRETechnique:      "Command and Scripting Interpreter: PowerShell",
			MITRETechniqueID:    "T1059.001",
			Confidence:          0.93,
		},
		{
			ID:                  "R-PS-002",
			Kind:                ruleKindTelemetryMatch,
			Title:               "PowerShell Download Cradle",
			Description:         "Flags PowerShell usage that downloads remote content or executes web requests.",
			Detector:            "behavioral-correlation",
			EventTypes:          []string{"process_create", "network_connect"},
			ProcessNames:        []string{"powershell.exe", "pwsh.exe"},
			CommandLineContains: []string{"invoke-webrequest", "downloadstring", "http://", "https://"},
			Severity:            "high",
			MITRETactic:         "Command and Control",
			MITRETechnique:      "Ingress Tool Transfer",
			MITRETechniqueID:    "T1105",
			Confidence:          0.88,
		},
		{
			ID:                  "R-CHAIN-001",
			Kind:                ruleKindTelemetryMatch,
			Title:               "Office Spawned Script Interpreter",
			Description:         "Detects suspicious Office to cmd to PowerShell process lineage often associated with malicious documents.",
			Detector:            "process-chain-analysis",
			EventTypes:          []string{"process_create"},
			ProcessNames:        []string{"powershell.exe"},
			ProcessTreeSequence: []string{"winword.exe", "cmd.exe", "powershell.exe"},
			Severity:            "critical",
			MITRETactic:         "Execution",
			MITRETechnique:      "Malicious File",
			MITRETechniqueID:    "T1204.002",
			Confidence:          0.96,
		},
		{
			ID:                  "R-CRED-001",
			Kind:                ruleKindTelemetryMatch,
			Title:               "Credential Dumping via comsvcs",
			Description:         "Detects rundll32 comsvcs MiniDump usage against LSASS or related sensitive processes.",
			Detector:            "mitre-rule-engine",
			EventTypes:          []string{"process_create"},
			ProcessNames:        []string{"rundll32.exe", "procdump.exe"},
			CommandLineContains: []string{"comsvcs.dll", "minidump", "lsass"},
			Severity:            "critical",
			MITRETactic:         "Credential Access",
			MITRETechnique:      "OS Credential Dumping",
			MITRETechniqueID:    "T1003",
			Confidence:          0.98,
		},
		{
			ID:                  "R-LOL-001",
			Kind:                ruleKindTelemetryMatch,
			Title:               "LOLBins Remote Retrieval",
			Description:         "Detects common living-off-the-land binaries used to retrieve payloads or stage malware.",
			Detector:            "mitre-rule-engine",
			EventTypes:          []string{"process_create"},
			ProcessNames:        []string{"certutil.exe", "mshta.exe", "bitsadmin.exe", "regsvr32.exe"},
			CommandLineContains: []string{"http://", "https://", "-urlcache", "/transfer", "scrobj.dll"},
			Severity:            "high",
			MITRETactic:         "Defense Evasion",
			MITRETechnique:      "System Binary Proxy Execution",
			MITRETechniqueID:    "T1218",
			Confidence:          0.87,
		},
	}

	return append(rules, systemRules()...)
}

func systemRules() []model.DetectionRule {
	return []model.DetectionRule{
		{
			ID:               "R-TI-001",
			Kind:             ruleKindThreatIntelMatch,
			Title:            "Threat Intelligence Match",
			Description:      "Observed network activity matched a known malicious indicator from the threat intelligence corpus.",
			Detector:         "threat-intel-enrichment",
			Severity:         "high",
			MITRETactic:      "Command and Control",
			MITRETechnique:   "Application Layer Protocol",
			MITRETechniqueID: "T1071",
			Confidence:       0.94,
		},
	}
}
