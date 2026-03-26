INSERT INTO incidents (id, title, status, severity, created_at, updated_at, endpoint_id, hostname, mitre_tactic, mitre_technique, mitre_technique_id, alert_count, analyst_owner, summary, tags)
VALUES
  ('inc-1001', 'Office to PowerShell execution on FIN-WS-042', 'investigating', 'critical', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '12 minutes', 'endpoint-finance-042', 'FIN-WS-042', 'Execution', 'Malicious File', 'T1204.002', 2, 'a.reyes', 'Word spawned cmd and PowerShell with remote download activity on a finance workstation.', '["automation","priority:1"]'),
  ('inc-1002', 'Credential dumping attempt on DB-SQL-001', 'open', 'critical', NOW() - INTERVAL '5 hours', NOW() - INTERVAL '29 minutes', 'endpoint-sql-001', 'DB-SQL-001', 'Credential Access', 'OS Credential Dumping', 'T1003', 1, 'r.patel', 'rundll32 with comsvcs MiniDump targeted LSASS on a SQL server.', '["automation","domain-controller-adjacent"]')
ON CONFLICT (id) DO NOTHING;
