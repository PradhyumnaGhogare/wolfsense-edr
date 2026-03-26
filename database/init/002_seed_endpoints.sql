INSERT INTO endpoints (id, organization_id, hostname, owner, os_version, agent_version, status, risk_score, health, tags, last_telemetry_at, last_seen_ip)
VALUES
  ('endpoint-finance-042', 'acme-corp', 'FIN-WS-042', 'j.smith', 'Windows 11 Enterprise 23H2', '1.7.2', 'online', 92, '{"agent_health":"healthy","sensor_mode":"prevention"}', '["finance","crown-jewel"]', NOW() - INTERVAL '2 minutes', '10.40.12.42'),
  ('endpoint-sql-001', 'acme-corp', 'DB-SQL-001', 'sql-admin', 'Windows Server 2022', '1.7.2', 'online', 64, '{"agent_health":"healthy","sensor_mode":"detect"}', '["database","pci"]', NOW() - INTERVAL '4 minutes', '10.20.4.11'),
  ('endpoint-eng-233', 'acme-corp', 'ENG-LT-233', 'a.chen', 'Windows 11 Enterprise 23H2', '1.7.1', 'degraded', 48, '{"agent_health":"degraded","last_error":"spooler restart"}', '["engineering"]', NOW() - INTERVAL '11 minutes', '10.30.18.233'),
  ('endpoint-vdi-104', 'acme-corp', 'VDI-104', 'contractor.pool', 'Windows 10 Enterprise 22H2', '1.7.2', 'online', 38, '{"agent_health":"healthy","sensor_mode":"detect"}', '["vdi","contractor"]', NOW() - INTERVAL '6 minutes', '10.50.9.104')
ON CONFLICT (id) DO NOTHING;
