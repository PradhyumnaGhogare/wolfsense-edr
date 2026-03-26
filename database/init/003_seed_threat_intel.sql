INSERT INTO threat_intel (id, indicator, indicator_type, provider, severity, confidence, category, first_seen_at, last_seen_at, expires_at, context)
VALUES
  ('ti-001', '45.155.205.233', 'ipv4', 'MISP', 'critical', 96, 'c2', NOW() - INTERVAL '30 days', NOW() - INTERVAL '2 hours', NOW() + INTERVAL '30 days', '{"family":"DarkGate","tlp":"amber"}'),
  ('ti-002', '185.220.101.11', 'ipv4', 'AbuseIPDB', 'high', 85, 'anonymization', NOW() - INTERVAL '14 days', NOW() - INTERVAL '6 hours', NOW() + INTERVAL '7 days', '{"note":"TOR exit node with malware overlap"}'),
  ('ti-003', '203.0.113.44', 'ipv4', 'OpenCTI', 'high', 88, 'payload-hosting', NOW() - INTERVAL '9 days', NOW() - INTERVAL '8 hours', NOW() + INTERVAL '21 days', '{"campaign":"InvoiceLure"}'),
  ('ti-004', 'c8f22590b5df2e6a4fd06d105fdc139e6bb7829df97eda9204d76407c707e529', 'sha256', 'VirusTotal', 'critical', 99, 'credential-dumping', NOW() - INTERVAL '90 days', NOW() - INTERVAL '1 day', NOW() + INTERVAL '90 days', '{"malware":"LSASSDump"}')
ON CONFLICT (id) DO NOTHING;
