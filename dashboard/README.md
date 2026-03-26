## SOC Dashboard

This service provides the SOC analyst experience for the EDR platform.

### Local run

```bash
npm run dev
```

The dashboard queries `API_BASE_URL` when the backend is available and falls back to local mock data during standalone UI work.

### Views

- overview metrics and live alert stream
- alerts triage
- incident investigation
- endpoint posture
- threat intelligence
- MITRE ATT&CK coverage
