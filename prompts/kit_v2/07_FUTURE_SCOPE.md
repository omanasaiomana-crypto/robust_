# 07 · Future scope (for slides and Q&A, NOT for the hackathon build)

These come from the audit's Priority 2–3 roadmap and from items deliberately left out of v2. Present them as the production path.

| Item | Why it is not in the hackathon build | Production design |
|---|---|---|
| Real AWS/Okta enforcement adapters | Rules require the supplied simulator; modifying live tenants is forbidden | IAM deny policy / STS session revocation and Okta session clear, behind the same `SimulatorAdapter` interface, with analyst approval and dry-run mode |
| Real-time streaming ingestion | Needs live cloud accounts | CloudTrail → EventBridge/SQS; Okta Event Hooks → webhook receiver; sliding correlation buffer; detection within seconds |
| Distributed workers and shared state | Single laptop is enough at hackathon scale | Task queue (Celery/RQ) + Redis or PostgreSQL for shared pipeline state; horizontal API scaling |
| OIDC single sign-on with RBAC | Opt-in analyst token covers the demo (Phase 28) | OIDC with Viewer / Analyst / Admin roles; per-action authorization; SSO audit |
| Time-series event store | SQLite and in-memory data are enough for thousands of events | ClickHouse or TimescaleDB for hundreds of millions of events and sub-second queries |
| Graph neural networks for lateral movement | Not enough training data or time | GNN over the identity graph to predict risky privilege paths across multi-account setups |
| SIEM/SOAR integrations | Email covers admin notification now | Webhooks to Splunk, Microsoft Sentinel, PagerDuty, Jira; signed payloads; retry queue |
| More identity sources | Scope limited to the supplied data | Entra ID, Google Workspace, GitHub audit logs |
| LLM analyst copilot | Optional; prompt-injection risk from log content | Natural-language queries over alerts, with log fields passed strictly as data |
| Localized alerts | Time | Email and console in Kannada/Hindi for small organizations without a SOC |
