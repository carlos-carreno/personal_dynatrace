fetch events
| filter event.kind == "SECURITY_EVENT"
| filter event.type == "VULNERABILITY_STATE_REPORT_EVENT"
| filter event.level == "VULNERABILITY"
| filter contains(vulnerability.type, "Blind XPath Injection")
| summarize {
   vulnerability.display_id = takeAny(vulnerability.display_id),
   vulnerability.title = takeAny(vulnerability.title),
   vulnerability.risk.level = takeFirst(vulnerability.risk.level),
   vulnerability.risk.score = takeFirst(vulnerability.risk.score),
   vulnerability.references.cve = takeFirst(vulnerability.references.cve),
   affected_entities.vulnerable_components.names = takeFirst(affected_entities.vulnerable_components.names)
   }, by: {vulnerability.id}
| sort vulnerability.risk.score desc