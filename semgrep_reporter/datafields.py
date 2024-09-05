SEVERITIES = ["high", "medium", "low"]

STATES = ["muted", "fixed", "removed", "unresolved"]

STATUSES = ["open", "fixed", "ignored", "fixing", "reviewing"]

CSV_COLUMNS = [
    "Finding Title",
    "Finding Description & Remediation",
    "status",
    "First Seen",
    "severity",
    "confidence",
    "triage_state",
    "triaged_at",
    "triage_comment",
    "state_updated_at",
    "repository",
    "location",
]

SAST_REPORT_COLUMNS = [
    # 'First Seen',
    "Finding Title",
    "Finding Description & Remediation",
    "severity",
    "status",
    "repository.name",
    "repository.url",
    "location.file_path",
    "location.line",
    "ref",
    # 'finding_hyperlink',
    # 'extra.severity',
    # 'extra.metadata.confidence',
    # 'extra.metadata.semgrep.url',
    # 'extra.metadata.likelihood',
    # 'extra.metadata.impact',
    # 'extra.metadata.owasp',
    # 'extra.metadata.cwe',
    # 'extra.metadata.cwe2021-top25',
    # 'extra.metadata.cwe2022-top25',
]
