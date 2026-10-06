FIRM_PERMISSIONS: list[tuple[str, str, str, str]] = [
    ("user:read", "user", "read", "View users"),
    ("user:create", "user", "create", "Invite and create users"),
    ("user:update", "user", "update", "Update and deactivate users"),
    ("permission:read", "permission", "read", "View permission catalog"),
    ("role:read", "role", "read", "View roles"),
    ("role:manage", "role", "manage", "Create and manage roles"),
    ("job:read", "job", "read", "View forensic jobs"),
    ("job:run", "job", "run", "Run forensic jobs"),
    ("artifact:read", "artifact", "read", "View artifacts"),
    ("artifact:manage", "artifact", "manage", "Register and manage forensic evidence"),
    ("report:generate", "report", "generate", "Generate reports"),
    ("case:manage", "case", "manage", "Manage forensic cases"),
    # Vulnerability / Nessus module (additive — does not change forensic meaning of job:*)
    ("scan:read", "scan", "read", "View vulnerability scans"),
    ("scan:run", "scan", "run", "Launch vulnerability scans"),
    ("scan:launch", "scan", "launch", "Launch vulnerability scans"),
    ("scan:admin", "scan", "admin", "Administer scanners and scan capacity"),
    ("scan:policy_manage", "scan", "policy_manage", "Manage scan policies"),
    ("vuln:read", "vuln", "read", "View vulnerabilities"),
    ("vuln:write", "vuln", "write", "Update vulnerability workflow state"),
    ("vuln:remediate", "vuln", "remediate", "Create and update remediation tasks"),
    ("vuln:validate", "vuln", "validate", "Run safe exploit validation on findings"),
    ("asset:read", "asset", "read", "View assets"),
    ("asset:write", "asset", "write", "Update asset ownership and criticality"),
    ("remediation:write", "remediation", "write", "Manage remediation tasks"),
    ("exception:approve", "exception", "approve", "Approve risk exceptions"),
    ("evidence:read", "evidence", "read", "View compliance evidence packages"),
    ("dashboard:export", "dashboard", "export", "Export vulnerability dashboards"),
    ("correlation:read", "correlation", "read", "View correlations"),
    ("agent:read", "agent", "read", "View Nessus/Tenable agents"),
    ("agent:manage", "agent", "manage", "Manage Nessus/Tenable agent lifecycle"),
    ("credential:read", "credential", "read", "View scan credential vault references"),
    ("credential:manage", "credential", "manage", "Manage scan credential vault references"),
    # Forensic Agentic AI (distinct from Nessus agent:read / agent:manage)
    ("forensic_agent:read", "forensic_agent", "read", "View forensic AI agent runs and threads"),
    ("forensic_agent:run", "forensic_agent", "run", "Invoke forensic AI agents and tools"),
]

PLATFORM_PERMISSIONS: list[tuple[str, str, str, str]] = [
    ("tenant:manage", "tenant", "manage", "Provision and manage firms"),
    ("user:read", "user", "read", "View platform users"),
    ("user:create", "user", "create", "Create platform users"),
    ("user:update", "user", "update", "Update platform users"),
]

ADMIN_ROLE_PERMISSIONS = [code for code, *_ in FIRM_PERMISSIONS]
USER_ROLE_PERMISSIONS: list[str] = []
