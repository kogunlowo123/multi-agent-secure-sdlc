package sdlc_security

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Allow health checks without authentication
allow if {
    input.path in ["/api/v1/health", "/api/v1/readiness"]
}

# Allow code review with valid tenant
allow if {
    input.method == "POST"
    input.path == "/api/v1/code/review"
    has_valid_tenant
    has_valid_role({"developer", "security-reviewer", "ci-agent"})
}

# Allow SAST scan with valid tenant
allow if {
    input.method == "POST"
    input.path == "/api/v1/sast/scan"
    has_valid_tenant
    has_valid_role({"developer", "security-reviewer", "ci-agent"})
}

# Allow release gate only for authorized roles
allow if {
    input.method == "POST"
    input.path == "/api/v1/release/gate"
    has_valid_tenant
    has_valid_role({"release-manager", "security-reviewer", "ci-agent"})
}

# Allow release status check
allow if {
    input.method == "GET"
    startswith(input.path, "/api/v1/release/")
    endswith(input.path, "/status")
    has_valid_tenant
    has_valid_role({"developer", "release-manager", "security-reviewer", "ci-agent"})
}

# Helper: check valid tenant
has_valid_tenant if {
    input.tenant_id != ""
    input.tenant_id != "unknown"
}

# Helper: check user has one of the allowed roles
has_valid_role(allowed_roles) if {
    some role in input.roles
    role in allowed_roles
}
