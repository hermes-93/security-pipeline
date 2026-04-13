package k8s

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ── Helpers ───────────────────────────────────────────────────────────────────

is_deployment if input.kind == "Deployment"
is_pod        if input.kind == "Pod"

containers := input.spec.template.spec.containers if is_deployment
containers := input.spec.containers               if is_pod

# ── Security Context Rules ────────────────────────────────────────────────────

# DENY: container running as root
deny contains msg if {
    some c in containers
    sc := c.securityContext
    sc.runAsUser == 0
    msg := sprintf("k8s: container '%v' must not run as UID 0 (root)", [c.name])
}

deny contains msg if {
    some c in containers
    sc := c.securityContext
    sc.runAsNonRoot == false
    msg := sprintf("k8s: container '%v' must set runAsNonRoot: true", [c.name])
}

# WARN: missing securityContext
warn contains msg if {
    some c in containers
    not c.securityContext
    msg := sprintf("k8s: container '%v' has no securityContext defined", [c.name])
}

# DENY: privileged containers
deny contains msg if {
    some c in containers
    c.securityContext.privileged == true
    msg := sprintf("k8s: container '%v' must not be privileged", [c.name])
}

# DENY: allowPrivilegeEscalation not explicitly disabled
deny contains msg if {
    some c in containers
    sc := c.securityContext
    sc.allowPrivilegeEscalation != false
    msg := sprintf("k8s: container '%v' must set allowPrivilegeEscalation: false", [c.name])
}

# ── Resource Limits Rules ─────────────────────────────────────────────────────

# DENY: missing resource limits
deny contains msg if {
    some c in containers
    not c.resources.limits.cpu
    msg := sprintf("k8s: container '%v' must define resources.limits.cpu", [c.name])
}

deny contains msg if {
    some c in containers
    not c.resources.limits.memory
    msg := sprintf("k8s: container '%v' must define resources.limits.memory", [c.name])
}

# ── Image Rules ───────────────────────────────────────────────────────────────

# DENY: :latest image tag
deny contains msg if {
    some c in containers
    endswith(c.image, ":latest")
    msg := sprintf("k8s: container '%v' must not use :latest image tag", [c.name])
}

deny contains msg if {
    some c in containers
    not contains(c.image, ":")
    msg := sprintf("k8s: container '%v' image must specify an explicit tag", [c.name])
}

# ── Capabilities ──────────────────────────────────────────────────────────────

# WARN: not dropping all capabilities
warn contains msg if {
    some c in containers
    caps := c.securityContext.capabilities
    not caps.drop
    msg := sprintf("k8s: container '%v' should drop all capabilities", [c.name])
}
