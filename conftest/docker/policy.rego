package docker

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# ── Helpers ───────────────────────────────────────────────────────────────────

instructions := [i | i := input[_]]

instruction_types := {i.Cmd | i := instructions[_]}

# ── Rules ─────────────────────────────────────────────────────────────────────

# DENY: running as root
deny contains msg if {
    some i in instructions
    i.Cmd == "user"
    i.Value[0] == "root"
    msg := "Dockerfile: do not run containers as root (USER root)"
}

deny contains msg if {
    not "user" in instruction_types
    msg := "Dockerfile: must specify a non-root USER instruction"
}

# DENY: using :latest tag
deny contains msg if {
    some i in instructions
    i.Cmd == "from"
    image := i.Value[0]
    endswith(image, ":latest")
    msg := sprintf("Dockerfile: do not use :latest tag in FROM (%v)", [image])
}

# DENY: no HEALTHCHECK
deny contains msg if {
    not "healthcheck" in instruction_types
    msg := "Dockerfile: must define a HEALTHCHECK instruction"
}

# WARN: ADD instead of COPY
warn contains msg if {
    some i in instructions
    i.Cmd == "add"
    msg := "Dockerfile: prefer COPY over ADD unless extracting archives"
}

# WARN: apt-get without version pinning
warn contains msg if {
    some i in instructions
    i.Cmd == "run"
    cmd := concat(" ", i.Value)
    contains(cmd, "apt-get install")
    not contains(cmd, "=")
    msg := "Dockerfile: pin package versions in apt-get install for reproducibility"
}

# DENY: curl/wget piped to sh (supply chain risk)
deny contains msg if {
    some i in instructions
    i.Cmd == "run"
    cmd := concat(" ", i.Value)
    contains(cmd, "curl")
    contains(cmd, "| sh")
    msg := "Dockerfile: do not pipe curl/wget output directly to sh"
}

deny contains msg if {
    some i in instructions
    i.Cmd == "run"
    cmd := concat(" ", i.Value)
    contains(cmd, "wget")
    contains(cmd, "| sh")
    msg := "Dockerfile: do not pipe curl/wget output directly to sh"
}
