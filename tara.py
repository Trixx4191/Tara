"""
Tara — identity for the CTF attack-defense agent.

"Tara" (Persian: تارا) — "star". The name for this agent.

Tara runs ONLY inside authorized, sandboxed CTF competition environments. Its
whole design is built around a hard, deny-by-default scope gate: it can only
touch the competition's own targets, and both the application-layer checks and
the socket-level egress guard enforce that on every connection. That containment
is not an add-on — it is what makes Tara a competition agent rather than an
unbounded one, and it has no off switch by design.
"""

NAME = "Tara"
NAME_FA = "تارا"
VERSION = "0.4.0"
TAGLINE = "attack-defense CTF agent — sandboxed by design"


def banner() -> str:
    return f"{NAME} ({NAME_FA}) v{VERSION} — {TAGLINE}"
