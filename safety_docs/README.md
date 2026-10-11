# Tara safety documentation

This directory documents the safety chain that keeps Tara bounded to the competition or lab environment. The project is intentionally designed so that network access is deny-by-default, and every network-touching action must pass through multiple layers before it can run.

Start with the detailed guide:

- [tara_safety_chain.md](tara_safety_chain.md)

The key files behind the safety model are:

- [../config/default.yaml](../config/default.yaml)
- [../main.py](../main.py)
- [../core/scope.py](../core/scope.py)
- [../core/netguard.py](../core/netguard.py)
- [../core/toolrunner.py](../core/toolrunner.py)
- [../defense/assurance.py](../defense/assurance.py)
- [../defense/mitigation.py](../defense/mitigation.py)

The correct operational stance is: keep the controls active, narrow the allowlist to a dedicated lab, and restore the original policy after research.
