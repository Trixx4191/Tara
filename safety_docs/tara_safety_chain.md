# Tara safety chain: exact design, implementation, and restoration

## 1. Safety model in one sentence

Tara is built as a constrained, deny-by-default research/competition agent. It is not designed to reach arbitrary hosts. The project relies on multiple independent layers to prevent out-of-scope and accidental egress:

1. configuration declares the allowed lab scope
2. the scope policy validates targets before any tool call
3. the socket-level NetworkGuard blocks outbound connections outside control-plane or in-scope traffic
4. the ToolRunner becomes the single chokepoint for all tool execution
5. defense logic adds scoring, confirmation, false-positive checks, and mitigation gates before action
6. flag validation and review guard against hallucinated or unsafe actions

This is the safety chain the project depends on.

---

## 2. The exact config fields in default.yaml that form the safety chain

The authoritative config file is [../config/default.yaml](../config/default.yaml).

### 2.1 Global execution safety

#### dry_run

```yaml
dry_run: false
```

Meaning:
- `false` means the project is allowed to execute real tool calls within the approved scope.
- `true` is the safe, non-executing mode: the tool runner still checks scope, but will not run the tool.

Implementation:
- [../core/scope.py](../core/scope.py): `ScopePolicy.from_config()` reads the config and stores the runtime state.
- [../core/toolrunner.py](../core/toolrunner.py): `ToolRunner.run()` checks `self.scope.dry_run` after scope validation and before running the tool.

Why it matters:
- it is a deliberate fail-safe for testing and operator review, not a bypass.

---

### 2.2 Scope gate: allowed targets

#### scope.allowed_hosts

```yaml
scope:
  allowed_hosts: []
```

Meaning:
- explicit hostnames that are allowed even when they are not inside a broader CIDR
- used for exact, named lab targets or special hosts

Implementation:
- [../core/scope.py](../core/scope.py): `ScopePolicy.allowed_hosts`
- `ScopePolicy._host_allowed()` and `ScopePolicy.resolve_and_check()`

Why it matters:
- this is a hard allowlist, not a permissive default.

#### scope.allowed_cidrs

```yaml
scope:
  allowed_cidrs: []
```

Meaning:
- the lab or competition network range(s), such as `10.60.0.0/16`
- if this is empty, the project denies all network actions by default

Implementation:
- [../core/scope.py](../core/scope.py): `ScopePolicy.from_config()` parses CIDRs into `ipaddress` network objects
- `ScopePolicy._ip_in_cidrs()` and `ScopePolicy.resolve_and_check()` enforce them

Why it matters:
- this is the primary safety boundary. A target is only allowed if it resolves to an in-scope IP or is explicitly allowed.

#### scope.allowed_ports

```yaml
scope:
  allowed_ports: []
```

Meaning:
- restricts target ports to a known-safe subset
- empty means “any port on an allowed host” unless other checks apply

Implementation:
- [../core/scope.py](../core/scope.py): `_check_port()`
- called from `check_target()`, `resolve_and_check()`, and `check_onion()`

Why it matters:
- prevents accidental targeting of unexpectedly high-risk or non-lab ports

#### scope.allowed_paths

```yaml
scope:
  allowed_paths:
    - "./state"
    - "./challenges"
```

Meaning:
- local filesystem roots the agent is allowed to read or write

Implementation:
- [../core/scope.py](../core/scope.py): `check_path()`

Why it matters:
- this controls the file system side of the sandbox, not just network egress

---

### 2.3 Safety hardening for dangerous ranges

#### scope.block_special

```yaml
scope:
  block_special: true
```

Meaning:
- blocks dangerous special network ranges such as metadata endpoints, link-local space, CGNAT, multicast, and reserved ranges

Implementation:
- [../core/scope.py](../core/scope.py): `_SPECIAL_DENY` list and `_is_special()`
- `resolve_and_check()` rejects any resolved address matching those blocks unless explicitly allowed

Why it matters:
- this prevents the project from accidentally hitting cloud metadata, link-local addresses, or other non-competition traffic.

#### scope.resolve_check

```yaml
scope:
  resolve_check: true
```

Meaning:
- hostnames are resolved and every returned IP is checked before connecting
- closes the DNS rebinding / name-to-IP mismatch gap

Implementation:
- [../core/scope.py](../core/scope.py): `ScopePolicy.resolve_and_check()`

Why it matters:
- the project validates the actual IP(s) behind a hostname, not just the hostname string.

---

### 2.4 Egress enforcement

#### scope.enforce_egress

```yaml
scope:
  enforce_egress: true
```

Meaning:
- installs the socket-level NetworkGuard to intercept outbound TCP connections and deny anything not in scope

Implementation:
- [../main.py](../main.py): `_install_guard(cfg, scope)`
- [../core/netguard.py](../core/netguard.py): `NetworkGuard.install()` monkey-patches `socket.socket.connect` and `socket.getaddrinfo`

Why it matters:
- this is the second line of defense under the application-level scope logic.

#### scope.control_hosts

```yaml
scope:
  control_hosts: []
```

Meaning:
- additional hosts the agent is allowed to reach for control-plane functions, such as the model API or local infrastructure

Implementation:
- [../main.py](../main.py): `_install_guard()` adds configured control hosts
- [../core/netguard.py](../core/netguard.py): `add_control_host()` and `_seed_defaults()`

Why it matters:
- the guard distinguishes control-plane traffic from target-plane traffic

#### scope.allowed_onions

```yaml
scope:
  allowed_onions: []
```

Meaning:
- explicit `.onion` names the lab is allowed to test
- deny-by-default and separate from regular CIDR logic

Implementation:
- [../core/scope.py](../core/scope.py): `valid_onion()`, `is_onion()`, `check_onion()`

Why it matters:
- onion traffic is a special case because Tor is remote-resolved and the socket layer does not see the final target directly.

---

### 2.5 Tor-specific safety

#### tor.enabled / tor.socks_host / tor.socks_port

```yaml
tor:
  enabled: false
  socks_host: 127.0.0.1
  socks_port: 9050
```

Meaning:
- Tor is only enabled when explicitly configured
- the project treats Tor as a pathway to explicit onion targets and not as a general anonymizer for arbitrary external traffic

Implementation:
- [../main.py](../main.py): `_build_tools(cfg)` registers `TorTcp` and `TorHttpRequest` only when enabled
- [../core/scope.py](../core/scope.py): `check_onion()` ensures onion targets are in `allowed_onions`

Why it matters:
- if Tor is disabled, onion traffic stays blocked by default; if enabled, the scope still enforces the onion allowlist.

---

### 2.6 Defensive action safety

#### defense.checker_allowlist

```yaml
defense:
  checker_allowlist: []
```

Meaning:
- patterns identifying benign checker traffic that should never be treated as an attack or auto-mitigated

Implementation:
- [../defense/defense.py](../defense/defense.py): `Detector(flag_format=..., checker_allowlist=...)`
- [../defense/assurance.py](../defense/assurance.py): `FalsePositiveGuard(checker_patterns=...)`

Why it matters:
- the system avoids blocking its own SLA checker or legitimate verification traffic.

#### defense.auto_mitigate

```yaml
defense:
  auto_mitigate: false
```

Meaning:
- action is disabled unless the operator explicitly turns it on

Implementation:
- [../defense/defense.py](../defense/defense.py): `_handle_group()` only installs a block rule when `act and self.auto_mitigate and ...`

Why it matters:
- this is a deliberate safety gate between “something looked suspicious” and “install a firewall-style rule.”

---

### 2.7 Offense review safety

#### offense.auto_submit

```yaml
offense:
  auto_submit: false
```

Meaning:
- captured flags go through the review queue by default instead of being auto-submitted

Implementation:
- [../offense/offense.py](../offense/offense.py): `_on_flag()` routes to `ReviewQueue` when auto-submit is off

Why it matters:
- it prevents automatic submission of low-confidence or hallucinated tokens.

---

## 3. The runtime safety chain, end-to-end

### 3.1 Startup and installation

The startup path is in [../main.py](../main.py):

- `build_context(cfg)` creates the `ScopePolicy` from config
- `_install_guard(cfg, scope)` installs `NetworkGuard` if `scope.enforce_egress` is enabled
- the guard is passed the competition scope and control-plane hosts
- the tool registry is created and the `ToolRunner` is bound to the same scope object

This means every tool runs under the same safety gate.

---

### 3.2 Application-layer scope gate

[../core/scope.py](../core/scope.py) is the central policy engine.

The main policy checks are:

- `ScopePolicy.from_config()`
- `check_target()`
- `resolve_and_check()`
- `check_onion()`
- `check_targets()`
- `check_path()`

The meaningful behaviors are:

- deny any host not in `allowed_hosts` or not covered by `allowed_cidrs`
- reject special ranges even when they appear in a broad CIDR
- resolve names and validate all returned IPs
- reject malformed or unlisted onion names
- enforce allowed ports and filesystem roots

This policy is intentionally safe-by-default and warns if a CIDR is dangerously broad.

---

### 3.3 Socket-level egress gate

[../core/netguard.py](../core/netguard.py) adds a second layer.

It monkey-patches:

- `socket.socket.connect`
- `socket.getaddrinfo`

At runtime it does this:

- allow loopback and configured control-plane hosts
- resolve and remember control IPs
- check every attempted outbound connection against the policy
- raise `OSError` if the target is neither control-plane nor in scope

This is the defense-in-depth layer that catches missed or malicious tool behavior.

---

### 3.4 The one chokepoint: ToolRunner

[../core/toolrunner.py](../core/toolrunner.py) is the single gatekeeper for all tool execution.

Flow:

1. find the tool in the registry
2. ask the tool for its target list
3. run `self.scope.check_targets(targets)` before execution
4. if `scope.dry_run` is enabled, log the planned call and do not run it
5. execute under a timeout and capture output
6. write safe metadata to state

This is important because it guarantees that every network action is filtered by the same logic, even if a tool implementation is imperfect.

---

### 3.5 Defense scoring and false-positive guard

[../defense/defense.py](../defense/defense.py) and [../defense/assurance.py](../defense/assurance.py) add a second reasoning layer before action.

Key pieces:

- `AlertDeduper` collapses repeated alerts
- `ConfidenceScorer` scores a candidate detection
- `Confirmer` replays a request against a local replica or baseline
- `FalsePositiveGuard` vetoes block rules that match benign traffic or the checker itself
- `validate_flag()` ensures a captured token matches the competition flag format

This matters because the project is explicitly designed to avoid false positives, block storms, and hallucinated flags.

---

### 3.6 Mitigation as reversible policy, not blind code changes

[../defense/mitigation.py](../defense/mitigation.py) ensures that when mitigation is used, it is a structured block rule and not a direct, uncontrolled action.

Important values:

- `BlockRule` is an explicit record with `rule_id`, `kind`, `pattern`, `reason`, and `active`
- `BlocklistEnforcer` is in-process and reversible
- `NftEmitter` is emit-only unless the operator explicitly sets `run=True`
- `FalsePositiveGuard.is_safe()` rejects unsafe patterns before they are applied

This is a stability and safety layer for live defense actions.

---

## 4. How to restore the safety chain after a lab run

The correct path is not to “remove” the chain entirely; it is to keep a backup of the original policy and return to it after an isolated lab test.

### 4.1 Safe procedure

1. Back up the working config:

```bash
cp config/default.yaml config/default.yaml.bak
```

2. Make a lab-specific config file, for example `config/lab_research.yaml`, using only the lab subnet and hosts.

3. Run Tara with the lab config instead of the default one:

```bash
python main.py --config config/lab_research.yaml --mode both
```

4. Run only inside the dedicated lab network and a controlled allowlist.

5. After the research pass, restore the original config:

```bash
cp config/default.yaml.bak config/default.yaml
```

6. Verify the policy is back to the safe default by rerunning a core test or a dry-run check.

---

### 4.2 Recommended lab configuration pattern

Keep these values in the lab config:

```yaml
scope:
  allowed_hosts: []
  allowed_cidrs:
    - "10.50.0.0/16"
  allowed_ports:
    - 80
    - 443
    - 9000
  allowed_paths:
    - "./state"
    - "./challenges"
  block_special: true
  resolve_check: true
  enforce_egress: true
  control_hosts: []
  allowed_onions: []
```

And keep these values unchanged:

```yaml
dry_run: false
tor:
  enabled: false
```

This keeps the behavior controlled and still exercises the actual safety model in a lab.

---

### 4.3 Recovery checklist

Before ending a research session, confirm:

- `dry_run` is set to the desired test mode and not left accidentally permissive
- `scope.allowed_cidrs` points only to the lab range
- `block_special` stays `true`
- `resolve_check` stays `true`
- `enforce_egress` stays `true`
- `control_hosts` is limited to required endpoints
- `allowed_onions` remains empty unless they are explicitly required
- `defense.auto_mitigate` remains `false` unless the lab actually requires it
- `offense.auto_submit` remains `false` unless there is an explicit operator review policy

---

## 5. Safety summary by code layer

### Highest-level controls

- [../config/default.yaml](../config/default.yaml): declared policy including network, ports, files, and egress guard settings
- [../main.py](../main.py): installs the guard and wires the environment

### Core policy controls

- [../core/scope.py](../core/scope.py): the deny-by-default, explicit-allowlist core
- [../core/netguard.py](../core/netguard.py): socket-level enforcement under the app logic
- [../core/toolrunner.py](../core/toolrunner.py): the single tool execution choke point

### Defensive safety controls

- [../defense/defense.py](../defense/defense.py): health sweep, detection, and mitigation gates
- [../defense/assurance.py](../defense/assurance.py): dedup, scoring, confirmation, false-positive vetoes, flag validation
- [../defense/mitigation.py](../defense/mitigation.py): reversible, rule-based response logic

### Offense safety controls

- [../offense/offense.py](../offense/offense.py): review queue and controlled submission path

---

## 6. Practical policy recommendation

For a research environment, the best pattern is not disabling the chain. It is:

- keep the deny-by-default default intact
- use a lab-specific config with a narrow CIDR and explicit ports
- keep `enforce_egress` on
- keep `block_special` and `resolve_check` on
- restore the original default config after research

This preserves the project’s safety design while still allowing a contained, observable test environment.

---

## 7. Final note

Tara’s safety chain is intentional and multi-layered. The design is not accidental; it exists to keep the agent inside the authorized environment, reduce the chance of false positives, prevent accidental egress, and ensure that any real action is scored, confirmed, and reversible.

The correct lifecycle for lab work is:

- narrow the policy to the lab,
- keep the guardrails active,
- collect data,
- restore the safe defaults afterward.

That is the project’s supported research pattern.
