# Tara (تارا) — attack-defense CTF agent

**Tara** — from the Persian word for "star" — is an agent for authorized
attack-defense CTF competitions, with independent offense and defense halves
that can run alone or together over a shared event bus.

It is designed to run **only inside an authorized, sandboxed competition
environment**. A hard, deny-by-default scope gate — enforced both at the
application layer and at the socket level — means Tara can only ever touch the
competition's own targets. That containment has no off switch by design; it is
what makes this a competition agent rather than an unbounded one.

## Subsystems

- **core/** — scope gate, socket egress guard, state store, tool runner,
  reasoning loop, event bus, orchestrator (run defense, offense, or both).
- **defense/** — service health monitoring, flow-aware capture + detection,
  Suricata/IDS ingestion, transactional patching with rollback + liveness
  re-probe, SLA-safe edge mitigation, and an assurance layer (confidence
  scoring, confirmation, false-positive guard, dedup, flag validation).
- **offense/** — category-agnostic replay engine, solver plugin interface,
  scope-filtered target enumeration, flag sink (validate + dedupe + submit),
  and a web solver as the first plugin.
- **tools/** — scoped TCP/HTTP tools and Tor transport for onion-hosted
  challenges (restricted to an explicit onion allowlist).
- **interface/** — a loopback-only operator GUI: a live web console showing
  subsystem status, service health, findings (with confidence/confirmation),
  active mitigations and the flag tally, plus controls to start/stop subsystems
  and drop block rules. Runs with `--ui`; binds to 127.0.0.1 by design.

87 tests across six suites (`test_core`, `test_defense`, `test_assurance`,
`test_offense`, `test_tor`, `test_interface`), none requiring network or an API key.

## Running the console

As a desktop app (Electron, no browser):

```bash
cd electron && npm install && npm start
```

Electron launches the Python backend itself and opens a native window. Override
with env vars: `TARA_PYTHON`, `TARA_PORT`, `TARA_MODE`, `TARA_CONFIG`.

Or headless / in a browser:

```bash
python main.py --mode both --ui           # console on http://127.0.0.1:8787
```

The GUI has full CLI parity: start/stop defense and offense, add services,
**add attack targets** (in-scope ones are used, out-of-scope ones are flagged
and skipped), view and extend the competition scope (cidr/host/onion/port),
run an ad-hoc agent task, toggle dry-run and auto-mitigate, set the flag format,
and drop block rules. With no LLM key set, it still runs (monitoring, detection,
patching, replay); only ad-hoc tasks need a model.

## What's here

```
core/
  scope.py        # hard, deny-by-default scope gate (the containment layer)
  state.py        # durable per-namespace scratchpads + flag store
  toolrunner.py   # the single chokepoint; enforces scope before every call
  agent.py        # think -> tool -> observe loop; autonomy = auto | step
providers/
  base.py         # provider-agnostic LLM interface
  anthropic_provider.py
  openai_provider.py   # also covers ollama / vllm / local via base_url
  registry.py     # build the configured provider
tools/
  base.py         # Tool contract: declare targets(), then run()
  net_probe.py    # reference network tool (scoped TCP probe)
config/default.yaml
main.py
test_core.py      # scope-gate smoke test (no network / key needed)
```

## Design decisions

- **Scope is a hard gate, not a setting.** Deny-by-default; empty config denies
  everything. There is no "off" switch — only a dry-run mode that checks scope
  and logs intended actions without executing. This keeps the agent inside the
  game network and off anything that would trigger disqualification/fines.
- **Autonomy is a dial, not a capability unlock.** `auto` runs to completion;
  `step` pauses for confirmation per tool call. Neither changes what tools can do.
- **Provider-agnostic.** Swap Claude / OpenAI / a local model by config, so an
  air-gapped round can fall back to a self-hosted model.

## Run

```bash
pip install -r requirements.txt
python test_core.py                       # verify the gate
export ANTHROPIC_API_KEY=...              # or configure a local model
# edit config/default.yaml -> scope.allowed_cidrs/hosts for your competition
python main.py --task "probe 10.60.4.9:9000 and report what service it is"
```

## Next milestone

Offense and defense subsystems register their tools into the same `ToolRegistry`
and run through the same gated `ToolRunner`:

- **Defense:** service health monitor, pcap capture + exploit detection, local
  replay confirm, minimal auto-patch + checker verify.
- **Offense:** per-category solve loops (pwn/web/crypto/rev), exploit launcher,
  flag harvest + submission.
- **Shared:** the detect→confirm→patch loop and the capture→weaponize loop that
  turn incoming attacks around on a tick cycle.
