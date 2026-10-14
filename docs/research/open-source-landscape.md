# Open source landscape: what exists, what we reuse, what we avoid

Research date: 2026-10-08. Each row marked **verified** was read directly from
the project's repository (license file and last commit date, shallow clone of
the default branch). Rows marked *secondary* come from vendor blogs, search
summaries or docs sites and should be re-checked before relying on them.

## 1. The problem we are solving

An operator sits at a connected machine and talks to an AI the way they talk to
a chat assistant. The machines being fixed may have no internet access at all.
When a user brings a laptop with a problem, the operator needs to:

1. pull system facts, configs and logs off that laptop,
2. have an AI reason about the fault and propose a repair,
3. run the repair on the laptop with a safety gate and a record,
4. keep every secret on the operator machine and never in git,
5. do all of this in a way that can be made HIPAA compliant.

No single open source project does all five. The closest categories are:

* **RMM / remote control** (MeshCentral, Tactical RMM, RustDesk, Remotely):
  they assume the endpoint can reach a server, and none of them has an AI
  planning loop.
* **Endpoint telemetry** (osquery, Fleet, Wazuh): excellent fact collection,
  no remediation planning, and they assume a live server connection for
  anything beyond local log files.
* **LLM agent frameworks** (Hermes Agent, AI-Remote-Agent, ansible-heal-agent,
  auto-healing-agent): they can run commands under a model, but they are not
  built around an offline endpoint, a signed approval flow, or PHI redaction.

So the plan is to **own the thin layer that none of them have** (offline
bundle, redaction, signed plan, policy-gated executor, audit chain) and
**reuse the heavy pieces** (osquery for facts, MeshCentral for live screen
sharing when there is a network, Ollama or the Claude API for the model).

## 2. License and activity table

| Project | License | Last commit on default branch | Status | How we use it |
|---|---|---|---|---|
| MeshCentral 1.2.6 | Apache-2.0 **(verified)** | 2026-09-23 **(verified)** | Active | Optional: live remote desktop, terminal and file transfer when the endpoint is on a LAN with the console. Permissive license, can be bundled. |
| Tactical RMM | "Tactical RMM License Version 1.0", explicitly **not** open source **(verified, LICENSE.md)** | 2026-09-30 **(verified)** | Active | Reference only. Its license forbids making the software "available as part of any other commercial or for-profit service" without written permission, and Mac/Linux agents are a paid sponsorship feature. Not usable as a base for a project meant for other organizations and MSPs. |
| Remotely | GPL-3.0 **(verified)** | 2024-12-17 **(verified)** | Stale (22 months without a commit) | Reference for agent design (SignalR + WebRTC). Not a dependency. |
| RustDesk 1.5.0 | AGPL-3.0 **(verified, file `LICENCE`)** | 2026-10-08 **(verified)** | Active | Optional screen share, run as a separate process over its own protocol, never linked into our code (AGPL). |
| Fleet | MIT for the core; `ee/` directory under the Fleet EE license **(verified)** | 2026-10-08 **(verified)** | Active | Optional osquery fleet manager for the connected part of a network. Not needed for offline endpoints. |
| osquery | Apache-2.0 OR GPL-2.0-only **(verified)** | 2026-10-08 **(verified)** | Active | If `osqueryi` is present on the endpoint, the agent runs a query pack and includes the JSON in the bundle. |
| Microsoft Presidio | MIT *(secondary)* | mid-2026 *(secondary)* | Active | Optional NLP recognizers for names and addresses in free text. Our built-in redactor is regex based; Presidio is the upgrade path. |
| Ollama | MIT *(secondary, from project knowledge)* | Active | Active | Default local model runtime so no data leaves the operator machine. |
| Hermes Agent (Nous Research) | MIT *(secondary)* | 2026 | Active | Reference for a local model agent loop with a terminal tool. |
| NetLock RMM | AGPL-3.0 open core, public commits paused *(secondary)* | unknown | Uncertain | Watch list. Claims air-gapped operation and an LLM feature, but the public tree lags the product. |
| Wazuh | GPL-2.0 *(secondary, from project knowledge)* | Active | Active | Future: ship osquery results into a Wazuh manager on an isolated network. |
| Ansible | GPL-3.0 *(secondary, from project knowledge)* | Active | Active | Future: Linux remediation playbooks invoked by the executor. |

### Notes on the vendor comparisons

The comparison blogs that come up first in search (openmsp.ai, breezermm.com,
valebyte.com) are written by companies selling competing RMM products. Their
feature tables were useful for scoping, but the license claims in them
conflicted with each other, which is why the table above was verified against
the repositories directly. In particular, one blog called MeshCentral AGPL
with a paid "Server Pro"; the repository is Apache-2.0.

## 3. Projects that already combine an LLM with IT remediation

None of these matched the whole requirement, but each has a piece worth
studying:

* **ansible-heal-agent** (adventurewave-labs): reads Ansible failures, patches
  playbooks and re-runs. LLM-first with a rule-based fallback. Works on
  Ansible code, not on a live endpoint.
* **auto-healing-agent** (restrok): homelab self-healing with human-in-the-loop
  approval and LLM root-cause analysis. Targets Docker services.
* **AI-Remote-Agent** (airemoteagent): MIT, cross-platform agent that runs
  commands under a model with a local policy file. General agent, no offline
  bundle, no signed plans, no PHI handling.
* **it-self-service-agent** (Red Hat AI quickstart): service-desk automation,
  ticket oriented rather than endpoint oriented.
* **NetLock RMM**: has an "LLM role" on its server, but the code is not fully
  public at the moment.

Design lessons we adopted from them: keep the model's output as a structured
plan rather than free text, require explicit approval before anything runs,
and keep a rule-based fallback so the system still works without a model.

## 4. Offline and air-gapped transport

Search found no open source tool that collects a Windows/Linux/macOS support
bundle and carries it across an air gap. Pieces that exist:

* **NNCP** handles encrypted, authenticated store-and-forward over removable
  media, but has no Windows story in the sources found.
* Product-specific support bundle scripts (Netdata, Netenrich, Bindplane,
  Microsoft TSSv2) show the right shape: one archive, secrets redacted,
  IPs and hostnames pseudonymized, event log excerpts bounded by days.
* Ollama can be installed offline by copying the binary and a GGUF model
  across the gap and importing it with a Modelfile.

Our bundle format (`docs/architecture.md`) borrows the support-bundle shape
and adds encryption to the console key and an agent signature so a USB stick
found in a parking lot is useless.

## 5. Local model agents

Local agents that run shell commands under Ollama exist (Hermes Agent, Cline,
ollama-agent). Reported caveats that shaped our design:

* An 8B model is noticeably weaker than a hosted frontier model on obscure
  commands. We therefore ask the model for a **plan** with rationale and
  expected outcome, and a human approves it. The model never has a live
  shell.
* Tool calling reliability varies by local model. We use Ollama's JSON schema
  `format` option and validate the result with pydantic; unusable output is
  fed back to the model for a bounded number of repair attempts, and the
  operator can choose an explicit `--fallback dryrun` option (never
  automatic, always audited) to get a read-only checklist instead.

## 6. Decision

Build a small Python code base with two commands:

* `aiit-agent` on endpoints: collect, encrypt, apply signed plans, report.
* `aiit-console` on the operator machine: ingest, redact, plan with an LLM,
  approve and sign, record.

Reuse osquery (facts), Ollama or the Claude API (model), MeshCentral
(optional live access on a LAN), gitleaks and pre-commit (secret hygiene).
Keep the project under Apache-2.0 so hospitals, MSPs and vendors can adopt
it, and keep AGPL and source-available projects at arm's length (separate
process, network API) so their terms do not attach to this code.

## Sources

Verified directly (shallow clone of the default branch on 2026-10-08):
Ylianst/MeshCentral, amidaware/tacticalrmm, immense/Remotely, rustdesk/rustdesk,
fleetdm/fleet, osquery/osquery.

Secondary sources consulted:

* [MeshCentral vs Tactical RMM: Honest Comparison (2026)](https://breezermm.com/blog/meshcentral-vs-tactical-rmm/)
* [Open Source RMM Software: 30+ Tools Compared](https://www.openmsp.ai/blog/open-source-rmm-software)
* [Self-Hosted RMM Tools: Tactical RMM vs MeshCentral vs OpenRMM Guide](https://www.pistack.xyz/posts/2026-05-02-tactical-rmm-vs-meshcentral-vs-openrmm-self-hosted-remote-monitoring-management-guide/)
* [RustDesk vs MeshCentral: Self-Hosted Remote Desktop Compared (2026)](https://selfhosting.sh/compare/rustdesk-vs-meshcentral/)
* [Remotely on AlternativeTo (listed as discontinued)](https://alternativeto.net/software/remotely/about/)
* [NetLock RMM repository](https://github.com/0x101-Cyber-Security/NetLock-RMM)
* [ansible-heal-agent](https://github.com/adventurewave-labs/ansible-heal-agent)
* [auto-healing-agent](https://github.com/restrok/auto-healing-agent)
* [AI-Remote-Agent](https://github.com/airemoteagent/AI-Remote-Agent)
* [it-self-service-agent (Red Hat)](https://github.com/rh-ai-quickstart/it-self-service-agent)
* [Hermes Agent local Ollama setup](https://hermes-agent.nousresearch.com/docs/guides/local-ollama-setup)
* [Ollama air-gapped deployment guide](https://markaicode.com/tutorial/air-gapped-ai-deployment/)
* [Threat Hunting with FleetDM and Osquery](https://benheater.com/threat-hunting-fleetdm-osquery/)
* [OSQuery vs Wazuh Agent (2025)](https://cybersnowden.com/osquery-vs-wazuh-agent/)
* [Netdata support bundle](https://learn.netdata.cloud/docs/developer-and-contributor-corner/netdata-support-bundle)
* [Microsoft TSSv2](https://github.com/andreipintica/TSSV2)
* [NNCP package](https://launchpad.net/ubuntu/+source/nncp/8.9.0-1)
* [Microsoft Presidio overview](https://gittrend.io/repo/microsoft/presidio)
* [Gitleaks guide](https://docs.bike4mind.com/security/gitleaks-guide)
