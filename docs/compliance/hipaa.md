# HIPAA analysis and compliance design

This document separates three things: what the regulation requires (evidence),
what that implies for this software (inference), and what is still a judgment
call for the organization deploying it (speculation or policy).

## 1. Is any existing open source RMM "HIPAA compliant"?

Short answer: no product is, and none can be on its own.

* HHS does not certify software. HIPAA compliance is a property of a covered
  entity's or business associate's program: risk analysis, policies, training,
  contracts, and technical safeguards taken together (45 CFR 164.308 and
  164.312).
* A self-hosted open source tool has no vendor touching your data, so there is
  no business associate agreement (BAA) to sign for the software itself. That
  removes one obstacle. It also means every safeguard is on you.
* None of the projects reviewed (MeshCentral, Tactical RMM, RustDesk, Remotely,
  Fleet, osquery) publish a HIPAA control mapping. Each can be deployed inside a
  compliant program if you add access control, audit, encryption and policy
  around it. Commercial RMMs sell exactly that packaging plus a BAA.

The inference for this project: ship the technical safeguards in the code by
default, ship the paperwork templates in `docs/compliance/`, and make the
remaining organizational duties explicit.

## 2. Where PHI could appear in an IT support tool

Protected health information is health information tied to an identifier.
Diagnostic data from a clinic laptop can contain it even though the tool is
"just for IT":

| Data collected | PHI risk | Why |
|---|---|---|
| Event logs, application logs | High | Application crash messages often embed patient names, MRNs, file names like `Smith_John_MRI.pdf`, email subjects. |
| Running processes, window titles | Medium | Window titles and document paths. |
| User profile paths | Medium | `C:\Users\<name>` is a name. |
| Hostnames, IPs, MAC addresses | Low to medium | Safe Harbor lists IP addresses and device identifiers among the 18 identifiers. |
| Hardware inventory, driver list | Low | Rarely identifying. |
| Installed software list | Low | Could reveal an EHR vendor; not PHI by itself. |

So the design assumption is: **treat every bundle as if it contains PHI**.

### Residual exposure per collector

The redactor (`src/aiit/common/redact.py`) is a regex layer. The table below
says, collector by collector, what it catches and what it does not, so an
operator can decide what to exclude (`--quick` skips the collectors marked
*full only*) and what to add with `aiit-console ingest --redact <literal>`.
"Caught" means replaced with a per-case token or, for secrets, removed
irreversibly. Collector names are those in `src/aiit/agent/collectors.py`.

| Collector (OS) | Can carry | Redactor catches | Redactor does not catch |
|---|---|---|---|
| `application_errors_7d`, `system_errors_7d`, `windows_update`, `kernel_power_bugchecks` (Windows), `journal_errors`, `journal_boot`, `dmesg_err` (Linux), `log_errors_30m` (macOS) | Free-text crash and error messages: patient names, MRNs after a label, document paths, email subjects, usernames in paths, URLs with credentials. | Emails, phones, SSNs, labelled MRN and date of birth, user profile paths (`C:\Users\<name>`, `/home/<name>`, `/Users/<name>`), `DOMAIN\user`, SIDs, UNC server names, IPs, MACs, hostnames, secrets in key/value or header form, URL userinfo, harvested usernames. | **Names and addresses in prose**, file names that are a patient name without a profile path, MRNs with no label, dates of birth with no label, free-text clinical content. Highest-risk collectors; review `preview` output before any hosted provider call. |
| `processes_top` (all), `connections` / `listening` (Windows, Linux), `startup`, `scheduled_tasks` (Windows) | Window titles and document paths in command lines, usernames in process owner columns, remote IPs, URLs. | User paths, usernames harvested from the account collectors, IPs, MACs, URL credentials, secrets passed as flags (`--password x`, `-p'x'`). | A document name in a command line argument, an application-specific identifier format. |
| `computerinfo`, `systeminfo`, `hostnamectl`, `hardware` (macOS `SPHardwareDataType` / `SPSoftwareDataType`), osquery `system_info` | Hostname, registered owner and organisation, logged-on user, serial number, UUIDs, machine id, domain. | Labelled hostname, computer name, domain, DNS suffix, user name, registered owner and organisation, serial numbers, UUID/UDID/machine id (when labelled), harvested usernames. | Unlabelled serial-looking strings; an owner name that appears elsewhere without its label is caught only because the labelled value is propagated through the whole file. |
| `local_users`, osquery `logged_in_users` | Account names, display names. | Account names (harvested into the redaction literals for the whole case); `Display Name (account)` pairs. | Display names that differ from the account name and appear only here without a label. |
| `ipconfig`, `adapters`, `routes`, `dns`, `ip_addr`, `ip_route`, `resolv_conf`, `ifconfig`, `network`, osquery `interface_addresses` | IP addresses (public by default; private optional), MAC addresses, DNS suffixes, hostnames. | Public IPv4 and IPv6, MACs, labelled DNS suffixes and hostnames, UNC server names. Private IPs with `--redact-private-ips`. | Private IPs by default (deliberate: the model often needs them for network diagnosis); network names that are a site name. |
| `installed_software`, `hotfixes`, `drivers`, `pnp_errors`, `services`, `services_stopped_auto`, `launchd`, `running_services`, `failed_units` | Vendor and product names (may reveal an EHR vendor), service accounts. | `DOMAIN\user` service accounts, SIDs. | Product names; not PHI by themselves. |
| `volumes`, `disks`, `disk_df`, `lsblk`, `mounts`, `storage`, `diskutil`, `disk_usage`, osquery `disk_encryption` | Volume labels, mounted share paths with server names. | UNC server names, user paths on mounted volumes. | A volume label that is a person's name. |
| `hosts_file`, `fstab`, `crontab`, `proxy`, `apt_history` | Hostnames and IPs, share paths, proxy credentials, cron entries with user paths. | Hostnames (when labelled or when in the hostname list), IPs, URL userinfo, user paths. | Hostnames in `/etc/hosts` that are not labelled and not the endpoint's own name. Add them with `--redact`. |
| `env_names` | Names of environment variables only. | Values are never collected. | A variable *name* that embeds a username (`USERPROFILE_JSMITH`); rare. |
| `defender`, `bitlocker`, `firewall_profiles`, `security`, `power`, `printers`, `battery`, `updates_history`, `uptime*`, `os_release`, `uname`, `sw_vers`, `python_platform` | Little; printer names and node name. | Hostname in `python_platform` (`node`), labelled values. | A printer name that is a person's name. |

Two environment switches matter for this table. `AIIT_HIPAA_MODE=1` keeps
Anthropic requests on the generally available, BAA-covered API surface by
disabling beta features (server-side refusal fallbacks); set it on every
console that handles PHI. `AIIT_ALLOW_HOSTED=1` (or `--allow-hosted`),
arriving in PR 2, is required before any hosted provider is used at all; the
console refuses otherwise, which makes "nothing leaves this machine" the
default rather than a convention.

## 3. Technical safeguards: 45 CFR 164.312 mapped to controls

The standard text below is paraphrased from the regulation (Cornell LII copy of
45 CFR 164.312). "R" is a required implementation specification, "A" is
addressable. Addressable does not mean optional: you implement it, or document
why not and what you did instead.

| Standard / spec | R/A | How AI_IT implements it | Status |
|---|---|---|---|
| (a)(1) Access control | Std | Console data dir is `0700`; one console identity per operator; agents trust a single console key. | Implemented (local). RBAC for multi-operator deployments is on the roadmap. |
| (a)(2)(i) Unique user identification | R | Every audit entry records the OS user and the console id; approvals carry `approved_by`. | Implemented. Multi-user accounts with MFA: roadmap (reverse proxy or OS login today). |
| (a)(2)(ii) Emergency access procedure | R | Keys can be backed up to an offline, sealed envelope; documented procedure template. | Policy template only. |
| (a)(2)(iii) Automatic logoff | A | Console is a CLI running under the OS session; rely on OS screen lock policy. Web UI (roadmap) will add an idle timeout. | Delegated to OS. |
| (a)(2)(iv) Encryption and decryption | A | Bundles are AES-256-GCM encrypted with a key derived from X25519 ECDH to the console key before they leave the endpoint. Case store at rest relies on full disk encryption (BitLocker, FileVault, LUKS) which the install checklist requires. | Implemented in transit and on removable media. At-rest key wrapping of the case store is roadmap. |
| (b) Audit controls | Std | Hash-chained JSONL audit log on both console and agent: ingest, redaction, model call (provider, model, token counts, no content), approval, each executed step with exit code. `aiit-console audit-verify` detects tampering. | Implemented. SIEM export: roadmap. |
| (c)(1) Integrity, (c)(2) Mechanism to authenticate ePHI | A | Every file in a bundle has a SHA-256 in the manifest; the whole bundle is authenticated by AES-GCM and signed by the agent key; plans are Ed25519 signed by the console. | Implemented. |
| (d) Person or entity authentication | Std | Agent to console: Ed25519 agent signature plus trust-on-first-use registry. Console to agent: Ed25519 plan signature bound to agent id, case id and expiry. LAN mode: shared token plus TLS. | Implemented (TOFU). Per-agent enrollment approval: roadmap. |
| (e)(1) Transmission security, (e)(2)(i) Integrity controls, (e)(2)(ii) Encryption | A | Application-layer encryption and signatures apply identically to USB and LAN transport, so transport TLS is defense in depth, not the only control. | Implemented. |

## 4. Administrative safeguards: 45 CFR 164.308 (organizational duties)

The software cannot do these for you; the repo ships templates so a small
clinic or MSP can start from something:

* Risk analysis and risk management (164.308(a)(1)):
  [`docs/compliance/risk-analysis-template.md`](risk-analysis-template.md),
  a worksheet with the asset inventory, threat and risk tables, the control
  mapping to 164.308 and 164.312 and a review schedule.
* Information system activity review: `aiit-console audit-verify` plus a
  monthly review checklist.
* Workforce security and sanction policy: who may hold a console key.
* Security awareness and training: operator runbook (roadmap).
* Security incident procedures: SECURITY.md plus breach notification steps.
* Contingency plan: key backup and bundle retention.
* Business associate contracts: required for any cloud LLM that could see PHI.

## 5. The LLM is the business associate question

If a diagnostic bundle can contain PHI and you send it to a hosted model, that
model provider is creating, receiving, maintaining or transmitting PHI on your
behalf and needs a BAA. Three options, in order of preference for a HIPAA
deployment:

1. **Local model (default).** Ollama on the operator machine. No third party.
   Weaker models, so plans need closer review.
2. **Anthropic API with a signed BAA.** Per Anthropic's documentation
   (platform.claude.com, "API and data retention", and the support article on
   BAAs for commercial customers): HIPAA-ready API access is arranged through
   sales, a dedicated organization is provisioned with HIPAA readiness controls,
   non-eligible features return a 400 error, and the BAA does not cover
   Workbench and Console, consumer plans, Cowork, or beta features. Zero data
   retention is a separate arrangement. Note from the current model
   documentation: `claude-fable-5-1` requires 30-day data retention and is not
   available under zero data retention unless Anthropic expressly authorizes
   it, so a ZDR org should use `claude-opus-5-5`, which is this project's
   default.
3. **Any other hosted model without a BAA.** Only with redaction verified
   good enough that no PHI remains. Our regex redactor is not sufficient for
   that claim on its own; Presidio-grade NLP plus a measured test set would be
   required, and that is still a de-identification judgment your privacy
   officer must sign off.

Regardless of option, the console always redacts before the model call and
logs the provider, model and token counts (never content) in the audit chain.

## 6. The proposed Security Rule update

Evidence from secondary sources (hipaajournal.com, pact-one.com, cyberz.pro,
medcurity.com) as of September 2026:

* HHS published a proposed rule on 2025-01-06; comments closed 2025-03-07.
* The proposal removes the "addressable" category, making encryption of ePHI
  at rest and in transit mandatory, requires MFA, asset inventories, network
  maps, 72-hour restoration capability, and regular vulnerability scanning and
  penetration testing.
* The final rule slipped; the Fall 2026 Unified Agenda lists July 2027 as the
  anticipated date, with roughly 240 days after that before compliance is
  enforced. Timelines are not binding.

Inference: build to the proposed rule now. That is why encryption and
signatures are on by default and not configurable off, and why MFA for the
console and an asset inventory export are on the roadmap rather than optional.

## 7. Deployment checklist for a HIPAA environment

1. Operator machine has full disk encryption and OS login with MFA or a
   smart card.
2. `AIIT_KEY_PASSPHRASE` set so private keys are encrypted at rest.
3. Default provider is `ollama`; `anthropic` only after the BAA is signed and
   the HIPAA-ready org is provisioned; API key lives in the console's `.env`
   only (`<console dir>/.env` or `AIIT_ENV_FILE`, never the working
   directory). Set `AIIT_HIPAA_MODE=1` so no beta feature is used, and (from
   PR 2) `AIIT_ALLOW_HOSTED=1` as the explicit, audited decision that data
   may leave the machine.
4. Retention: decide how long case folders stay; the default is forever, so
   schedule deletion. Audit logs are typically kept six years (secondary
   sources cite this period; confirm with counsel).
5. Removable media used for bundles is encrypted anyway, but still inventory
   and wipe it.
6. Review `aiit-console audit-verify` output monthly and keep the report.
7. Sign a BAA with any MSP that operates the console on your behalf.

## Sources

* [45 CFR 164.312 Technical safeguards (Cornell LII)](https://www.law.cornell.edu/cfr/text/45/164.312)
* [HIPAA Security Rule Technical Safeguards: complete requirements list](https://www.accountablehq.com/post/hipaa-security-rule-technical-safeguards-the-complete-requirements-list-45-cfr-164-312)
* [New HIPAA Regulations in 2026 (HIPAA Journal)](https://www.hipaajournal.com/new-hipaa-regulations/)
* [Is the HIPAA Security Rule Final in 2026?](https://www.pact-one.com/2026/09/hipaa-security-rule-2026-status/)
* [HIPAA Security Rule Changes in 2026: what changed and what slipped to 2027](https://cyberz.pro/blog/2026/07/30/hipaa-security-rule-changes-2026/)
* [2026 HIPAA Security Rule Update (Medcurity)](https://medcurity.com/hipaa-security-rule-2026-update/)
* [Anthropic: API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention)
* [Anthropic: Business Associate Agreements for commercial customers](https://support.claude.com/en/articles/8114513-business-associate-agreements-baa-for-commercial-customers)
* [Anthropic: I need to be HIPAA compliant, can I use Claude?](https://privacy.claude.com/en/articles/8956058-i-need-to-be-hipaa-compliant-can-i-use-claude)
* [HIPAA Compliant Remote Access: requirements, tools, best practices](https://www.accountablehq.com/post/hipaa-compliant-remote-access-requirements-tools-and-best-practices)
