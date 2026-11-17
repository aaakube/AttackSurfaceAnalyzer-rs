# What is collected

`asa collect` runs every collector by default: `files, services, firewall, com, registry,
users, certificates, ports, wifi, tasks, defender, rights, security, wmi, tpm, keys`.
`--collectors files,services,...` picks some.

Collectors read files, the registry and Win32 APIs directly. There is no PowerShell, and WMI
is used only where the data lives nowhere else (WMI subscriptions and the TPM). This keeps
collection fast and offline.

Runtime state (running or stopped) is deliberately not collected: it changes constantly and is
not attack surface. Secrets are never read: no private keys, Wi-Fi keys or passwords.

## What each collector watches for

- **files:** unsigned or tampered binaries, missing ASLR/DEP/CFG, anything non-admins can write
- **services and drivers:** new SYSTEM services, unquoted paths, writable binaries or service
  keys, unsigned drivers
- **firewall:** new inbound openings, disabled profiles, allow-by-default
- **COM:** elevation-enabled classes, service-hosted servers, per-user hijacks of machine classes
- **registry:** Run keys, IFEO debuggers, AppInit/AppCert DLLs, Winlogon, LSA packages,
  policies, installed programs, and more
- **users and groups:** new accounts, privileged group membership, Guest enabled, no password
- **certificates:** rogue trusted roots (including via Group Policy), trusted publishers,
  removed distrust, weak signatures
- **ports:** new listeners on all interfaces, unsigned or user-writable listening programs
- **Wi-Fi:** open or weak networks, auto-connect, keys stored in clear text
- **tasks:** privileged scheduled tasks, script hosts, writable or missing binaries
- **defender:** new exclusions, disabled protections, attack surface reduction rules
- **rights:** sensitive privileges granted to unexpected accounts
- **security:** UAC, WDigest, LSA protection, NTLM, SMBv1 and signing, RDP
- **WMI:** permanent event subscriptions (a classic persistence technique)
- **TPM and keys:** TPM state, Secure Boot, machine keys readable by non-admins

## Fields

| Kind | Identity | Main fields |
|---|---|---|
| `file` | path | see [below](#files) |
| `service`, `driver` | service name | `display_name`, `type`, `start`, `delayed_start`, `account`, `image_path`, `binary`, `unquoted_path`, `service_dll`, `failure_command`, `binary_missing`, `binary_signature.*`, `binary_writable_by`, `key_writable_by` |
| `firewall` | `rule\<store>\<id>`, `profile\<store>\<profile>` | rules: `name`, `action`, `direction`, `enabled`, `profiles`, `protocol`, `local_ports`, `remote_ports`, `remote_addresses`, `program`, `service`; profiles: `firewall_enabled`, `default_inbound`, `default_outbound`. Store is `local` or `gpo`. |
| `com` | `clsid\{..}`, `clsid32\{..}`, `user\<sid>\clsid\{..}`, `appid\{..}`, `typelib\{..}` | classes: `name`, `progid`, `inproc_server`, `local_server`, `server`, `server_signature.*`, `server_writable_by`, `elevation`, `shadows_machine`; AppIDs: `local_service`, `run_as`, `dll_surrogate`, `launch_permission`, `access_permission`; type libraries: `versions` |
| `registry` | key path (`HKLM\...`, `HKU\<sid>\...`) | `values.<name>`, `subkeys` (at the depth limit), `writable_by` |
| `user` | `user\<name>` | `sid`, `enabled`, `password_required`, `password_expires`, `password_changeable`, `builtin`, `groups`, `group_sids`, `administrator`, `privileged_groups` (no last-logon or password age: they change constantly) |
| `group` | `group\<name>` | `sid`, `members`, `member_sids`, `privileged`, `privilege` |
| `certificate` | `cert\<location>\<store>\<thumbprint>` | `location` (group_policy, enterprise, machine, user), `store`, `subject`, `issuer`, `serial`, `not_before`, `not_after`, `self_signed`, `has_private_key`, `key_algorithm`, `key_bits`, `signature_algorithm`, `purposes` |
| `port` | `tcp\<address>:<port>`, or `tcp\dynamic\<program>` | `protocol`, `address`, `port`, `scope` (any, loopback, specific), `process`, `services`, `process_signature.*`, `process_writable_by`. Listeners on the dynamic range (49152+) get a new port each boot, so they are grouped per program; PIDs are never stored. |
| `task` | `task\<task path>` | `path`, `author`, `description`, `enabled`, `hidden`, `run_as`, `run_level`, `logon_type`, `privileged`, `triggers`, `actions`, `binary`, `arguments`, `working_directory`, `com_handler`, `script_host`, `binary_missing`, `binary_signature.*`, `binary_writable_by`. Parsed from `System32\Tasks`; the few files that deny administrators are read with backup rights. |
| `defender` | `defender\exclusion\<source>\<category>\<value>`, `defender\settings` | exclusions: `source` (local / policy), `category` (path, extension, process, ip, asr, cfa_app), `value`, `writable_by`; settings: `realtime_protection`, `behavior_monitoring`, `scan_downloads`, `script_scanning`, `disabled_by_policy`, `tamper_protection`, `cloud_protection`, `sample_submission`, `pua_protection`, `controlled_folder_access`, `asr_rules`. Policy overrides local, as in Defender. |
| `right` | `right\<SeXxx>` | `name`, `description`, `sensitive`, `members`, `sids`, `unexpected_members`. Every right is listed, held or not, so a first grant is a modification. |
| `security` | `security\options` | `uac_enabled`, `uac_admin_prompt`, `uac_secure_desktop`, `remote_uac_filtering`, `builtin_admin_approval`, `wdigest_plaintext`, `lsa_protection`, `credential_guard`, `lm_compatibility_level`, `lm_hash_stored`, `ntlm_outgoing`, `restrict_anonymous`, `restrict_anonymous_sam`, `everyone_includes_anonymous`, `smb1_server`, `smb1_client`, `smb_server_signing_required`, `smb_client_signing_required`, `smb_insecure_guest_logons`, `remote_desktop`, `rdp_nla`. Policy wins; unset values take Windows' defaults. |
| `wmi` | `wmi\<namespace>\filter\<name>`, `...\consumer\<class>\<name>`, `...\binding\<filter> -> <consumer>` | Permanent event subscriptions in `root\subscription` and `root\default`: filters (`query`, `query_language`, `event_namespace`), consumers (`class`, `command_line`, `executable`, `script_engine`, `script_text`, `script_file`, `target`, `binary`, `binary_signature.*`, `binary_writable_by`) and bindings. |
| `tpm` | `tpm` | `present`, `enabled`, `activated`, `owned`, `manufacturer`, `manufacturer_version`, `spec_version`, `secure_boot` |
| `key` | `key\machine\<provider>\<container>` | Machine keys of the software and TPM key storage providers: `provider`, `name`, `algorithm`, `length`, `legacy`, `exportable`, `plaintext_exportable`, `file`, `readable_by` (who besides administrators can copy the key file). Key material is never read. |
| `wifi` | `wifi\<adapter>\<profile>` | `ssid`, `connection_mode`, `hidden_network`, `authentication`, `encryption`, `uses_802_1x`, `key_type`, `key_protected` |

### Files

| Field | Notes |
|---|---|
| `path`, `file_type`, `size`, `modified`, `target` | `modified` is left out for directories (it changes whenever an entry is added). |
| `hidden`, `system`, `readonly` | File attributes. |
| `owner`, `owner_sid`, `sddl` | Owner and DACL. Rules should match on SIDs, because account names are localized. |
| `writable_by` | Low-privileged principals (Everyone, Users, Authenticated Users, Interactive, Guests, Anonymous, Domain Users) that can write, append, change permissions or take ownership. Inherit-only ACEs are ignored and deny ACEs are honoured. The same model applies to service binaries, COM servers and registry keys. |
| `executable`, `format` | `pe` (confirmed by the MZ header), `msi` or `script`. |
| `pe.*` | `machine`, `subsystem`, `dll`, `dotnet`, `aslr`, `high_entropy_va`, `dep`, `cfg`, `force_integrity`, `appcontainer`. `aslr` is false when relocations are stripped. |
| `signature.*` | `status` (valid / unsigned / invalid / untrusted / expired / revoked / distrusted), `source` (embedded / catalog), `signer`. Like Windows, a file is valid if either its embedded or a catalog signature verifies. Checks run offline. |
| `hash` | With `--hash`. |

## Registry locations

The registry collector covers persistence and policy locations: Run/RunOnce (machine, 32-bit
and every loaded user), Winlogon, Windows (AppInit_DLLs), Image File Execution Options,
SilentProcessExit, Session Manager (BootExecute, KnownDLLs, AppCertDlls), LSA, security
providers, print monitors, network providers, Terminal Server, Active Setup, Browser Helper
Objects, shell extensions, the COM auto-approval list, Policies (machine and user), uninstall
entries, and the top-level vendor keys of `HKLM\SOFTWARE`.

Add your own with `--registry-key KEY[:DEPTH]` (repeatable). For example
`--registry-key HKLM\SOFTWARE\Vendor:2` walks that key and two levels of subkeys, and
`HKCU\...` means every loaded user hive. `--no-default-registry` collects only your keys.
