# Claims register

Every promise Sentinel Vision makes in public (the website, the README and SECURITY.md) is listed here with the code
that keeps it and the test that proves it. `tests/test_claims.py` fails the build if a test named here no longer exists,
and if a feature on the website has no row here. A change that adds or rewords a claim updates this file in the same
pull request (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

**Status**

* **Tested**: unit or integration tests run on every pull request (Windows, macOS and Linux).
* **Tested (Windows CI)**: checked end to end on a real Windows install by `packaging/windows/test-installer.ps1` or
  `test-upgrade.ps1`, which run for every release build.
* **Tested (online, weekly)**: needs the live services; runs weekly in `integration.yml` (`SV_ONLINE=1`).
* **Tested (weekly audit)**: the false-positive audit in `fp-audit.yml` scans everyday software every week.
* **Review**: a design property checked by reading the code, not by an automated test. Say so if you rely on it.

Last reviewed: 0.5.2, 2026-10-31.

## Website: "What it protects you from"

| Claim | Implementation | Evidence | Status |
|---|---|---|---|
| Ransomware: decoy files and a watch on how quickly documents change catch encryption while it's happening | `ransomware.py` | `tests/test_ransomware.py::test_decoys_are_planted_and_trip_on_modification`<br>`tests/test_ransomware.py::test_mass_encryption_burst_trips_and_normal_edits_do_not`<br>`tests/test_ransomware.py::test_slow_encryption_below_the_burst_rate_still_trips`<br>`tests/test_ransomware.py::test_intermittent_encryption_with_intact_header_is_detected` | Tested |
| Ransomware: the program responsible is paused, so you decide whether to end it | `ransomware.py`, `behavior.py` | `tests/test_ransomware.py::test_suspect_is_suspended_and_resumable` | Tested |
| Ransomware: earlier versions are kept, encrypted, in a rollback vault; pick a time and every file changed since goes back | `vault.py`, `servicecore.py` | `tests/test_ransomware.py::test_vault_versions_dedup_restore_and_encryption_at_rest`<br>`tests/test_ransomware.py::test_rollback_to_point_in_time`<br>`tests/test_ransomware.py::test_vault_retention_by_age`<br>`tests/test_ransomware.py::test_vault_flood_is_refused_and_good_versions_survive`<br>`tests/test_audit_regressions.py::test_vault_flood_cannot_evict_good_versions`<br>`tests/test_vault_reserve.py::test_a_flood_of_first_versions_cant_block_edits_of_established_documents` | Tested |
| Dangerous websites: lists of malware and phishing sites are checked on your computer and can be blocked for every browser and app | `webshield.py`, `systemblock.py` | `tests/test_webshield.py::test_list_parsing_handles_every_common_format`<br>`tests/test_webshield.py::test_intel_lookup_store_filter_and_parent_match`<br>`tests/test_webshield.py::test_hosts_block_is_idempotent_and_removable`<br>`tests/test_webshield.py::test_hosts_for_blocking_prioritises_malware` | Tested |
| Link checker spots new scam sites that imitate a brand, before they're on any list | `webshield.py` | `tests/test_webshield.py::test_link_checker_heuristics`<br>`tests/test_webshield.py::test_link_checker_uses_intel` | Tested |
| Suspicious connections: every connection, which program made it, whether the address is on a botnet or criminal list; end or block in one click | `network/` | `tests/test_network_and_intel.py::test_network_classification`<br>`tests/test_network_and_intel.py::test_network_poll_snapshot`<br>`tests/test_network_and_intel.py::test_firewall_validation`<br>`tests/test_seams.py::test_net_block_refuses_anything_but_public_addresses` | Tested |
| Weak settings: the checkup reviews firewall, disk encryption, updates, remote access, Wi-Fi and router safety | `advisor.py` | `tests/test_advisor.py::test_full_checkup_runs_on_this_machine`<br>`tests/test_advisor.py::test_netsh_firewall_parser`<br>`tests/test_advisor.py::test_route_arp_dns_wifi_winget_parsers`<br>`tests/test_advisor.py::test_score_weights` | Tested |
| Weak settings: nothing is changed without you | `advisor.py` only reads system state | Code review: the checkup runs read-only queries; fixes are shown as instructions | Review |
| No machine-learning model; nothing is sent to AI services | whole source tree | `tests/test_audit_regressions.py::test_no_ai_service_hosts_in_source` | Tested |

## Website: "Also included"

| Claim | Implementation | Evidence | Status |
|---|---|---|---|
| Real-time file checks: new and changed files against hash lists, YARA rules, ClamAV when installed, and heuristics | `realtime.py`, `scanner.py`, `engines/` | `tests/test_app.py::test_realtime_catches_dropped_file`<br>`tests/test_engines.py::test_eicar_detected_by_hash_and_yara_and_quarantined`<br>`tests/test_network_and_intel.py::test_clamd_instream_protocol`<br>`tests/test_engines.py::test_heuristic_powershell_cradle` | Tested |
| Real-time file checks: more than 5,000 YARA rules | `updater.py` (YARA Forge core), `engines/yara_engine.py` | `tests/test_online.py::test_every_default_feed_downloads_and_parses` | Tested (online, weekly) |
| Encrypted quarantine: detected files are encrypted so they can't run, and can be restored | `quarantine.py`, `secretbox.py` | `tests/test_quarantine.py::test_roundtrip_multi_chunk`<br>`tests/test_quarantine.py::test_tampering_is_detected`<br>`tests/test_quarantine.py::test_truncation_is_detected`<br>`tests/test_quarantine.py::test_restore_does_not_overwrite` | Tested |
| Memory scan: finds malware that runs only in memory | `memscan.py` | `tests/test_memscan.py::test_memory_scan_finds_injected_marker_in_running_process` | Tested |
| USB drive checks: removable drives are scanned when connected | `devices.py` | `tests/test_devices.py::test_usb_insertion_triggers_scan`<br>`tests/test_devices.py::test_drive_watcher_reports_only_new_drives` | Tested |
| Scheduled scans: daily quick and weekly full, caught up if the computer was off | `devices.py` | `tests/test_devices.py::test_schedule_due_logic` | Tested |
| Camera and microphone alerts (Windows and Linux) | `devices.py` | `tests/test_devices.py::test_privacy_monitor_reports_new_users_once`<br>`tests/test_devices.py::test_linux_device_use_runs` | Tested |
| Password breach check without sending the password | `reputation.py` (k-anonymity range API) | `tests/test_webshield.py::test_pwned_password_range_parsing_and_privacy`<br>`tests/test_online.py::test_pwned_passwords_api` | Tested |
| File shredder: overwrites files before deleting them (SSDs and synced folders may keep copies) | `devices.py` | `tests/test_devices.py::test_shredder` | Tested |
| Router and DNS checks: router impersonation and DNS pointing at a known bad server | `advisor.py` | `tests/test_advisor.py::test_netguard_detects_router_spoofing_and_bad_dns`<br>`tests/test_advisor.py::test_browser_dns_check_flags_browsers_that_bypass_blocking` | Tested |
| Tamper protection (Windows): quarantine, vault and settings out of reach of programs running with your rights | `servicecore.py`, `winservice.py`, `service_client.py` | `tests/test_servicecore.py::test_users_cannot_see_each_others_vault_or_quarantine`<br>`tests/test_servicecore.py::test_protected_policy_wins_over_a_tampered_settings_file`<br>`tests/test_audit_regressions.py::test_pipe_acl_does_not_grant_generic_write`<br>`tests/test_audit_regressions.py::test_installed_build_never_falls_back_to_local_storage`<br>`packaging/windows/test-installer.ps1` | Tested, Tested (Windows CI) |
| Tamper protection: turning protection off needs administrator approval | `servicecore.py`, `protect.py` | `tests/test_servicecore.py::test_weakening_needs_admin_and_is_recorded`<br>`tests/test_servicecore.py::test_stopping_protection_needs_admin`<br>`tests/test_servicecore.py::test_elevated_helper_shows_and_applies_only_confirmed_changes` | Tested |
| Tamper protection: restoring a quarantined file needs administrator approval | `servicecore.py` (`quarantine.release`) | `tests/test_servicecore.py::test_quarantine_release_is_one_time_and_needs_an_administrator`<br>`tests/test_audit_regressions.py::test_quarantine_open_requires_elevation` | Tested |
| Tamper protection: the app is restarted if something closes it | `winservice.py` (watchdog) | `packaging/windows/test-installer.ps1` | Tested (Windows CI) |
| Tamper protection: if the service is stopped, the app warns you and keeps settings at full strength | `core.py`, `gui/app.py` | `tests/test_degraded.py::test_weakened_local_settings_are_raised_to_full_strength`<br>`tests/test_degraded.py::test_the_window_shows_the_degraded_banner`<br>`tests/test_degraded.py::test_reconnecting_switches_to_protected_storage` | Tested |
| Firewall blocking (Windows): known-malicious networks blocked in Windows Firewall for the whole computer | `servicecore.py`, `network/firewall.py` | `tests/test_servicecore.py::test_machine_wide_blocking_on_freely_off_with_admin`<br>`tests/test_servicecore.py::test_firewall_rules_never_block_local_or_huge_ranges`<br>`tests/test_audit_regressions.py::test_feed_network_floor`<br>`tests/test_audit_regressions.py::test_feed_hosts_are_never_blocked` | Tested |
| Signed updates: ML-DSA-65 (FIPS 204) and Ed25519; refuses an update that fails either check or is older | `pqsign.py`, `app_update.py`, `trust.py` | `tests/test_pqsign.py::test_every_tampering_is_rejected`<br>`tests/test_autostart_update.py::test_installer_requires_valid_pq_signature_and_hash`<br>`tests/test_autostart_update.py::test_downgrade_is_refused`<br>`tests/test_autostart_update.py::test_service_update_runs_only_a_verified_newer_installer_once` | Tested |

## Website: "Everything that leaves your computer" and privacy

| Claim | Implementation | Evidence | Status |
|---|---|---|---|
| The ledger is the complete list of hosts the app contacts | `site/build.py` (`LEDGER`) | `tests/test_ledger.py::test_every_host_in_the_app_is_in_the_ledger`<br>`tests/test_audit_regressions.py::test_ledger_names_every_publisher` | Tested |
| No telemetry; files never leave the computer (only hashes, addresses and update checks) | `reputation.py`, `updater.py`, `app_update.py` | Same ledger tests; code review of every request site | Tested, Review |
| Every bundled component is listed with its licence | `tools/third_party_notices.py` | `tests/test_ledger.py::test_licences_page_lists_every_runtime_dependency`<br>`tests/test_ledger.py::test_vendored_licence_texts_are_the_official_ones` | Tested |

## README: "Security design"

| Claim | Implementation | Evidence | Status |
|---|---|---|---|
| Never executes what it scans; archive members are parsed in memory | `scanner.py`, `engines/` | `tests/test_engines.py::test_detection_inside_zip_and_nested_tar`<br>`tests/test_claims.py::test_no_shell_or_exec_of_scanned_content` | Tested, Review |
| Hardened parsing: size caps, decompression-bomb checks, YARA timeouts, engine error boundaries | `scanner.py` | `tests/test_engines.py::test_zip_bomb_is_flagged_not_expanded`<br>`tests/test_archive_budget.py::test_listing_stops_at_the_byte_budget`<br>`tests/test_archive_budget.py::test_listing_stops_at_the_time_budget`<br>`tests/test_engines.py::test_oversized_files_are_skipped`<br>`tests/test_engines.py::test_yara_is_safe_under_concurrent_scans` | Tested |
| Safe updates: only the bundled certificate list is trusted; rule archives can't escape their folder | `updater.py`, `network/` | `tests/test_tls.py::test_only_the_bundled_certificate_list_is_trusted`<br>`tests/test_tls.py::test_compromised_emsign_roots_are_not_trusted`<br>`tests/test_network_and_intel.py::test_yara_zip_extraction_is_traversal_safe` | Tested |
| Encrypted quarantine with tamper, reorder and truncation detection; restores never overwrite | `quarantine.py` | `tests/test_quarantine.py::test_tampering_is_detected`<br>`tests/test_quarantine.py::test_truncation_is_detected`<br>`tests/test_quarantine.py::test_restore_does_not_overwrite` | Tested |
| Careful automatic actions: only confirmed malware is ended or removed; pattern hits on signed programs and system files are report-only | `policy.py`, `behavior.py`, `scanner.py` | `tests/test_behavior.py::test_pattern_hits_on_signed_programs_are_report_only`<br>`tests/test_rules.py::test_system_files_are_never_auto_quarantined_on_pattern_matches`<br>`tests/test_behavior.py::test_confirmed_malware_process_is_terminated`<br>`tests/test_engines.py::test_report_only_mode_keeps_file`<br>`tests/test_policy.py::test_quarantine_decisions` | Tested, Tested (weekly audit) |
| Service accepts only well-formed, known requests, rate-limits changes and limits transfers | `servicecore.py`, `winservice.py` | `tests/test_service_limits.py::test_unknown_arguments_and_operations_are_refused`<br>`tests/test_service_limits.py::test_changing_requests_are_rate_limited`<br>`tests/test_service_limits.py::test_at_most_four_transfers_and_idle_ones_expire`<br>`tests/test_audit_regressions.py::test_policy_rejects_non_finite_and_wrong_types` | Tested |
| The vault only keeps files from protected folders and restores never write through a link | `servicecore.py`, `vault.py` | `tests/test_service_limits.py::test_vault_only_keeps_files_in_protected_folders`<br>`tests/test_service_limits.py::test_vault_refuses_paths_that_escape_a_protected_folder`<br>`tests/test_service_limits.py::test_restore_never_writes_through_a_link` | Tested |
| A flood of new files can't fill the vault for good: a fifth stays for documents it already holds, new files have an hourly byte budget, and a full vault is a lasting dashboard warning | `vault.py`, `servicecore.py`, `gui/pages/dashboard.py` | `tests/test_vault_reserve.py::test_a_flood_of_first_versions_cant_block_edits_of_established_documents`<br>`tests/test_vault_reserve.py::test_first_versions_count_against_a_byte_budget_per_hour`<br>`tests/test_vault_reserve.py::test_the_full_mark_lasts_until_there_is_room`<br>`tests/test_vault_reserve.py::test_a_tiny_file_that_still_fits_does_not_clear_the_warning`<br>`tests/test_vault_reserve.py::test_the_service_reports_the_full_mark`<br>`tests/test_vault_reserve.py::test_the_dashboard_warns_while_the_vault_is_full` | Tested |
| The service's pipe rejects remote clients and ordinary accounts can't impersonate it | `winservice.py` | `tests/test_audit_regressions.py::test_pipe_acl_does_not_grant_generic_write`<br>`packaging/windows/test-installer.ps1` | Tested (Windows CI) |
| Administrator prompts only ever run a program that only administrators can change | `webshield.py` (`elevation_problem`) | `tests/test_elevation.py::test_user_owned_program_is_refused_with_instructions`<br>`tests/test_elevation.py::test_running_from_source_is_never_elevated` | Tested |
| Installed builds ignore developer environment variables | `config.py`, `policy.py`, `service_client.py` | `tests/test_audit_regressions.py::test_installed_build_ignores_developer_variables`<br>`tests/test_degraded.py::test_the_windows_folder_comes_from_windows_not_the_environment` | Tested |
| Plugins only with consent, from an administrator-only folder; a broken plugin is never fatal | `plugins.py` | `tests/test_plugins.py::test_python_plugins_are_found_and_only_shown_after_approval`<br>`tests/test_plugins.py::test_installed_app_loads_only_from_the_protected_folder`<br>`tests/test_plugins.py::test_a_broken_plugin_cannot_crash_the_app`<br>`tests/test_plugins.py::test_allowing_a_plugin_needs_administrator_approval_with_the_service`<br>`tests/test_plugins.py::test_the_old_agent_guard_plugin_is_refused` | Tested |
| Companion programs get a published command-line contract (`docs/plugin-contract.json`) that the real tool is tested against; a file refused on purpose exits with 3 and is never moved | `cli.py`, `quarantine.py` (`external_target`), `docs/plugin-contract.json` | `tests/test_plugin_contract.py::test_the_contract_describes_this_version`<br>`tests/test_plugin_contract.py::test_quarantine_add`<br>`tests/test_plugin_contract.py::test_quarantine_add_refuses_a_link`<br>`tests/test_plugin_contract.py::test_plugin_log`<br>`tests/test_plugin_contract.py::test_net_block`<br>`tests/test_plugin_contract.py::test_scan` | Tested |
| No shell, ever; IPs validated before firewall rules; private addresses can't be blocked | `network/firewall.py`, whole source tree | `tests/test_claims.py::test_no_shell_or_exec_of_scanned_content`<br>`tests/test_network_and_intel.py::test_firewall_validation`<br>`tests/test_seams.py::test_netsh_rule_names_are_passed_the_way_netsh_expects` | Tested |
| The app's own files are never detected; anything else in its data folder is | `scanner.py` | `tests/test_engines.py::test_own_install_and_data_dirs_are_excluded`<br>`tests/test_data_folder.py::test_own_files_are_skipped_and_anything_else_is_scanned`<br>`tests/test_audit_regressions.py::test_data_folder_is_scanned_for_programs` | Tested |
| Settings files with out-of-range or wrong-type values fall back to safe defaults | `config.py`, `schema.py` | `tests/test_audit_regressions.py::test_settings_out_of_range_fall_back_to_defaults` | Tested |
| Updates install through the service on Windows, with no administrator prompt | `app_update.py`, `winservice.py`, `SentinelVision.iss` | `tests/test_autostart_update.py::test_service_update_runs_only_a_verified_newer_installer_once`<br>`tests/test_autostart_update.py::test_update_op_needs_the_windows_service_and_is_rate_limited`<br>`packaging/windows/test-upgrade.ps1` | Tested; the full download-and-install path is first exercised by the release after 0.5.0 |

## Known gaps

* "Nothing is changed without you" in the checkup and "files never leave your computer" rely on code review. A test
  that monkeypatches every network and system-changing call during a full checkup would close the first.
* The Windows restore-approval prompt (UAC) can't be clicked in CI, so the approval flow is unit-tested and the
  prompt itself is checked by hand before each release.
