# DFIR-tool interop — KAPE, Velociraptor, Timesketch, Plaso

AgentDFIR fits into the collection and timeline stack IR teams already run, in both directions.

## In: triage trees and images → one sealed package

```sh
agentdfir collect --import /cases/host42/kape-output --case-id CASE-42 --operator "Your Name"
agentdfir collect --import /mnt/image/root                   # mounted disk image
```

`--import` walks a KAPE, Velociraptor, CyLR or image tree, finds **every user profile** that holds a known AI agent product (by config presence — nothing is executed, symlinks never followed) and collects **all products for all users** into one `.adfir` package. Every artifact carries the profile's user; `case.json` records `mode=import-tree` and the import root. Collector manifests are applied for every platform, so a Windows tree analyzed on a Mac or Linux workstation is collected correctly.

Discovery works on layouts such as `C/Users/<u>/…` (KAPE), `uploads/<client>/C%3A/Users/<u>/…` (Velociraptor), `home/<u>/…` and `root/…` (Linux images).

The shipped [KAPE Target/Module](../deploy/kape) and [Velociraptor artifact](../deploy/velociraptor) produce trees this command understands — collect fleet-wide with the tool you have, seal and analyze with AgentDFIR.

## Out: the timeline where you already work

```sh
agentdfir report CASE-42.adfir --format timesketch   # timeline.timesketch.jsonl
agentdfir report CASE-42.adfir --format l2tcsv       # timeline.l2tcsv
```

**Timesketch JSONL** — one object per event with the required `message` / `datetime` / `timestamp_desc` keys plus flat, searchable AgentDFIR attributes (`event_type`, `agent_id`, `parent_agent_id`, `tool`, `mcp_server`, `command`, `network_destination`, `corroboration_state`, `source_path`, `source_line`, …). Import with the Timesketch web UI or `timesketch_importer`. Events with no parsable timestamp are omitted (Timesketch rejects them) and the count is printed.

**l2tcsv** — the classic 17-column log2timeline/Plaso format (`date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`), accepted by Timesketch, Autopsy, Magnet and spreadsheet triage. `filename` is the evidence's logical path and `inode` its line number, so any row leads straight back to the sealed artifact. Undated events keep a blank date rather than disappearing.

All exported strings are sanitized — terminal escapes and invisible Unicode from hostile transcripts are neutralized before they reach another tool.

See also [SIEM interop](siem-interop.md) for OCSF, SARIF and Sigma.
