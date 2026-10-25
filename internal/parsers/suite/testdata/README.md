# Forensic-suite fixtures — all SYNTHETIC

Every file in this directory is hand-made. None was produced by Cellebrite,
Magnet AXIOM, Plaso or Autopsy. They follow the publicly described layout of
each export, carry no real case data, and exist to exercise the readers in
`internal/parsers/suite` and `internal/parsers/plaso`.

| Path | Imitates | Notes |
|---|---|---|
| `ufdr/report.xml` | Cellebrite UFDR `report.xml` (project / sourceExtractions / caseInformation / metadata / taggedFiles / decodedData) | AI-app chat (Source=ChatGPT) with nested messages, a WhatsApp chat holding a claude.ai share URL, VisitedPage rows, Contacts, an unknown model type and an unrecognized element. IMEI and serial are synthetic (the IMEI is a published test number). |
| `ufdr-malformed/report.xml` | the same, cut at 3000 bytes | truncated mid-document |
| `ufdr-xxe/report.xml` | hostile | external entity (`file:///etc/passwd`) reference |
| `ufdr-laughs/report.xml` | hostile | billion-laughs entity expansion |
| `ufdr-notproject/report.xml` | unknown structure | Cellebrite-named XML whose root is not `<project>` |
| `ufd/synthetic.ufd`, `ufd/group.ufdx`, `ufd/synthetic.bin` | Cellebrite descriptors + the image they name | INI keys and XML attributes are illustrative |
| `axiom/Chrome Web History.csv` | AXIOM CSV export (UTF-8 BOM, comma, multi-line quoted cell) | per-hit trailer columns Source / Recovery method / Location / Evidence number / Item ID |
| `axiom/ChatGPT Messages.csv` | AXIOM CSV export (UTF-16LE BOM, TAB, `UTC+02:00 (dd/MM/yyyy)` time column) | artifact name names an AI app |
| `axiom/notes.csv` | not an AXIOM export | must not be recognized |
| `portable/` | AXIOM Portable Case tree | `Case.mfdb` is a tiny SQLite database made with the sqlite3 CLI (two synthetic tables), plus a CSV and an attachment |
| `plaso/timeline.jsonl` | `psort -o json_line` | includes an undated line and a non-JSON line |
| `plaso/timeline.l2tcsv` | `psort -o l2tcsv` | includes a non-UTC zone line and a short line |
| `autopsy/files.txt` | Autopsy "Files - Text" report (TAB) | column names from Autopsy's FileReportDataTypes |
