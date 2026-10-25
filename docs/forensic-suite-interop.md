# Forensic-suite interop — Cellebrite, Magnet AXIOM, Plaso, Autopsy

AgentDFIR reads the exports that mobile and disk forensic suites produce and pulls out the records that concern AI applications and AI-service URLs. It reads only documented, generic structure. It does not reverse-engineer undocumented proprietary formats.

```sh
agentdfir collect --suite-export case42.ufdr                    # UFDR (zip) or unpacked UFDR directory
agentdfir collect --suite-export "/exports/AXIOM CSV"           # directory of AXIOM CSV files
agentdfir collect --suite-export timeline.jsonl                 # one psort json_line / l2tcsv file
agentdfir collect --import /cases/host42                        # finds suite exports anywhere in a tree
agentdfir analyze CASE.adfir --endpoint timeline.jsonl          # Plaso as a partial-coverage witness
```

`--ai-export` and `--archive` recognize the same files. Files are recognized by their content, not by their names. The only exceptions are `.ufd`/`.ufdx` descriptors and `Case.mfdb`, where the extension is part of the check.

## Rules every reader follows

- **Originals stay sealed byte for byte.** Each export file is a normal artifact (`suite.*` or `ufdr.report` collector rule). The tests check that the sealed bytes hash the same as the originals.
- **Only supported fields are normalized.** Every other record, model or column is counted in an inventory event. It stays raw in the sealed file.
- **Unknown structure is never skipped silently.** It produces a `trace_gap` event with result `unsupported` and a reason, and that event becomes a TRACE_GAP "Unsupported Evidence Format" finding. Malformed or truncated input produces a `trace_gap` with result `unparsed` that says where reading stopped.
- **Evidence class `forensic-suite`.** An event means "the suite reported this record, here in its export". It is another tool's decoding of the evidence, not the device's own record, and never proof of execution. Every event's timestamp source starts with `forensic_suite:<product>`, followed by the original field and value. A time is normalized only when its zone is stated. Otherwise it is kept raw and marked `(not normalized)`.
- **Device identifiers are masked in normalized output.** This covers IMEI, IMSI, ICCID, MEID, serial numbers, phone numbers, Wi-Fi/Bluetooth addresses and UDIDs. They appear as `[REDACTED:<category>:<8 hex of SHA-256>]`, the same marker format `--redact` uses. The verbatim values exist only in the sealed original.
- **One list of AI applications.** The list is in `internal/parsers/suite/aiapps.go`: ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, Grok, Character.AI, Poe, Meta AI and Mistral Le Chat. AI-service URLs are classified with the browser parser's service table, so a URL is recognized the same way everywhere.
- **Bounded.** Each XML token is capped at 16 MiB, XML nesting at 256 levels and model nesting at 64. Each CSV record is capped at 4 MiB with at most 1024 columns, and each Plaso line at 1 MiB. Each export yields at most 200 000 AI records. The table inventory reads a Case.mfdb only up to 256 MiB, and a descriptor is read up to 1 MiB. Over-long Plaso lines are counted and skipped, and reading resumes at the next line. An over-long CSV record stops that file with a gap event, because a CSV stream cannot be resynchronized safely.

## Coverage

| Source | Parsed (normalized) | Preserved raw, counted | UNSUPPORTED (with reason) | Fixture origin |
|---|---|---|---|---|
| **Cellebrite UFDR `report.xml`** | Streamed with `encoding/xml`; the whole document is never loaded. Read: `project` attributes; `sourceExtractions/extractionInfo` attributes; `caseInformation` fields (case number, examiner …); `metadata` items per section, with device model/vendor, OS, extraction type, extraction start/end and tool version lifted by item name (every item is also kept under its own name, identifiers masked). `decodedData` models whose `Source`/`Application` field names an AI app (with their nested Chat/InstantMessage/WebBookmark/VisitedPage/SearchedItem models). Chat, InstantMessage, WebBookmark, VisitedPage and SearchedItem models that hold an AI-service URL. Each event carries an XPath-like provenance path (`/project/decodedData/modelType[@type='Chat']/model[@type='Chat'][@id='…']/…`) in `source_json_path`, the byte offset and line, and the model id. | Every other model, counted per type (top-level and nested); tagged files (count); other top-level sections | Root element is not `<project>`; `<model>` without a type; elements outside the generic `modelType/model/field` shape. A declared character set other than UTF-8 stops the read with a malformed gap. | Synthetic, hand-made from the publicly described structure |
| XXE / billion laughs | — | — | `encoding/xml` neither fetches external entities nor expands DTD entities. A reference to one is a syntax error, so the document is reported malformed at that point. Tests prove no file content and no expansion reach the output. | Synthetic hostile fixtures |
| **Cellebrite `.ufd`** (INI-style) / **`.ufdx`** (XML) | Every section/key (or element/attribute), identifiers masked. File names with an evidence-container extension are listed as linked files. With `collect --image X`, descriptors in the same directory that name `X` are recorded in the case notes (`image_ufd_descriptor_N`) and sealed beside the image provenance. | — | Neither INI nor XML | Synthetic |
| **Magnet AXIOM CSV export** | One CSV per artifact type. The artifact name comes from a one-cell title line or the file name. Encoding is detected (UTF-8, UTF-8 BOM, UTF-16LE/BE with or without BOM), and so is the delimiter (`,` TAB `;` `\|`). Multi-line quoted cells are supported. Mapped columns: URL, Title, the first `…Date/Time…` column (zone and date order taken from its name, such as `- UTC (yyyy-mm-dd)` or `- UTC+02:00 (dd/MM/yyyy)`), Source, Location, Item ID, Artifact type/Artifact, Evidence number, plus message-like columns for AI rows. Rows become events when the artifact names an AI app or a cell is an AI-service URL. | Every other row; every column, kept raw in the sealed file and listed in the inventory | — (an over-long record stops the file with a gap event) | Synthetic |
| **AXIOM Portable Case / exported file tree** | Through `--import` / `--suite-export`: the CSVs inside it are read as above, and agent profiles in the tree are collected as usual | Other files (with `--suite-export`, every file is sealed) | — | Synthetic tree |
| **AXIOM `Case.mfdb`** | Sealed losslessly. Its SQLite table names and row counts are listed (read-only with `sqlitero`; rows are counted, not read). | The whole database | Always **`AXIOM_CASE_DB_UNSUPPORTED`**: "AXIOM Case.mfdb schema is undocumented; export to CSV/Portable Case from AXIOM and import that". The same applies when the file was over the collection size bound and was not sealed. | Tiny SQLite database made with the sqlite3 CLI |
| **Plaso `psort -o json_line`** and **`-o l2tcsv`** | timestamp (µs; l2tcsv only when the zone column is UTC/GMT), timestamp_desc, source/sourcetype, data_type, parser, display_name/filename, message, host, user, url, title, command, executable. In a package, lines become events for AI-service URLs, AI-app executables and files in AI agent data directories. With `--endpoint`, URL lines become network records, shell-history commands become process records, and `fs:` lines become file records. | Every other line, counted per parser | — (malformed and over-long lines are counted and reported in a gap event) | Synthetic (no Plaso install on the build host) |
| **Autopsy "Files - Text"** report | TAB- or comma-delimited, with column names from Autopsy's `FileReportDataTypes` (Name, Full Path, Last Modified …). Rows under AI agent / assistant data directories become events. Times are normalized only when the zone is UTC/GMT. | Every row | — | Synthetic |
| Autopsy HTML / Excel reports | — | Sealed if present in an imported tree | Out of scope. Use Autopsy's exported files through `--import`, or the Files - Text report. | — |

### Plaso as a witness

`analyze --endpoint timeline.jsonl` (format `plaso`, sniffed automatically) loads a timeline as a **sighting** source. Its records can corroborate a matching agent tool call (a URL the agent fetched, a command in shell history). They never contradict one and never count as telemetry coverage, because a super-timeline holds what the parsers found, not every process or connection. Undated lines are not used.

## What is not done

- No semantic parsing of `Case.mfdb`, `.clbx`, or any other undocumented proprietary database.
- No guessing of UFDR field meanings beyond their names. Fields such as `Source`, `Body`, `Url`, `Title` and `TimeStamp` are reported under the names the report gives them.
- No message-direction claims (prompt vs. response) for UFDR or AXIOM chat rows. They are reported as records.
- Fixtures are synthetic and labelled so in `internal/parsers/suite/testdata/README.md`. Real exports from the suites were not available to the build, so differences between product versions may surface as UNSUPPORTED findings, not as wrong data.
