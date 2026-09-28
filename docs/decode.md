# Offline payload decoding

The OpenAI–Hugging Face agent intrusion (July 2026) hid its programs in
more than 80,000 payloads using 1,588 combinations of encodings, and the
responders' commercial models refused to decode them. AgentDFIR decodes
offline, with no model involved.

```sh
agentdfir decode payload.txt
echo 'H4sIAAAAAAAA…' | agentdfir decode
```

Layers followed, up to four deep: base64 (standard and URL), base32
(with an explicit base32 step only), hex (`\x` escapes too), gzip, zlib,
bzip2, UTF-16LE (PowerShell `-EncodedCommand`) and
`String.fromCharCode(…)`. Base64 split across lines is joined first.
Output is kept only when it is readable text; binary never becomes a
finding.

## In analysis

When a command runs decoded data — `… | base64 -d | sh`, `eval "$(… |
base64 -d)"`, `exec(b64decode(…))`, `powershell -enc …`, an interpreter
reading its program from stdin — every command rule is also evaluated
against the decoded text. A rule that matches only after decoding keeps
its own ID and says so ("matched only after decoding the command's
payload (base64→gzip, decoded sha256 …)").

| rule | when |
|---|---|
| `ENCODED_PAYLOAD_EXECUTED` (HIGH) | the decoded text matches a HIGH/CRITICAL rule |
| `ENCODED_EXEC_UNRESOLVED` (MEDIUM) | decoded data is executed but the payload is not in the command (it came from a file, a variable or a download) and no HIGH rule already covers the command |

Data is not decoded: JWTs, `data:` URIs, SRI/lockfile integrity hashes,
40- and 64-character hex digests and anything that is decoded but not
executed are left alone. Heredoc bodies (files the agent writes) are
removed before any of this. Bounds: 64 KiB per blob, 256 KiB per
decompression (a >100× ratio that fills it is treated as a bomb),
2 MB decoded per event, 32 blobs per command.
