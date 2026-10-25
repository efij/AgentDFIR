# macOS host-state fixtures

| File | Origin |
|---|---|
| `TCC.db` | **Tool-generated.** Built with `/usr/bin/sqlite3` using the macOS 14+ `access` table schema; the three rows (service, client, auth_value, last_modified) are invented. |
| `com.example.agent.plist` | **Synthetic** XML launchd plist in Apple's plist DTD format. |
| `com.example.binary.plist` | **Tool-generated**: the XML plist above converted with `plutil -convert binary1` (binary plists are reported UNSUPPORTED). |
