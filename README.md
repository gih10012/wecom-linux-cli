# wecom-linux-cli

Local tools for the account owner's WeCom client on Linux. Reads locally
synced conversations and messages from an isolated official Windows client
under Wine, including committed WAL changes. Personal sending is still in
development. This project is
independent of Tencent's official `wecom-cli`, whose bot channel has a
different identity and scope.

Implemented commands:

```sh
python -m pip install .
wecom-linux status
wecom-linux client start
wecom-linux client resources --seconds 5
wecom-linux keys capture --database /private/prefix/drive_c/path/to/database.db
wecom-linux db inspect --database /path/to/database.db --key-file /private/key.json
wecom-linux account configure --account me --data-dir /private/prefix/drive_c/path/to/Data --key-file /private/key.json
wecom-linux conversations --query '会话名称' --limit 20
wecom-linux messages --chat 'EXACT_CHAT_ID' --limit 20
wecom-linux messages --chat 'EXACT_CHAT_ID' --cursor 'RETURNED_CURSOR'
wecom-linux messages --chat 'EXACT_CHAT_ID' --all
```

`status` inspects the configured Wine client without starting it. Local
configuration lives in `$XDG_STATE_HOME/wecom-linux-cli/client.json`, or
`~/.local/state/wecom-linux-cli/client.json`, with owner-only permissions.
Its `prefix`, `executable`, and `version` fields identify the isolated client.
The version is configured metadata; it is not a remote authentication check.

`client start` launches that isolated client in the owner's existing Linux
desktop session, including from a remote shell. It never creates an autostart
entry. Optional `desktop` (for example `WeCom,1280x960`) selects a Wine virtual
desktop; `environment` may contain Wine DLL and rendering overrides. A launch
request does not prove successful startup or login. This command requires a
previously installed client and a private Wine prefix.

`keys capture` requires the account owner's running client in that configured
prefix and a 32-bit MinGW compiler. Its fallback also requires a C compiler
and OpenSSL development headers. It reads bounded private writable memory
through Wine's Windows process APIs, checks candidates against the selected
encrypted database, and requires full SQLite integrity before saving an
owner-only key file. The fallback checks aligned key candidates in a bounded
pipe stream; raw process memory is never saved or printed. Temporary heuristic
candidates are deleted on completion or error;
the key is never printed. The scan does not call client message functions.
Finding a valid local cipher key would not prove remote login or message access.

`client resources` measures the existing configured Wine process group for
1–60 seconds. It reports CPU as a percentage of one core, RSS (including shared
pages), proportional memory (PSS) when accessible, and process identity changes.
CPU totals cover processes present throughout the sample; a changed process
group is explicitly reported. The command neither starts the client nor
changes autostart. Record whether the client was logged in and what activity
was happening separately; this sampler does not verify either.

`db inspect` takes two matching copies of a local database, validates the
wxSQLite3 AES-128 cipher key when needed, opens a temporary readonly snapshot,
and runs SQLite integrity checks before returning table schemas. Its key file
must be owner-only JSON containing `raw_key_hex`; keys are never printed.
Temporary plaintext snapshots are deleted when the operation finishes.
WAL header and frame checksums are verified over stored page bytes, salts
separate reused WAL cycles, and only committed frames are applied. Incomplete
or invalid current frames fail instead of silently ignoring recent data.
Other cipher WAL layouts and nonempty rollback journals are unsupported.
A stable database snapshot
does not prove account login, access to cloud history, or a message schema.

`account configure` validates all three exact account databases before
storing private paths. Normal reads reuse the key without scanning memory.
`messages` accepts any exact conversation ID or a unique complete name;
duplicate names require an ID. Both read commands default to 20 items and
return a scope-bound cursor. Message pages use time and local ID as the
ordering key and exclude insertions after the first page. `--all` returns all
locally synced rows in the requested scope; it does not fetch missing cloud
history. Snapshots across account databases are not atomic.

Observed Windows text types preserve the entire body, including whitespace,
newlines and emoji. Unknown content retains complete stored fields and binary
content as base64, rather than claiming a guessed text body. Sender and server
IDs are strings to preserve their integer precision. Media references are
returned; media downloads and viewing are not implied.

2026-10-01 local acceptance verified real private/group history, default
pagination, all synced rows in a selected conversation, and an independently
read new GUI-generated text message with Chinese, newline and emoji. This
proves CLI reads, not CLI sends or complete cloud history.

Development acceptance still requires native text and
media sends with deduplication, school workbench integration, and resource and
restart measurements. GUI results and generated test data do not prove native
CLI message support. No application autostart or background receiver is
installed by this project.

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

The decoder test fixture was generated with the independent upstream C
implementation; see [fixture provenance](tests/fixtures/README.md).
