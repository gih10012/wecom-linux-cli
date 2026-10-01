# wecom-linux-cli

Local tools for the account owner's WeCom client on Linux. Work in progress;
personal message reading and sending are not yet available. This project is
independent of Tencent's official `wecom-cli`, whose bot channel has a
different identity and scope.

Implemented commands:

```sh
python -m pip install .
wecom-linux status
wecom-linux client start
wecom-linux keys capture --database /private/prefix/drive_c/path/to/database.db
wecom-linux db inspect --database /path/to/database.db --key-file /private/key.json
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
prefix and a 32-bit MinGW compiler. It reads bounded private writable memory
through Wine's Windows process APIs, checks candidates against the selected
encrypted database, and requires full SQLite integrity before saving an
owner-only key file. Temporary candidates are deleted on completion or error;
the key is never printed. The scan does not call client message functions.
Finding a valid local cipher key would not prove remote login or message access.

`db inspect` takes two matching copies of a local database, validates the
wxSQLite3 AES-128 cipher key when needed, opens a temporary readonly snapshot,
and runs SQLite integrity checks before returning table schemas. Its key file
must be owner-only JSON containing `raw_key_hex`; keys are never printed.
Temporary plaintext snapshots are deleted when the operation finishes.
Live nonempty WAL files are currently rejected. A stable database snapshot
does not prove account login, access to cloud history, or a message schema.

Development acceptance still requires a usable logged-in official client,
real private/group history and pagination, new-message reads, native text and
media sends with deduplication, school workbench integration, and resource and
restart measurements. GUI results and generated test data do not prove native
CLI message support. No application autostart or background receiver is
installed by this project.

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

The decoder test fixture was generated with the independent upstream C
implementation; see [fixture provenance](tests/fixtures/README.md).
