# wecom-linux-cli

Local tools for the account owner's WeCom client on Linux. Reads locally
synced conversations and messages from an isolated official Windows client
under Wine, including committed WAL changes, and sends native personal text,
PNG/JPEG images, ordinary files, native GIF stickers and article/mini-program cards
through the running client. This project is
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
wecom-linux send-preflight --chat 'EXACT_CHAT_ID' --text '文字'
wecom-linux send-text --chat 'EXACT_CHAT_ID' --text '文字' --request-id 'unique-request-01'
wecom-linux send-image-preflight --chat 'EXACT_CHAT_ID' --image '/path/image.png'
wecom-linux send-image --chat 'EXACT_CHAT_ID' --image '/path/图片.jpg' --request-id 'unique-image-01'
wecom-linux send-file-preflight --chat 'EXACT_CHAT_ID' --file '/path/文件.zip'
wecom-linux send-file --chat 'EXACT_CHAT_ID' --file '/path/文件.zip' --request-id 'unique-file-01'
wecom-linux send-sticker-preflight --chat 'EXACT_CHAT_ID' --sticker '/path/表情.gif'
wecom-linux send-sticker --chat 'EXACT_CHAT_ID' --sticker '/path/表情.gif' --request-id 'unique-sticker-01'
wecom-linux forward --chat 'EXACT_SOURCE_CHAT_ID' --message-id 123 --recipient 'EXACT_TARGET_CHAT_ID' --request-id 'unique-card-01'
wecom-linux message-xml --chat 'EXACT_SOURCE_CHAT_ID' --message-id 123
wecom-linux send-xml-preflight --chat 'EXACT_TARGET_CHAT_ID' --xml '/private/card.xml'
wecom-linux send-xml --chat 'EXACT_TARGET_CHAT_ID' --xml '/private/card.xml' --request-id 'unique-xml-01'
wecom-linux send-status --request-id 'unique-request-01'
wecom-linux media export --chat 'EXACT_CHAT_ID' --message-id 123
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
returned; references alone do not prove downloaded or viewed media.

`media export` supports native image type14 and external WeChat image type101. It resolves
the original reference through the account's plaintext CacheMapping database,
including committed WAL changes, and requires the message's original size and
MD5 to match the cached bytes. It copies verified PNG/JPEG bytes into private
`attachments/` with mode0600 and returns the path/SHA-256. It neither fetches
remote media nor substitutes thumbnails. If the original is absent, open that
image normally in the client and then export again. Other types and missing
remote originals remain unsupported. Absolute C: mappings are accepted only
inside the configured Wine prefix and this account's Image cache. The exact chat/message scope and cache
path containment are checked before reading. Real 2026-10-01 acceptance used
a personal WeChat CLI PNG received in the corresponding authorized WeCom
chat: both UIs displayed it and the exported original matched input bytes.
An image sent through the normal WeCom GUI produced type14 and reached the
authorized personal WeChat peer once; its full cached PNG export also matched
the original bytes. On 2026-10-02, installed ordinary native CLI PNG and Chinese-filename
JPEG sends each reached the authorized personal WeChat peer once; both UIs
displayed them and each cached-original export matched its input bytes.
External type101 JPEG exports and other attachment formats still need separate acceptance.

2026-10-01 local acceptance verified real private/group history, default
pagination, all synced rows in a selected conversation, and an independently
read new GUI-generated text message with Chinese, newline and emoji. This
proves CLI reads, not complete cloud history.

Native text, image, file, sticker and card sending supports only the SHA-256-pinned official Windows
5.0.11.6018 executable under the configured isolated Wine prefix. It requires
32-bit MinGW on the first use, one untraced client, a unique native manager and
the configured account's current user ID. A same-thread Windows message hook
constructs native message objects with the client's allocator and releases
its references with the client's destructors. Each send first performs a
construct-only preflight using the same artifact and verifies the exact
serialized Chinese/UTF-8 body or attachment filename, path and dimensions/size.
Native dispatch does not type into a window,
change focus or require a powered-on monitor. Its small pinned helper remains
loaded until client exit to avoid a callback/unload race.

`send-text`, `send-image`, `send-file` and `send-sticker` accept any exact conversation ID or a unique complete name;
authorization must be checked by the calling agent. `FILEASSIST` is the native
file-helper conversation, distinct from the internal chat with yourself.
There is no recipient authorization allowlist in this CLI. Text must contain
1–3072 UTF-8 bytes, preserve whitespace and contain no NUL. Request IDs use
4–80 ASCII letters/digits/`._-`, starting with a letter or digit.

`send-image` takes a regular PNG/JPEG file of 1 byte to 10 MiB, with dimensions
up to 32768 per side and 64 million pixels total. The extension must match the
format. Chinese filenames are preserved; invalid Windows filenames and source
symlinks are rejected. An immutable owner-only copy in private `send-assets/`
keeps the upload path available after the original file changes or the CLI exits.
These copies are retained, including after uncertain outcomes. Request IDs bind
the filename, content hash, format and dimensions. The native image objects copy
the strings and retain their own asynchronous references; temporary references
are released after dispatch. If asynchronous ownership cannot be established,
the two small native handles remain until client exit and the result reports this.

`send-file` accepts ordinary files of 1 byte to 10 MiB, with the same private
snapshot, filename checks, native ownership and replay behavior. The filename
and bytes are preserved. It sends an attachment; a GIF file sent this way does
not prove native sticker support. Chinese-filename TXT and ZIP were independently
received and downloaded byte-for-byte in the authorized personal WeChat peer.
Other file formats require their own acceptance.

`send-sticker` takes a GIF of 1 byte to 10 MiB, using the client's native
EmotionMessage input29. GIF framing, palette/block boundaries, dimensions and
frame count are checked before the native call; the filename must end in `.gif`.
Dimensions use the same bounds as images, with at most 2000 frames. Its preflight
verifies the exact serialized local path, dimensions and emotion type. Private
staging, asynchronous ownership and request replay use the shared asset journal.
An animated GIF was independently received as personal WeChat type47; GIF files
sent through `send-file` are a different operation. PNG/JPEG stickers and sends
to other peer kinds still require separate acceptance.

An owner-only journal is flushed to disk before native submission. Replaying
the same request ID and payload queries the existing result; changed payloads
are rejected. A timeout or interrupted submission remains unknown. Query its
original ID; do not use a new ID or GUI action to retry an uncertain send.
`send-status` only reconciles the returned local message ID against the exact
account, sender, conversation and body; images additionally require the stored
type14 filename, MD5, original size and dimensions to match; ordinary files
require type15, exact filename, size and MD5; stickers require type29, exact MD5,
dimensions and emotion type. A nonzero server ID proves the local
server acknowledgement, while independent recipient delivery and UI checks
remain separate. Journals contain message text in private state; do not copy
them into public bug reports.

2026-10-01 installed ordinary CLI acceptance verified text from personal
WeChat into the owner's authorized WeCom external chat, then native WeCom
CLI text back into that corresponding WeChat chat. Independent readers on
both sides found each full Chinese/newline/emoji body exactly once with
nonzero server IDs; both client windows displayed them. Same-ID replay did
not duplicate the message and a changed body was rejected. A preceding native
file-helper candidate also had the owner's phone confirmation. This does not
verify arbitrary groups or every media format. Three subsequent normal tray
exits and client restarts restored the configured account without new login,
reused the private key and prior request records, and passed construct-only
native preflights in each new process. A new text after the third restart was
independently received exactly once; replay did not duplicate it. The send
worked with the monitor off and no selected chat. Two timed client restarts
reached the native preflight in about 3.6 seconds with an existing Wine runtime.
This is not a whole-Wine cold-start or long-duration stability measurement.
Five-second client-group samples used roughly 4.4–5.6 GiB PSS; observed CPU
ranged from 9–18% of one core while idle and about 20% in one send window.
These are short samples, not continuous resource bounds.

2026-10-02 installed ordinary CLI acceptance verified a native PNG and a JPEG
with a Chinese filename, each independently read once in the authorized personal
WeChat recipient with a nonzero server ID. Both client windows displayed the
images; verified original exports matched input bytes. Same-ID PNG replay added
no messages and a changed image was rejected. Construct-only image and text
preflights added no messages. This does not verify arbitrary group sends or
other image/attachment formats.

Installed ordinary CLI Chinese-filename TXT and ZIP acceptance on 2026-10-02
verified each file once in the authorized personal WeChat recipient with
nonzero server IDs. The recipient's downloaded bytes matched each input, and
both client windows rendered the filename and size. Temporary native references
were released while the client's asynchronous references retained the file.
Same-ID TXT replay added no messages, a changed file was rejected, and an image
request from the previous installation replayed without resubmission. File,
image and text construct-only preflights added no messages; 58 tests passed.

Installed ordinary CLI animated-GIF acceptance on 2026-10-02 verified one new
type47 receipt in the authorized personal WeChat peer with matching XML MD5 and
length and nonzero server IDs. Both client windows displayed changing animation
frames. Same-ID replay added no messages, a renamed input was rejected, and a
file request from the previous installation replayed without resubmission.
The native constructor/serialization/release preflight passed without adding
messages; asynchronous owners retained the sticker after temporary references
were released. All 65 tests passed. Recipient cache bytes remain encrypted;
original export from that cache is not verified by this send acceptance.

Development acceptance still requires native card/custom XML support and remote/missing
original downloads beyond the verified PNG and native type14 JPEG cache export,
school workbench integration, offline-gap coverage and longer stability/resource
measurements. Residency remains an owner decision; no autostart is added. GUI results and generated test data do not prove native
CLI message support. No application autostart or background receiver is
installed by this project.

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

The decoder test fixture was generated with the independent upstream C
implementation; see [fixture provenance](tests/fixtures/README.md).

`forward --chat SOURCE --message-id ID --recipient TARGET --request-id ID`
forwards an exact locally synced article (type13) or mini-program (type78)
through the native card pipeline. `message-xml --chat SOURCE --message-id ID`
exports editable UTF-8 `msg/appmsg` XML, including a `wecom-native` base64
payload with its SHA-256 so unknown native fields and resource metadata survive
editing. Treat these exports as private account data. `send-xml --chat TARGET
--xml /private/card.xml --request-id ID` sends the edited card;
`send-xml-preflight` constructs and releases it without sending.

XML files must be 1–65536 UTF-8 bytes, without NUL, DTD or entity declarations.
The supported appmsg types are article5 and mini-program33. Article XML can edit
title, description, HTTP(S) URL and thumbnail URL. Mini-program XML can edit
title, description, display name and app icon; its actual app ID, username,
page path, type and native share/resource metadata must come from an exported
source. New mini-program identities, arbitrary XML tags, merged histories and
type36 are not covered. The client may normalize fields; this is not an opaque
arbitrary-XML transport. Native card payloads are limited to 65536 bytes and
checked by a construct-only parse/serialize preflight before dispatch.

Card request IDs bind the exact source account/chat/message and payload, or
custom XML bytes, as well as the target and action. Reusing a forward ID for
an XML send conflicts even with equivalent content. If the source was removed,
query `send-status` instead of retrying under a new ID. Native card construction
uses the observed LinkMessage allocation, separate shared control and client
parser/destructor, with a distinct v3 hook protocol to coexist with older
pinned helpers. Existing text/image/file/sticker request identities remain valid.

Installed ordinary CLI acceptance on 2026-10-02 independently received one
article forward, one mini-program forward, and edited-title/description XML
for each in the authorized personal WeChat peer. Type49/app5 or app33, native
server IDs, Chinese/newline/emoji and mini-program app identity/page matched.
Article cards displayed their thumbnails in both clients; mini-program cards
rendered titles and identity but their source thumbnail metadata was empty,
so both normal GUI and CLI forwarding displayed a placeholder. Complete
mini-program thumbnail transfer and click-through are not yet verified.
All four same-ID replays added no messages; changed actions were rejected.
Native v3 text/image/file/sticker construct-only checks passed without sends.

## Protocol web links

`wecom-linux web resolve --url 'ACTUAL_LINK'` parses HTTP URLs and explicit HTTP
parameters in WeChat/WeCom webview envelopes. `--probe` performs a bounded GET.
Opaque mini-program tickets return `CLIENT_REQUIRED`; OAuth callbacks are not
treated as authenticated business pages.

`web open --url 'HTTP_PAGE' --browser edge` (or `chrome`) requests a normal
browser window. For an observed HTTP equivalent, use `web bind --url
'EXACT_SOURCE_LINK' --target 'OBSERVED_HTTP_SOURCE' --view json`, then `web relay
--url 'EXACT_SOURCE_LINK' --seconds 300 --browser chrome`. Bindings are private,
exact-source mappings shared with `wechat-linux`; no school adapters are built
into the CLI. Relay output streams a temporary localhost URL and closes on
Ctrl+C or its deadline. It supports complete JSON, plain text, and HTML text
reading, with optional origin-scoped private HTTP session state; it does not
run a mini-program or emulate client OAuth/JS SDK APIs. HTTP success and browser
launch are reported separately from actual business/content verification.

## Private voice calls

```sh
wecom-linux call inspect --account me
wecom-linux call selector-cancel --account me --selector-token CURRENT_SELECTOR_TOKEN
wecom-linux call selector-select --account me --selector-token CURRENT_SELECTOR_TOKEN --member-id EXACT_NATIVE_ID --select
wecom-linux call selector-select --account me --selector-token CURRENT_SELECTOR_TOKEN --member-id EXACT_NATIVE_ID --deselect
wecom-linux call preflight --account me --chat EXACT_PRIVATE_CHAT_ID
wecom-linux call start --account me --chat EXACT_PRIVATE_CHAT_ID --request-id CALL_ID
wecom-linux call answer --account me --invitation-token CURRENT_TOKEN --request-id ANSWER_ID
wecom-linux call status --request-id CALL_ID
wecom-linux call play --request-id CALL_ID --file /path/notification.wav --audio-request-id AUDIO_ID --wait-seconds 30
wecom-linux call hangup --request-id CALL_ID
```

`call inspect` also reports visible, complete typed contact pickers in
`member_selectors`. It reads normal `CSelectUserFrame` contact pickers and
`CSelectUserFrame2` group-creation pickers on the verified UI thread, including
nonvirtual control bases at nonzero offsets. `visible_members` reports exact
individual checkbox metadata and its own checked state, using the formal
`GetUserData` and `IsSelfSelected` getters. Classic picker IDs were matched to
actual group membership. In creation pickers only the verified external
individual metadata format is exposed as a member; department metadata and
unknown formats are excluded. These are visible rows, not a complete member
list or the full selection after scrolling. The picker remains separate from
incoming and active calls; neither a selected member nor its caption proves
an invitation or connection. Close or cancel it normally before another
call. Target preflight, start, answer and unresolved-call resolution refuse a
pending picker. Native start/answer checks this again before activation.
`selector-cancel` uses the current token to activate only the typed normal
cancel button, then checks that this same picker closed. Its token binds the
account, process creation time, window/root/cancel control and captions; stale
or incomplete snapshots are refused. This local cancellation does not submit
an invitation or use a call request ID. It never retries on an uncertain result;
inspect the actual window before further actions.

`selector-select` sets one exact visible individual's local checkbox. It binds
the current account/window token, native metadata, checkbox and previous state,
activates the normal `COptionUI` control once, and independently reads back the
desired state. Repeating an already satisfied state is read-only. It never
activates the confirmation button, creates a group, or submits an invitation.
The ordinary installed CLI selected and deselected the owner's authorized
external contact in a group-creation picker; the checked row and selected count
also appeared in the UI, repeated selection was read-only, a pending picker
blocked private start before any call journal, and normal cancellation closed
it. A real group voice picker was read without selecting or inviting its
members. CLI opening and submission of group invitations, complete selection
across scrolling, group connection and group audio remain unfinished.

These commands control the normal UI on the verified client UI thread. They
require the configured official 5.0.11.6018 client, matching executable/DuiLib/owl
hashes, Wine, a 32-bit MinGW compiler, and the installed niri-computer-use display
session helper. UI mutations wake and restore the owner's display session;
another active display session is refused. No sudo or client restart is needed.
The small native helper stays loaded until client exit for callback safety.

`start` accepts exact private conversation IDs (`S:ID_ID`). The target must have
a cached, attached normal chat view: open it in the client if preflight requests
this. The backend validates the exact conversation string, account, process
creation time, UI thread, view type, parent and window before activating the
normal voice handler. It has no recipient authorization whitelist. The calling
agent checks authorization before inviting or accepting a call. Group invitation
and member selection are not implemented by these WeCom commands.

`inspect` reads normal call controls without inviting or accepting. Incoming
tokens bind the account, current process/window/root/button and full caption;
captions do not expose an exact native caller ID. Confirm authorization using
the actual caller context before `answer`; a matching name alone is insufficient.
`preflight` also resolves 19 system DLLs through the verified client's normal CRT
resolver on its UI thread, avoiding the loader-lock cycle observed during voice
component initialization. Run it after starting the client before incoming-call
tests; `start` and `answer` also perform this local warmup. It makes no invitation.

IDs are journaled before native UI mutations, in private
`~/.local/state/wecom-linux-cli/calls/`. Same-ID replay performs no second action;
changed payloads conflict. Unknown invite/accept/hangup outcomes block new IDs:
query the original ID and independently check the client before
`call resolve --request-id ORIGINAL_ID --ended`. Resolution changes only the
local journal. Hangup binds the original call window and cannot control another
current call.

`call play` waits up to 120 seconds for the original private call's elapsed
clock and typed hangup control, then selects its one active capture stream.
The transient "connected" tip may disappear; a ringing tip, incomplete tree,
group layout or capture stream alone never permits playback. Audio uses its own
request ID and the restoration/recovery rules below. The result's
`call_connection_verified_before_playback` describes the UI check; remote audio
delivery still requires independent evidence.

Installed-command acceptance on 2026-10-03 covers private placement, incoming
acceptance, connected playback, normal hangup and replay guards against the
owner's personal WeChat client. In one connected call, generated Chinese speech
was independently captured at both receiving clients (envelope correlations
0.87 and 0.95); both histories report 00:22. One normal tray exit/client restart
preserved the account/history and passed new-process incoming/outgoing control,
connected playback, hangup and replay after ordinary system-DLL warmup. The
outgoing target view was reopened in the normal client before preflight. This
does not cover restarting the whole Wine runtime. Group calls and long-term
voice stability remain separate acceptance work.

## Existing call audio

```sh
wecom-linux audio streams --pid CLIENT_PID --start-time PROC_START_TIME
wecom-linux audio play --pid CLIENT_PID --start-time PROC_START_TIME --source-output STREAM_ID --file /path/notification.wav --request-id UNIQUE_ID
wecom-linux audio status --request-id UNIQUE_ID
wecom-linux audio recover --request-id UNIQUE_ID
```

These commands require a local PulseAudio-compatible server (including
PipeWire), `pactl`, and `paplay`. `play` accepts mono/stereo PCM WAV, up to
5 minutes and 32 MiB. The caller first confirms the call is connected and
authorizes its participants, then selects one capture stream from `streams`.
A capture stream by itself does not prove connection. The commands do not
place, accept, invite members to, or hang up a call.

Playback temporarily routes that exact process/start time/stream identity to
a private null-sink monitor, then restores its original input and removes the
module. No global defaults are changed. A disconnected, muted, replaced, or
manually rerouted stream stops playback. Same-ID replay never plays again;
changed content/target conflicts. Journals are private in
`~/.local/state/wechat-audio/`. Following an abrupt process exit, check the
original ID and run `recover` to clean up before any new audio request;
recovery never repeats audio.

Actual acceptance covers a normal GUI WeCom ↔ Linux WeChat private call:
source CLI playback of generated Chinese speech was independently captured
at each receiving client's selected output stream (envelope correlations
0.88 and 0.93). Standalone routing, restoration, and no-playback replay also
passed. Installed-command acceptance is recorded separately by the skill.
Private call controls are described above; selected-member group calls remain
in development.
The audio result's `remote_delivery_verified` and
`call_connection_verified` stay false: neither is inferred from local playback.

The underlying monitor-source behavior is documented in
[PulseAudio modules](https://wiki.freedesktop.org/www/Software/PulseAudio/Documentation/User/Modules/).
