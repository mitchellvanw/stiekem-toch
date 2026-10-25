# stiekem-toch

Dutch for "secretly, after all".

A Claude Code mod that keeps API keys and tokens out of what the model reads and what the transcript keeps, and lets the model use keys you store without ever reading them.

When a tool's answer or something you type holds a key in a known format, or a key you stored, the key is replaced with `[redacted: <kind>]` before the model reads it or the transcript stores it. A Bash command the model writes with a key in it is denied, so it does not run. A key you store goes out only through the mod's own request tool, and only to the hosts you allowed it. The mod writes no files, and makes network requests only when the model calls its request tool.

## What it checks

- Known formats, listed in `hooks/patterns.ts`: private key blocks, AWS access keys, GitHub tokens, `sk-` API keys (Anthropic and OpenAI), Stripe keys, Slack tokens, Google API keys, and JSON Web Tokens.
- Each key you stored, by its value: as is, URL-encoded, base64 (standard and URL-safe) and hex. This catches keys of any format, such as a password.

## What it covers

- A tool's text and its structured record, such as a Bash command's stdout, at any depth.
- Anything you type in a prompt: what the model reads, the transcript's rows, the prompt history (the up arrow), and the record of a prompt you type while a turn runs. A key in a known format that you paste is kept for the session, so the model can still use it; see [Pasted keys](#pasted-keys).
- A slash command's arguments. The command runs with the key redacted, so a command that needs a key in its arguments gets the placeholder instead.
- A Bash command the model writes with a key in it. The command is denied.

## Stored secrets

Store a key and the hosts it may go to, and the model can make HTTPS requests with it through the `mcp__stiekem-toch__request` tool. The model names the key. The mod adds it to the request on the host and removes it from the response before the model reads it. The tool is offered even when nothing is stored, so the model knows this is how a key reaches a request.

Set them in your own terminal, so the key never passes through a session:

```sh
claude plugin configure stiekem-toch --values-stdin
```

Give it a JSON object whose `vault` holds the secrets, written as one line of JSON:

```json
{"vault": "{\"github\":{\"value\":\"ghp_…\",\"hosts\":[\"api.github.com\"],\"header\":\"Authorization\",\"template\":\"Bearer {}\"}}"}
```

Each secret has:

- `value`: the key, at least 8 characters.
- `hosts`: the exact hosts it may be sent to.
- `header`: the request header that carries it.
- `template`: how the header is spelled, `{}` standing for the key. Optional; `{}` by default.

A secret missing any of these is dropped whole, so a typo never widens what it may do. The `vault` option is marked sensitive, so Claude Code keeps it in secure storage, not in `settings.json`. The hosts live in the same field on purpose: a model that can edit `settings.json` cannot add a host. If the field is not valid JSON, the request tool is not offered and a notice says why. Redaction by the known formats still runs.

The request tool refuses:

- a URL that is not `https://<host>/<path>`, or that has user info, a port other than 443, or a backslash;
- a host not on the secret's list;
- a header of the model's own that would replace the secret's header, and any header holding a line break.

A redirect is followed. One that leaves the origin drops every request header, the secret's included; this was checked against `Authorization` and a custom `X-Api-Key`. A response body is cut at 100,000 characters.

The keys live only in the mod's memory for the session: never in its state, its store or a file.

### Pasted keys

When a key in a known format is in a prompt you send, the mod keeps it in memory for the session under a name, `pasted-1`, `pasted-2` and so on. The model reads the name in the key's place and is told it can send the key with the request tool. A key you paste twice keeps its first name.

A pasted key has no hosts to start with. The first time the model sends it to a host, you are asked whether to send it there. If you allow it, that host stays allowed for the session. If you refuse, close the dialog, or no one can answer, as in `claude -p`, the request does not run. A pasted key always goes in `Authorization: Bearer <key>`. A key that goes in another header, such as an Anthropic `x-api-key`, has to be stored in the vault instead.

Keys in a slash command's arguments are not kept, only redacted.

## What it does not cover

- **The model's own tool calls.** The transcript keeps a tool call's input as the model wrote it. A key the model types into a command stays in the transcript, even though the command does not run.
- **Other tools' inputs**, such as file writes and edits. Only Bash commands are checked.
- **What the prompt box shows while you type.** A key stays on screen until you press Enter, and in your terminal's scrollback after that.
- **Files you mention with `@`.** The transcript keeps a mentioned file's content as read.
- **Transcripts from before the mod was installed.**
- **The model's own replies.**
- **Keys in formats not on the list** that you have not stored, and values that do not look like a key.
- **Images and other non-text content.**
- **Other mods.** A mod installed beside this one can hook the requests the request tool makes and read their headers. Install only mods you trust beside it.
- **The model acting as you on this machine.** The model's Bash commands run as your user, so it could change this mod's installed code or read Claude Code's secure storage. Redaction catches a key printed as is, but not one transformed in a way the mod does not check. To close this, turn on Claude Code's Bash sandbox, so the model can write only inside the project, and deny edits to the mod's folder and your settings.

## When the check fails

If a check throws, nothing it was checking passes through unchecked:

- A tool's result is withheld.
- A row of the conversation keeps a notice in place of its text.
- A prompt is not sent.
- A slash command does not run.
- A request through the request tool returns nothing.

## Where it runs

Per the mods documentation, hooks run in the terminal, the Desktop app's Code tab (not in WSL sessions), the VS Code chat panel, `claude -p`, the Agent SDK and Remote Control. Notices appear as toasts only where something draws, so `claude -p` shows none. Cloud sessions run the mod only when the plugin reaches them.

## Install

Requires Claude Code 2.1.275 or later.

In Claude Code:

```
/plugin install stiekem-toch --marketplace mitchellvanw/stiekem-toch
```

Or from a terminal:

```sh
claude plugin install stiekem-toch --marketplace mitchellvanw/stiekem-toch
```

This installs for you, in user scope. To try it for one session from a clone instead:

```sh
claude --plugin-dir /path/to/stiekem-toch
```

## Develop

```sh
claude plugin validate .
claude plugin test .
tsc -p .
```

`tsc` needs the types Claude Code writes to `.claude-plugin/types/` once it has loaded the plugin from this folder, for example with `claude --plugin-dir .`.

The tests cover:

- the patterns, and the redaction of structured records;
- the Bash deny;
- prompts and slash-command arguments;
- the vault: its parsing, the host and header checks, and the redaction of each spelling;
- pasted keys: keeping them, and asking before each new host;
- the request tool, with the network stood in for.

The rest was checked by hand, with fake keys:

- the request tool, in a headless run against an echo service;
- the redirect behaviour, against local servers;
- the prompt history, the queued-prompt record and a slash command's arguments, in an interactive session.

Version 0.2.0.
