import type { Register } from 'claude-code'
import { formatMatches, redact, redactBlock, redactDeep, secretKinds, withhold } from './patterns'
import { checkRequest, hostOf, parseVault, pastedGrant, spellings, type Grant, type Request } from './vault'

const TOOL = 'request'
const TOOL_NAME = `mcp__stiekem-toch__${TOOL}`
// Bodies past this are cut before the model reads them.
const MAX_BODY = 100_000
const ALLOW = 'Send it'

export const register: Register = (on, options) => {
  // The stored secrets live here alone, in this module's memory: never in `$.state`, `$.store` or a file.
  // Keys the person pastes into a prompt join them for the session.
  const vault = new Map<string, Grant>()
  let isVaultBroken = false
  try {
    for (const [name, grant] of parseVault(options.vault as string | undefined)) vault.set(name, grant)
  } catch {
    isVaultBroken = true
  }
  let known = spellings(vault)

  const keep = (name: string, grant: Grant) => {
    vault.set(name, grant)
    known = spellings(vault)
  }

  // The tool is offered with an empty vault too, so the model learns how a key reaches a request
  // instead of reading one from a file into a Bash command. Its `secret` takes no enum: a key
  // kept mid-session is usable before the tool list is read again, and an unknown name is refused.
  const toolSpec = () => {
    const listing = [...vault].map(([name, g]) =>
      g.pasted === undefined
        ? `- "${name}": ${g.hosts.join(', ')}`
        : `- "${name}": a ${g.pasted} the person pasted, sent as a bearer token; the person is asked before it goes to a host they have not allowed${g.hosts.length > 0 ? ` (allowed: ${g.hosts.join(', ')})` : ''}`,
    )
    return {
      name: TOOL,
      description: [
        'Makes an HTTPS request with a stored secret attached. You never see the secret: the plugin adds it to the request and removes it from the response.',
        listing.length > 0 ? `Each secret goes only to its own hosts:\n${listing.join('\n')}` : 'No secret is stored yet.',
        'The person adds one by pasting it into a prompt, which keeps it for the session, or for good with `claude plugin configure stiekem-toch --values-stdin` in their own terminal.',
        'Use this instead of putting a key in a Bash command, which is refused, or reading one from a file into a command.',
      ].join('\n'),
      inputSchema: {
        type: 'object',
        properties: {
          secret: { type: 'string', description: 'The name of a stored secret' },
          method: { type: 'string', enum: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] },
          url: { type: 'string', description: "https://<host>/<path>, the host one of the secret's own" },
          headers: { type: 'object', additionalProperties: { type: 'string' } },
          body: { type: 'string' },
        },
        required: ['secret', 'url'],
      },
      isDeferred: false,
    }
  }

  on('session.start', async ($, e, next) => {
    const started = await next(e)

    if (isVaultBroken) $.ui.toast(`${$.plugin.name}: the vault option is not valid JSON, so no configured secret can be used`)
    await $.tool.register(toolSpec())

    return started
  })

  // The request runs here, on the host: the model's call names the secret, never holds it.
  on('tool.call', { tool: TOOL_NAME }, async ($, e) => {
    const req = e as unknown as Request
    const grant = vault.get(req.secret)
    const host = hostOf(req.url)

    // A pasted key has no hosts of its own: the person allows each one at first use.
    if (grant?.pasted !== undefined && host !== undefined && !grant.hosts.includes(host)) {
      const answer = await $.ui
        .ask(`Send the ${grant.pasted} you pasted to ${host}? It is added as a bearer token, and ${host} stays allowed for this session.`, {
          options: [ALLOW, "Don't send it"],
          header: 'Secret',
        })
        .catch(() => undefined)
      if (answer !== ALLOW) return { deny: `${$.plugin.name}: the person did not allow "${req.secret}" to go to ${host}.` }

      keep(req.secret, { ...grant, hosts: [...grant.hosts, host] })
    }

    const checked = checkRequest(vault, req)
    if ('deny' in checked) return { deny: `${$.plugin.name}: ${checked.deny}` }

    const res = await $.http.fetch(checked.url, checked.init)

    const kinds: string[] = []
    const body = res.text.length > MAX_BODY ? `${res.text.slice(0, MAX_BODY)}\n[cut at ${MAX_BODY} characters]` : res.text
    const result = redactDeep({ status: res.status, headers: res.headers, body }, kinds, known)

    if (kinds.length > 0) $.ui.toast(`Redacted ${kinds.length} secret${kinds.length === 1 ? '' : 's'} from a response: ${kinds.join(', ')}`)

    // A plugin's tool answers text. It is written after the redaction, so JSON escaping cannot hide a secret from it.
    return { result: JSON.stringify(result, null, 2) }
  }).catch($ => ({ deny: `${$.plugin.name}: the request failed, so nothing is returned.` }))

  // A tool's answer, before the model reads it and before the transcript keeps its structured record.
  on('tool.call', async ($, e, next) => {
    if (e.tool === 'Bash') {
      const kinds = secretKinds(e.command, known)

      // A command that holds a key would send it somewhere or write it down, so it does not run.
      if (kinds.length > 0) {
        $.ui.toast(`Blocked a Bash command holding a ${kinds[0]}`)
        return {
          deny: `${$.plugin.name}: the command holds what looks like a ${kinds[0]}, so it did not run. Leave the value out of the command.`,
        }
      }
    }

    const ran = await next(e)

    if (ran.deny !== undefined) return ran

    const kinds: string[] = []
    const answer = {
      ...ran,
      text: redactDeep(ran.text, kinds, known) as typeof ran.text,
      result: redactDeep(ran.result, kinds, known) as typeof ran.result,
    }

    if (kinds.length > 0) {
      $.ui.toast(`Redacted ${kinds.length} secret${kinds.length === 1 ? '' : 's'} from ${e.tool}: ${kinds.join(', ')}`)
    }

    return answer
  }).catch($ => ({ deny: `${$.plugin.name}: its check failed, so this call's result is withheld.` }))

  // What the person typed, before the prompt history and the queue record keep it.
  // A slash command's line takes no rewrite here; its arguments are masked at command.run below.
  on('prompt.submit', async ($, e, next) => {
    if (e.command !== undefined) return next(e)

    // A key the person pastes is one they mean the model to use: keep it, so the redaction names it.
    const pasted = formatMatches(e.text, known)
    const kept: string[] = []
    for (const { kind, value } of pasted) {
      if (known.some(([form]) => form === value)) continue
      const name = `pasted-${[...vault.values()].filter(g => g.pasted !== undefined).length + 1}`
      keep(name, pastedGrant(kind, value))
      kept.push(`"${name}", a ${kind}`)
    }
    if (kept.length > 0) await $.tool.register(toolSpec())

    const kinds: string[] = []
    const text = redact(e.text, kinds, known)

    if (kinds.length === 0) return next(e)

    $.ui.toast(
      `Redacted ${kinds.length} secret${kinds.length === 1 ? '' : 's'} from your prompt: ${kinds.join(', ')}` +
        (kept.length > 0 ? `. Kept for this session; you are asked before it goes to a host.` : ''),
    )
    if (kept.length === 0) return next({ ...e, text })

    const note = `${$.plugin.name} kept what the person pasted, for this session: ${kept.join('; ')}. Send it with the ${TOOL_NAME} tool, naming it; the person is asked before it goes to each host.`
    return next({ ...e, text, context: [...(e.context ?? []), note] })
  }).catch(($, e, next) => (next.called ? next(e) : { drop: `${$.plugin.name}: its check failed, so the prompt was not sent.` }))

  // A slash command's arguments, before the command runs and before its rows and its history line keep them.
  on('command.run', ($, e, next) => {
    const kinds: string[] = []
    const args = redact(e.args, kinds, known)

    if (kinds.length === 0) return next(e)

    $.ui.toast(`Redacted ${kinds.length} secret${kinds.length === 1 ? '' : 's'} from /${e.command}: ${kinds.join(', ')}`)
    return next({ ...e, args })
  }).catch(($, e, next) => (next.called ? next(e) : { text: `${$.plugin.name}: its check failed, so /${e.command} did not run.` }))

  // The rows the model reads and the transcript keeps: what the person typed, a command's rows, a queued
  // prompt's record, and any tool result the hook above did not reach.
  for (const door of ['tool-result', 'prompt', 'command', 'queue'] as const) {
    on('session.append', { door }, ($, e, next) => {
      const kinds: string[] = []
      const content = e.message.content.map(block => redactBlock(block, kinds, known))

      if (kinds.length === 0) return next(e)

      $.ui.toast(`Redacted ${kinds.length} secret${kinds.length === 1 ? '' : 's'}: ${kinds.join(', ')}`)
      return next({ ...e, message: { ...e.message, content } })
    }).catch(($, e, next) =>
      // The check failed before it could read the row, so the row keeps nothing it did not read.
      next.called ? next(e) : next({ ...e, message: { ...e.message, content: e.message.content.map(withhold) } }),
    )
  }
}
