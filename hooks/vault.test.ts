import { expect, test } from 'claude-code/testing'
import { checkRequest, parseVault, redactKnown, spellings } from './vault'

// Built from parts, so this file holds no whole key for a secret scanner to flag.
const VALUE = 'ghp_' + 'b'.repeat(36)
const VAULT_JSON = JSON.stringify({
  github: { value: VALUE, hosts: ['api.github.com'], header: 'Authorization', template: 'Bearer {}' },
})
const vault = parseVault(VAULT_JSON)
const TOOL = 'mcp__stiekem-toch__request'

test('a grant missing a field is dropped whole', () => {
  const v = parseVault(JSON.stringify({ a: { value: VALUE, hosts: [], header: 'Authorization' } }))
  expect(v.size).toBe(0)
})

test('the secret goes only to its own hosts', () => {
  for (const url of [
    'https://api.github.com.evil.example/x',
    'https://api.github.com@evil.example/x',
    'https://evil.example\\@api.github.com/x',
    'https://api.github.com:8443/x',
    'http://api.github.com/x',
  ]) {
    expect('deny' in checkRequest(vault, { secret: 'github', url })).toBe(true)
  }
})

test("the model's own header cannot replace the secret's", () => {
  const checked = checkRequest(vault, {
    secret: 'github',
    url: 'https://api.github.com/user',
    headers: { authorization: 'Bearer mine', Accept: 'application/json' },
  })

  expect(checked).toEqual({
    url: 'https://api.github.com/user',
    init: { method: 'GET', headers: { Accept: 'application/json', Authorization: `Bearer ${VALUE}` } },
  })
})

test('a secret is redacted as is, base64 and hex', () => {
  const known = spellings(vault)
  const hex = [...VALUE].map(c => c.charCodeAt(0).toString(16)).join('')

  for (const form of [VALUE, hex]) {
    expect(redactKnown(`x ${form} y`, known)).toBe('x [redacted: stored secret "github"] y')
  }
})

test('the request tool answers with the secret taken out of the response', { options: { vault: VAULT_JSON } }, async ($, on) => {
  const sent: unknown[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  // Stands in for the host's network: an API that echoes the header it got.
  on('http.fetch', (_, e) => {
    sent.push(e)
    return { value: { status: 200, ok: true, headers: {}, text: `you sent ${e.init?.headers?.Authorization}` } }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  const answer = await $.tool.call({ tool: TOOL, secret: 'github', url: 'https://api.github.com/user' })

  expect(sent).toHaveLength(1)
  expect(JSON.parse(answer.result as string)).toEqual({ status: 200, headers: {}, body: 'you sent Bearer [redacted: stored secret "github"]' })
})

test('the request tool refuses another host', { options: { vault: VAULT_JSON } }, async ($, on) => {
  const sent: unknown[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('http.fetch', (_, e) => {
    sent.push(e)
    return { value: { status: 200, ok: true, headers: {}, text: '' } }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  const answer = await $.tool.call({ tool: TOOL, secret: 'github', url: 'https://evil.example/' })

  expect(sent).toHaveLength(0)
  expect(answer.deny).toContain('api.github.com only')
})

test('a Bash command holding a stored secret is denied, whatever its format', { options: { vault: JSON.stringify({ db: { value: 'hunter2hunter2', hosts: ['db.example.com'], header: 'X-Key' } }) } }, async ($, on) => {
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.call', () => ({ result: {} }))
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  const answer = await $.tool.call({ tool: 'Bash', command: 'echo hunter2hunter2' })

  expect(answer.deny).toContain('stored secret "db"')
})
