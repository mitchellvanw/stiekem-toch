import { expect, test, type TestBody } from 'claude-code/testing'

// Built from parts, so this file holds no whole key for a secret scanner to flag.
const GITHUB = 'ghp_' + 'a'.repeat(36)
const JWT = 'eyJ' + 'h'.repeat(20) + '.' + 'p'.repeat(20) + '.' + 's'.repeat(20)
const TOOL = 'mcp__sanitize-secrets__request'

test('a Bash command holding a token is denied', async ($, on) => {
  // Stands in for the engine beneath the plugin: a call that gets this far would run.
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('tool.call', () => ({ result: {} }))
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  const answer = await $.tool.call({ tool: 'Bash', command: `echo ${GITHUB}` })

  expect(answer.deny).toContain('did not run')
})

test('a Bash command with no secret runs', async ($, on) => {
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('tool.call', () => ({ result: {} }))
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  const answer = await $.tool.call({ tool: 'Bash', command: 'ls' })

  expect(answer.deny).toBeUndefined()
})

test("a tool's structured record is redacted, not only its text", async ($, on) => {
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('tool.call', () => ({ result: { stdout: GITHUB, stderr: '' }, text: GITHUB }))
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  const answer = await $.tool.call({ tool: 'Bash', command: 'printf x' })

  expect(answer.result).toEqual({ stdout: '[redacted: GitHub token]', stderr: '' })
  expect(answer.text).toBe('[redacted: GitHub token]')
})

test('a typed prompt is redacted before the history and the queue record keep it', async ($, on) => {
  const arrived: string[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('prompt.submit', (_, e) => {
    arrived.push(e.text)
    return { text: e.text }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  await $.prompt.submit({ text: `my token is ${GITHUB}`, origin: { kind: 'composer' }, wait: false })

  expect(arrived).toEqual(['my token is [redacted: stored secret "pasted-1"]'])
})

test("a slash command's arguments are redacted before it runs", async ($, on) => {
  const arrived: string[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('command.run', (_, e) => {
    arrived.push(e.args)
    return { text: '' }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  await $.command.run({
    command: 'note',
    args: `remember ${GITHUB}`,
    origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 80 },
  })

  expect(arrived).toEqual(['remember [redacted: GitHub token]'])
})

test('the request tool is offered with no secret stored', async ($, on) => {
  const registered: string[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', (_, e) => {
    registered.push(e.description ?? '')
    return { value: { tool: TOOL } }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  expect(registered).toHaveLength(1)
  expect(registered[0]).toContain('No secret is stored yet')
})

test('a pasted key is kept for the session, and the model is told its name', async ($, on) => {
  const context: (readonly string[] | undefined)[] = []
  const registered: string[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', (_, e) => {
    registered.push(e.description ?? '')
    return { value: { tool: TOOL } }
  })
  on('prompt.submit', (_, e) => {
    context.push(e.context)
    return { text: e.text }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })

  await $.prompt.submit({ text: `${JWT} and again ${JWT}`, origin: { kind: 'composer' }, wait: false })

  expect(context[0]?.join('')).toContain('"pasted-1", a JSON Web Token')
  expect(context[0]?.join('')).not.toContain('pasted-2')
  expect(registered.at(-1)).toContain('"pasted-1": a JSON Web Token the person pasted')
})

// Answers the dialog `$.ui.ask` opens with `answer`, and counts how often it opened.
function answerAsks(on: Parameters<TestBody>[1], answer: string): string[] {
  const asked: string[] = []
  on('tool.call', { tool: 'AskUserQuestion' }, (_, e) => {
    const question = (e as unknown as { questions: { question: string }[] }).questions[0]!.question
    asked.push(question)
    return { result: { answers: { [question]: answer } } }
  })
  return asked
}

test('a pasted key goes to a host once the person allows it, and is asked once per host', async ($, on) => {
  const sent: { url: string; auth?: string }[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('prompt.submit', (_, e) => ({ text: e.text }))
  const asked = answerAsks(on, 'Send it')
  on('http.fetch', (_, e) => {
    sent.push({ url: e.url, auth: e.init?.headers?.Authorization })
    return { value: { status: 200, ok: true, headers: {}, text: `you sent ${e.init?.headers?.Authorization}` } }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await $.prompt.submit({ text: JWT, origin: { kind: 'composer' }, wait: false })

  const first = await $.tool.call({ tool: TOOL, secret: 'pasted-1', url: 'https://api.themoviedb.org/3/authentication' })
  await $.tool.call({ tool: TOOL, secret: 'pasted-1', url: 'https://api.themoviedb.org/3/configuration' })

  expect(asked).toHaveLength(1)
  expect(asked[0]).toContain('api.themoviedb.org')
  expect(sent).toEqual([
    { url: 'https://api.themoviedb.org/3/authentication', auth: `Bearer ${JWT}` },
    { url: 'https://api.themoviedb.org/3/configuration', auth: `Bearer ${JWT}` },
  ])
  expect(JSON.parse(first.result as string).body).toBe('you sent Bearer [redacted: stored secret "pasted-1"]')
})

test('a pasted key does not go to a host the person refuses', async ($, on) => {
  const sent: unknown[] = []
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('tool.register', () => ({ value: { tool: TOOL } }))
  on('prompt.submit', (_, e) => ({ text: e.text }))
  answerAsks(on, "Don't send it")
  on('http.fetch', (_, e) => {
    sent.push(e)
    return { value: { status: 200, ok: true, headers: {}, text: '' } }
  })
  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await $.prompt.submit({ text: JWT, origin: { kind: 'composer' }, wait: false })

  const answer = await $.tool.call({ tool: TOOL, secret: 'pasted-1', url: 'https://evil.example/' })

  expect(sent).toHaveLength(0)
  expect(answer.deny).toContain('did not allow')
})
