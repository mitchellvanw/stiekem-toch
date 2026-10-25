// Secrets the person stores for the model to use without reading them. Each one
// is bound to the hosts it may be sent to and the header that carries it.
export type Grant = {
  value: string
  hosts: readonly string[]
  header: string
  // How the header's value is spelled, `{}` standing for the secret: `Bearer {}`.
  template: string
  // Set on a key the person pasted into a prompt, to its kind. Such a grant starts
  // with no hosts; each one is added when the person allows it at first use.
  pasted?: string
}

export type Vault = ReadonlyMap<string, Grant>

export type Request = {
  secret: string
  method?: string
  url: string
  headers?: Record<string, string>
  body?: string
}

export type Checked = { url: string; init: { method: string; headers: Record<string, string>; body?: string } }

const NAME = /^[a-z0-9_-]{1,32}$/
const HOST = /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/
// https only, a bare host (no user info, no port but 443), a path with no backslash.
const URL_SHAPE = /^https:\/\/([a-z0-9.-]+)(?::443)?(\/[^\s#\\]*)?$/i
const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])

// The vault from the `vault` option: a JSON object of grants by name. A grant
// that does not hold its shape is dropped whole, so a typo never widens one.
export function parseVault(text: string | undefined): Vault {
  const vault = new Map<string, Grant>()
  if (text === undefined || text.trim() === '') return vault

  const parsed: unknown = JSON.parse(text)
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return vault

  for (const [name, raw] of Object.entries(parsed)) {
    const g = raw as Partial<Grant>
    const template = g.template ?? '{}'
    const isGrant =
      NAME.test(name) &&
      typeof g.value === 'string' &&
      g.value.length >= 8 &&
      Array.isArray(g.hosts) &&
      g.hosts.length > 0 &&
      g.hosts.every(h => typeof h === 'string' && HOST.test(h)) &&
      typeof g.header === 'string' &&
      /^[A-Za-z0-9-]+$/.test(g.header) &&
      typeof template === 'string' &&
      template.includes('{}')

    if (isGrant) vault.set(name, { value: g.value!, hosts: g.hosts!, header: g.header!, template })
  }

  return vault
}

// A key pasted into a prompt, kept for the session. It goes to no host until the
// person allows one, and then as a bearer token.
export function pastedGrant(kind: string, value: string): Grant {
  return { value, hosts: [], header: 'Authorization', template: 'Bearer {}', pasted: kind }
}

// The host a request's URL names, lowercased, or undefined when the URL is not https://<host>/<path>.
export function hostOf(url: string): string | undefined {
  return URL_SHAPE.exec(url)?.[1]?.toLowerCase()
}

// The fetch a request comes to, or why it does not run. The secret goes in
// only here, after the host is held to the grant.
export function checkRequest(vault: Vault, req: Request): Checked | { deny: string } {
  const grant = vault.get(req.secret)
  if (grant === undefined) return { deny: `no secret is named "${req.secret}"` }

  const host = hostOf(req.url)
  if (host === undefined) return { deny: 'the URL must be https://<host>/<path>, with no user info or port' }

  if (!grant.hosts.includes(host)) return { deny: `"${req.secret}" may be sent to ${grant.hosts.join(', ')} only, not ${host}` }

  const method = (req.method ?? 'GET').toUpperCase()
  if (!METHODS.has(method)) return { deny: `the method ${method} is not allowed` }

  const headers: Record<string, string> = {}
  for (const [name, value] of Object.entries(req.headers ?? {})) {
    if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) return { deny: 'a header holds a line break' }
    // The model may not set the header the secret rides in, nor where it goes.
    if (name.toLowerCase() === grant.header.toLowerCase() || name.toLowerCase() === 'host') continue
    headers[name] = value
  }
  headers[grant.header] = grant.template.replace('{}', grant.value)

  return { url: req.url, init: { method, headers, ...(req.body === undefined ? {} : { body: req.body }) } }
}

// Every spelling of each secret a response or output is checked for: the value
// as is, URL-encoded, base64 (standard and URL-safe, unpadded) and hex.
// Each pairs with the name the model reads in its place.
export function spellings(vault: Vault): readonly [string, string][] {
  const out: [string, string][] = []

  for (const [name, { value }] of vault) {
    const b64 = base64(value)
    const forms = new Set([
      value,
      encodeURIComponent(value),
      b64.replace(/=+$/, ''),
      b64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'),
      hex(value),
      hex(value).toUpperCase(),
    ])
    for (const form of forms) out.push([form, name])
  }

  // Longest first, so a spelling that holds another is replaced whole.
  return out.sort((a, b) => b[0].length - a[0].length)
}

export function redactKnown(text: string, known: readonly [string, string][], kinds: string[] = []): string {
  return known.reduce((out, [form, name]) => {
    if (!out.includes(form)) return out
    kinds.push(`stored secret "${name}"`)
    return out.split(form).join(`[redacted: stored secret "${name}"]`)
  }, text)
}

function utf8(text: string): number[] {
  return [...encodeURIComponent(text)].reduce<{ bytes: number[]; pct: string }>(
    (acc, ch) => {
      if (acc.pct !== '' || ch === '%') {
        acc.pct += ch
        if (acc.pct.length === 3) {
          acc.bytes.push(parseInt(acc.pct.slice(1), 16))
          acc.pct = ''
        }
      } else {
        acc.bytes.push(ch.charCodeAt(0))
      }
      return acc
    },
    { bytes: [], pct: '' },
  ).bytes
}

function hex(text: string): string {
  return utf8(text)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function base64(text: string): string {
  const bytes = utf8(text)
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const [a = 0, b = 0, c = 0] = bytes.slice(i, i + 3)
    const n = (a << 16) | (b << 8) | c
    out += B64.charAt((n >> 18) & 63) + B64.charAt((n >> 12) & 63)
    out += i + 1 < bytes.length ? B64.charAt((n >> 6) & 63) : '='
    out += i + 2 < bytes.length ? B64.charAt(n & 63) : '='
  }
  return out
}
