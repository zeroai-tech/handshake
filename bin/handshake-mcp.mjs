#!/usr/bin/env node
// Bearer tokens grant whole-vault access to trusted tools. See SECURITY.md.
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CLI = path.join(HERE, 'handshake')
const NAME = 'handshake', VERSION = '1.1.0'

function run(args, session, input) {
  return new Promise((resolve) => {
    const env = { ...process.env }
    delete env.HANDSHAKE_SESSION
    if (session) env.HANDSHAKE_SESSION = session
    const p = spawn(CLI, args, { env, stdio: ['pipe', 'pipe', 'pipe'] })
    p.stdin.on('error', () => {})
    p.stdin.end(input ?? '')
    let out = '', err = ''
    p.stdout.on('data', (d) => (out += d))
    p.stderr.on('data', (d) => (err += d))
    p.on('error', () => resolve({ code: 1, out: '', err: 'Could not start Handshake. Check its installation.' }))
    p.on('close', (code) => resolve({ code, out: out.trim(), err: err.trim() }))
  })
}

const TOOLS = [
  {
    name: 'handshake_status',
    description: 'Is the vault open? Shows whether a session is live, how long is left, and how many secrets exist. Needs no token — call this first when a credential is needed.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'handshake_list',
    description: 'List the NAMES of stored credentials (never values). Requires an open session token.',
    inputSchema: {
      type: 'object',
      properties: { session: { type: 'string', description: 'token from `handshake unlock`' } },
      required: ['session'],
    },
  },
  {
    name: 'handshake_get',
    description: 'Read ONE credential by name. Requires an open session token. Every read is written to an append-only audit log with the reason given, so always pass a truthful reason.',
    inputSchema: {
      type: 'object',
      properties: {
        session: { type: 'string' },
        name: { type: 'string', description: 'exact secret name, from handshake_list' },
        reason: { type: 'string', description: 'why it is needed — recorded permanently' },
      },
      required: ['session', 'name', 'reason'],
    },
  },
  {
    name: 'handshake_put',
    description: 'Store or update one credential. Requires an open session token.',
    inputSchema: {
      type: 'object',
      properties: {
        session: { type: 'string' }, name: { type: 'string' }, value: { type: 'string' },
        note: { type: 'string' }, category: { type: 'string' },
      },
      required: ['session', 'name', 'value'],
    },
  },
  {
    name: 'handshake_log',
    description: 'Recent access log — who read which credential, when, from where.',
    inputSchema: {
      type: 'object',
      properties: { session: { type: 'string' }, limit: { type: 'number' } },
      required: ['session'],
    },
  },
]

const text = (t) => ({ content: [{ type: 'text', text: t }] })

async function call(name, args = {}) {
  const invalid = () => ({ ...text('Invalid or missing tool arguments.'), isError: true })
  if (!args || typeof args !== 'object' || Array.isArray(args)) return invalid()
  if (name !== 'handshake_status' && (typeof args.session !== 'string' || !args.session || args.session.length > 512)) return invalid()
  if (['handshake_get', 'handshake_put'].includes(name) && (typeof args.name !== 'string' || !args.name || args.name.length > 128)) return invalid()
  if (name === 'handshake_put' && (typeof args.value !== 'string' || args.value.length > 32768)) return invalid()
  for (const field of ['note', 'category']) if (args[field] !== undefined && typeof args[field] !== 'string') return invalid()
  if (args.limit !== undefined && (!Number.isInteger(args.limit) || args.limit < 1 || args.limit > 100)) return invalid()
  const result = r => ({ ...text(r.out || r.err || (r.code ? 'Handshake operation failed.' : 'Done.')), ...(r.code ? { isError: true } : {}) })
  switch (name) {
    case 'handshake_status': return result(await run(['status']))
    case 'handshake_list':   return result(await run(['list'], args.session))
    case 'handshake_get': {
      if (!args.reason || typeof args.reason !== 'string') return { ...text('A reason is required.'), isError: true }
      return result(await run(['get', args.name, '--reason', args.reason], args.session))
    }
    case 'handshake_put': {
      const a = ['put', args.name, '--value', '-']
      if (args.note) a.push('--note', args.note)
      if (args.category) a.push('--category', args.category)
      return result(await run(a, args.session, args.value))
    }
    case 'handshake_log':
      return result(await run(['log', '--limit', String(args.limit || 30)], args.session))
    default:
      return text(`unknown tool: ${name}`)
  }
}

const send = (m) => process.stdout.write(JSON.stringify(m) + '\n')
createInterface({ input: process.stdin }).on('line', async (line) => {
  if (!line.trim()) return
  let msg
  try { msg = JSON.parse(line) } catch { return }
  const { id, method, params } = msg
  if (method === 'initialize')
    return send({ jsonrpc: '2.0', id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: NAME, version: VERSION } } })
  if (method === 'tools/list')
    return send({ jsonrpc: '2.0', id, result: { tools: TOOLS } })
  if (method === 'tools/call') {
    try { return send({ jsonrpc: '2.0', id, result: await call(params.name, params.arguments || {}) }) }
    catch (e) { return send({ jsonrpc: '2.0', id, error: { code: -32000, message: String(e.message || e) } }) }
  }
  if (id !== undefined) send({ jsonrpc: '2.0', id, result: {} })
})
