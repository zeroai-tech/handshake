#!/usr/bin/env node
// Handshake MCP — lets an agent USE credentials it has been granted, and
// nothing more.
//
// There is deliberately no `unlock` tool here, and no way to supply a
// passphrase or a 2FA code. Opening the vault is a human action taken in a
// terminal; this server can only spend a session that a human already opened,
// and only for the lifetime that human granted.
//
// The session token is passed per call rather than stored, so it lives in the
// conversation and disappears with it. A new chat has no token and must ask.
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CLI = path.join(HERE, 'handshake')
const NAME = 'handshake', VERSION = '1.0.0'

function run(args) {
  return new Promise((resolve) => {
    const p = spawn(CLI, args, { stdio: ['ignore', 'pipe', 'pipe'] })
    let out = '', err = ''
    p.stdout.on('data', (d) => (out += d))
    p.stderr.on('data', (d) => (err += d))
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
  const s = args.session ? ['--session', args.session] : []
  switch (name) {
    case 'handshake_status': return text((await run(['status'])).out)
    case 'handshake_list':   return text((await run(['list', ...s])).out)
    case 'handshake_get': {
      const r = await run(['get', args.name, '--reason', args.reason || 'unspecified', ...s])
      if (r.code !== 0) return text(r.out || r.err)
      return text(r.out)
    }
    case 'handshake_put': {
      const a = ['put', args.name, '--value', args.value, ...s]
      if (args.note) a.push('--note', args.note)
      if (args.category) a.push('--category', args.category)
      return text((await run(a)).out)
    }
    case 'handshake_log':
      return text((await run(['log', '--limit', String(args.limit || 30), ...s])).out)
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
