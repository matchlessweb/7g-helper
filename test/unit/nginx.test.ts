// Every exception file through real nginx (Docker): GridPane's shipped 7G maps and per-site file, the generated file
// in the site's folder, and requests sent to it. A file can pass nginx -t and still do nothing, or let through far more
// than the request it was written for; only real requests show which. Each scenario is its own server on its own port.
//
// The three ways a generated exception has been seen to fail (Matchless Fleet's generator, 2026-11-24) are each put
// back on purpose below, and nginx must show the failure, so this check is known to be able to fail:
//   1. a variable whose name starts with a digit ($7g_x): in an expression nginx reads it as regex capture $7 + "g_x";
//   2. only one of several fired rules lifted: the request stays blocked;
//   3. the path alone as the pattern: every query to that page gets past the rule;
//   4. a variable name over 46 characters: nginx -t fails at GridPane's variables_hash_bucket_size (nginx's default, 64).

import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { analyze } from '../../src/lib/analyze.ts'
import { buildException } from '../../src/lib/exception.ts'
import { parseMappings } from '../../src/lib/rules.ts'

const root = new URL('../../', import.meta.url)
const mappings = readFileSync(new URL('rules/gridpane-7g-mappings.conf', root), 'utf8')
const siteConf = readFileSync(new URL('rules/gridpane-7g-site.conf', root), 'utf8')
const samples = readFileSync(new URL('test/fixtures/7g-log-samples.txt', root), 'utf8')
const groups = parseMappings(mappings)
const docker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0
const skip = !docker && 'docker is not running'
const IMAGE = 'nginx:1.30'
const BROWSER = 'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0'

interface Probe {
  uri: string
  ua?: string
}
interface Scenario {
  name: string
  exception: string
  probes: Probe[]
}

/** Run every scenario in one nginx; returns the status code of each probe, per scenario. */
function serve(scenarios: Scenario[]): number[][] {
  const dir = mkdtempSync(join(tmpdir(), '7g-nginx-'))
  mkdirSync(join(dir, 'extra'))
  writeFileSync(join(dir, '7g-mappings.conf'), mappings)
  const servers = scenarios.map((s, i) => {
    const site = join(dir, `s${i}`)
    mkdirSync(site)
    writeFileSync(join(site, 'test-7g-context.conf'), s.exception)
    // GridPane's per-site file as shipped, with its include paths moved into the test folder and every group on.
    const processing = siteConf
      .replace(/^#(if \(\$bad_referer_7g\))/m, '$1')
      .replace('include /etc/nginx/extra.d/*7g-context.conf;', 'include /x/extra/*7g-context.conf;')
      .replace(/include \/var\/www\/[^/]+\/nginx\/\*-7g-context\.conf;/, `include /x/s${i}/*-7g-context.conf;`)
      .replace(/^access_log .*$/m, '')
    assert.match(processing, new RegExp(`include /x/s${i}/`), 'the site include was moved')
    writeFileSync(join(site, '7g.conf'), processing)
    return `  server {\n    listen ${9000 + i};\n    include /x/s${i}/7g.conf;\n    location / { return 200 "ok\\n"; }\n  }`
  })
  // variables_hash_max_size as GridPane's /etc/nginx/common/basics.conf sets it; the bucket size stays at its default.
  writeFileSync(join(dir, 'nginx.conf'), `events {}\nhttp {\n  variables_hash_max_size 2048;\n  include /x/7g-mappings.conf;\n${servers.join('\n')}\n}\n`)
  const probes = scenarios.flatMap((s, i) => s.probes.map((p) => `${9000 + i}\t${p.ua ?? BROWSER}\t${p.uri}`))
  writeFileSync(join(dir, 'probes.tsv'), `${probes.join('\n')}\n`)
  writeFileSync(
    join(dir, 'run.sh'),
    [
      'nginx -t -q -c /x/nginx.conf || exit 3',
      'nginx -c /x/nginx.conf',
      "while IFS='\t' read -r port ua uri; do",
      '  curl -s --path-as-is -o /dev/null -w "%{http_code}\\n" -A "$ua" "http://127.0.0.1:$port$uri"',
      'done < /x/probes.tsv',
    ].join('\n'),
  )
  const out = execFileSync('docker', ['run', '--rm', '-v', `${dir}:/x`, IMAGE, 'sh', '/x/run.sh'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const codes = out.trim().split('\n').filter((l) => /^\d{3}$/.test(l)).map(Number)
  assert.equal(codes.length, probes.length, out)
  let at = 0
  return scenarios.map((s) => codes.slice(at, (at += s.probes.length)))
}

// The OAuth sign-in false positive, as a GridPane server logged it on 2026-11-24 (IP anonymized).
const OAUTH = '[24/Nov/2026:19:52:04 +0000] [":bad_querystring_10::bad_request_15:"] 203.0.113.50 example.com "GET /?redirect_uri=http://localhost:8080/callback HTTP/2.0" 403 0.000 "-" "curl/8.7.1"'
const oauth = analyze(OAUTH, groups)[0]
assert.ok(oauth.ok)
const oauthFile = buildException(oauth.line, oauth.matches, 'site', '2026-11-24').content

const LEGIT = { uri: '/?redirect_uri=http://localhost:8080/callback' }
const NEAR = [
  { uri: '/?redirect_uri=http://localhost:9999/other' },
  { uri: '/?redirect_uri=http://localhost:8080/callbackX' },
  { uri: '/sample-page/?redirect_uri=http://localhost:8080/callback' },
]
const ATTACK = [{ uri: '/?q=%3Cscript%3E' }, { uri: '/.env' }]

test('real nginx: the OAuth exception lets that request through, and nothing near it', { skip }, () => {
  const [none, fixed, digit, oneRule, pathOnly] = serve([
    { name: 'no exception', exception: '', probes: [LEGIT] },
    { name: 'fixed', exception: oauthFile, probes: [LEGIT, { uri: '/?x=1&redirect_uri=http://localhost:8080/callback' }, ...NEAR, ...ATTACK] },
    // Control 1: the same file with a digit-leading variable, as Fleet wrote it.
    { name: 'digit variable', exception: oauthFile.replaceAll('$allow7g_', '$7g_allow_'), probes: [LEGIT] },
    // Control 2: only the first fired rule lifted.
    { name: 'one rule', exception: oauthFile.split('\n\nset ')[0], probes: [LEGIT] },
    // Control 3: the path alone as the pattern, as 7G Helper wrote it before.
    { name: 'path only', exception: oauthFile.replace(/~ "\^\/\\\?\(\.\*&\)\?redirect_uri=[^"]*"/g, '~ "^/(\\?|$)"'), probes: NEAR },
  ])
  assert.deepEqual(none, [403], 'without the file, the request is blocked')
  assert.deepEqual(fixed, [200, 200, 403, 403, 403, 403, 403], 'the request passes; near misses and attacks stay 403')
  assert.deepEqual(digit, [403], 'control 1: a $7… variable never matches, so the request stays blocked')
  assert.deepEqual(oneRule, [403], 'control 2: lifting one of two fired rules leaves the request blocked')
  assert.notDeepEqual(pathOnly, [403, 403, 403], 'control 3: the path-only pattern lets near misses through')
  assert.equal(pathOnly[0], 200, 'control 3: a different localhost redirect gets through the path-only pattern')
})

test('real nginx: every sample line’s exception lets its own request through and keeps 7G on', { skip }, () => {
  const lines = analyze(samples, groups).flatMap((r) =>
    // Custom-list rules are not in the shipped maps, so nothing here would block them.
    r.ok && r.matches.every((m) => m.status === 'matched') ? [r] : [],
  )
  assert.ok(lines.length >= 12, `${lines.length} lines`)
  const scenarios = lines.map((r) => {
    const file = buildException(r.line, r.matches, 'site', 'x')
    const ua = r.line.userAgent || BROWSER
    const probes = [{ uri: r.line.uri, ua }, { uri: '/?q=%3Cscript%3E' }, { uri: '/wp-config.php.bak' }]
    return { name: file.fileName, exception: file.content, probes }
  })
  const blocked = serve(scenarios.map((s) => ({ ...s, exception: '', probes: s.probes.slice(0, 1) })))
  const results = serve(scenarios)
  scenarios.forEach((s, i) => {
    assert.equal(blocked[i][0], 403, `${s.name}: the logged request is blocked without the file`)
    assert.notEqual(results[i][0], 403, `${s.name}: the logged request passes with it`)
    assert.deepEqual(results[i].slice(1), [403, 403], `${s.name}: the rest of 7G is still on`)
  })
})

test('real nginx: control 4, a variable name of 47 characters fails nginx -t, 46 passes', { skip }, () => {
  assert.throws(() => serve([{ name: 'long', exception: `set $${'a'.repeat(47)} "";\n`, probes: [LEGIT] }]), /variables_hash/)
  assert.deepEqual(serve([{ name: 'ok', exception: `set $${'a'.repeat(46)} "";\n`, probes: [LEGIT] }]), [[403]])
})
