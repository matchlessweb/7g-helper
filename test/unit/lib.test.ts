import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { analyze } from '../../src/lib/analyze.ts'
import { buildException, MAX_VARIABLE_NAME, nginxRegex, paramsAround } from '../../src/lib/exception.ts'
import { parseLogLine } from '../../src/lib/logline.ts'
import { nginxUnquote, parseMappings } from '../../src/lib/rules.ts'

const root = new URL('../../', import.meta.url)
const groups = parseMappings(readFileSync(new URL('rules/gridpane-7g-mappings.conf', root), 'utf8'))
const samples = readFileSync(new URL('test/fixtures/7g-log-samples.txt', root), 'utf8')
const results = analyze(samples, groups)
const ok = results.filter((r) => r.ok)

test('the shipped maps parse completely', () => {
  const counts = Object.fromEntries([...groups].map(([id, g]) => [id, g.rules.length]))
  assert.deepEqual(counts, { bad_bot: 7, bad_referer: 3, bad_querystring: 38, bad_request: 26, not_allowed_method: 5 })
  assert.equal(groups.get('bad_request')!.customInclude, '/etc/nginx/extra.d/*7g-bad-request-context.conf')
  assert.throws(() => parseMappings('map $request_uri $bad_request_7g {\n  ~*(x) one;\n}'), /not a rule/)
})

test('every sample line parses', () => {
  assert.equal(results.length, 15)
  assert.equal(ok.length, 15)
})

test("13 lines match the logged rule; the 2 bad_bot_6 lines are a custom list", () => {
  const statuses = ok.flatMap((r) => r.matches.map((m) => `${m.hit.group}_${m.hit.number}:${m.status}`))
  assert.equal(statuses.filter((s) => s.endsWith(':matched')).length, 13)
  assert.deepEqual(statuses.filter((s) => !s.endsWith(':matched')), ['bad_bot_6:custom', 'bad_bot_6:custom'])
})

test('the matched text is what the rule fired on', () => {
  const texts = ok.flatMap((r) => r.matches.filter((m) => m.matched).map((m) => m.matched!.text.toLowerCase()))
  assert.ok(texts.includes('.env'))
  assert.ok(texts.includes('petalbot'))
  assert.ok(texts.some((t) => t.startsWith('http') && t.includes('://')), 'rank math https://')
})

test('a quote logged as \\x22 is unescaped before matching', () => {
  const r = ok.find((r) => r.ok && r.matches[0].hit.number === 8 && r.matches[0].hit.group === 'bad_request')!
  assert.ok(r.ok && r.line.uri.endsWith('"'))
})

test('verdicts', () => {
  const byPath = Object.fromEntries(ok.map((r) => [r.ok && `${r.line.path}|${r.line.userAgent.slice(0, 12)}`, r.ok && r.verdict.kind]))
  const kind = (path: string) => Object.entries(byPath).find(([k]) => k.startsWith(`${path}|`))![1]
  assert.equal(kind('/wp-json/rankmath/v1/getHead'), 'false_positive')
  assert.equal(kind('/robots.txt'), 'false_positive')
  assert.equal(kind('/sitemap_index.xml'), 'judgment')
  assert.equal(kind('/podcast/sample-episode/context.line_item.image.srcset'), 'judgment')
  for (const p of ['/.env', '/web.config', '/docker-compose.yml', '/wp-includes/js/codemirror/config.php', '/wp-admin/shell.php', '/cgi-bin/cgi-bin/sql.php', '/tmp/core.php', '/database/.env', '/var/www/html/.env', '/htdocs/.env', '/%22/t/ct.js']) {
    assert.equal(kind(p), 'attack', p)
  }
})

test('lines that are not 7G lines say why', () => {
  const bad = analyze('hello there\n[21/Oct/2026:11:40:47 +0000] [":bad_request_27:"] 1.2.3.4 x.com "GET /', groups)
  assert.equal(bad.length, 2)
  assert.ok(!bad[0].ok && /not a 7G log line/.test(bad[0].reason))
  assert.ok(!bad[1].ok && /part of it is missing/.test(bad[1].reason))
  const none = parseLogLine('[21/Oct/2026:11:40:47 +0000] [""] 1.2.3.4 x.com "GET / HTTP/2.0" 200 0.000 "-" "x"')
  assert.ok(!none.ok && /names no 7G rule/.test(none.reason))
})

const nginxTest = (cond: string) => {
  const m = cond.match(/^\$(\S+) (~\*?) "(.*)"$/)!
  return { variable: m[1], regex: new RegExp(nginxUnquote(m[3]), m[2] === '~*' ? 'i' : '') }
}
const conditions = (content: string) => [...content.matchAll(/^if \((\$\S+ ~\*? ".*")\) \{$/gm)].map((m) => nginxTest(m[1]))

test('the Rank Math exception, in full', () => {
  const r = ok.find((r) => r.ok && r.line.path === '/wp-json/rankmath/v1/getHead')!
  assert.ok(r.ok)
  const site = buildException(r.line, r.matches, 'site', '2026-10-21')
  assert.equal(site.path, '/var/www/example.org/nginx/allow-rankmath-v1-gethead-7g-context.conf')
  assert.match(site.content, /^set \$allow7g_rankmath_v1_gethead_request_15 "";$/m)
  assert.ok(
    site.content.includes('if ($request_uri ~ "^/wp-json/rankmath/v1/getHead\\?(.*&)?url=https://example\\.org(&|$)") {\n'),
    site.content,
  )
  assert.match(site.content, /^if \(\$bad_request_7g = \$allow7g_rankmath_v1_gethead_request_15\) \{\n {4}set \$7g_drop_bad_request 0;\n\}$/m)
  assert.equal(site.testAllowed, `curl -s -o /dev/null -w '%{http_code}\\n' 'https://example.org/wp-json/rankmath/v1/getHead?url=https://example.org'`)
  const server = buildException(r.line, r.matches, 'server', '2026-10-21')
  assert.equal(server.path, '/etc/nginx/extra.d/allow-rankmath-v1-gethead-7g-context.conf')
})

test("every exception's condition matches its own request and not a probe", () => {
  for (const r of ok) {
    if (!r.ok) continue
    const file = buildException(r.line, r.matches, 'site', '2026-10-21')
    assert.match(file.fileName, /^allow-[a-z0-9-]+-7g-context\.conf$/)
    assert.equal(file.path, `/var/www/${r.line.host.replace(/^www\./, '')}/nginx/${file.fileName}`)
    for (const c of conditions(file.content)) {
      const value = { request_uri: r.line.uri, http_user_agent: r.line.userAgent, http_referer: r.line.referer }[c.variable]!
      assert.ok(c.regex.test(value), `${file.fileName}: ${c.regex} vs ${value}`)
      assert.ok(!c.regex.test(c.variable === 'http_user_agent' ? 'Mozilla/5.0 BLEXBot' : '/wp-config.php.bak?x=1'), `${file.fileName} too wide`)
    }
    for (const m of file.content.matchAll(/^set (\$\S+) "";$/gm)) assert.match(m[1], /^\$[A-Za-z0-9_]+$/)
  }
})

test('bot exceptions name the crawler', () => {
  const fb = ok.find((r) => r.ok && r.line.userAgent.startsWith('facebookexternalhit'))!
  assert.ok(fb.ok)
  const f = buildException(fb.line, fb.matches, 'site', '2026-10-21')
  assert.equal(f.fileName, 'allow-facebook-7g-context.conf')
  assert.match(f.content, /\$http_user_agent ~\* "facebookexternalhit"/)
  assert.match(f.content, /if \(\$bad_bot_7g = \$allow7g_facebook_bot_6\)/)
  assert.match(f.testStillBlocked, /-A 'BLEXBot'/)
  const gpt = ok.find((r) => r.ok && /GPTBot/.test(r.line.userAgent))!
  assert.ok(gpt.ok)
  assert.match(buildException(gpt.line, gpt.matches, 'site', 'x').content, /~\* "GPTBot"/)
})

test('nginxRegex escapes for the regex and for nginx quoting', () => {
  for (const s of ['/a.b', '/a"b', '/a\\b', '/a(b)?c$', '/{x}|[y]*+^']) {
    const re = new RegExp(`^${nginxUnquote(nginxRegex(s))}$`)
    assert.ok(re.test(s), s)
  }
})

test('a short line, as GridPane docs print it, still reads; with no user agent the scope is the address', () => {
  const r = analyze('[17/Nov/2020:15:05:35 +0000] [":bad_querystring_12::bad_request_15:"] 199.199.199.199 yourdomain.com "GET /wp-json/kadence-cloud/v1/get?key=abc HTTP/1.1" 403', groups)
  assert.equal(r.length, 1)
  const one = r[0]
  assert.ok(one.ok)
  assert.deepEqual(one.matches.map((m) => `${m.hit.group}_${m.hit.number}`), ['bad_querystring_12', 'bad_request_15'])
  const f = buildException(one.line, one.matches, 'site', 'x')
  assert.match(f.path, /^\/var\/www\/yourdomain\.com\/nginx\/.*-7g-context\.conf$/)
  assert.match(f.content, /set \$7g_drop_bad_query_string 0;/)
  assert.match(f.content, /set \$7g_drop_bad_request 0;/)
  assert.doesNotMatch(f.content, /7g_drop_bad_bot/)
  const bot = analyze('[1/Jan/2026:00:00:00 +0000] [":bad_bot_6:"] 1.2.3.4 a.com "GET /x HTTP/2.0" 403', groups)[0]
  assert.ok(bot.ok)
  const bf = buildException(bot.line, bot.matches, 'site', 'x')
  assert.doesNotMatch(bf.content, /http_user_agent/)
  assert.match(bf.content, /\$request_uri ~ "\^\/x\(\\\?\|\$\)"/)
})

// The ways an exception file was seen to pass nginx -t and still not work (Matchless Fleet, 2026-11-24), and one this
// tool had: a variable nginx -t refuses. test/unit/nginx.test.ts proves each in real nginx; these run without Docker.
const OAUTH = '[24/Nov/2026:19:52:04 +0000] [":bad_querystring_10::bad_request_15:"] 203.0.113.50 example.com "GET /?redirect_uri=http://localhost:8080/callback HTTP/2.0" 403 0.000 "-" "curl/8.7.1"'
const oauth = analyze(OAUTH, groups)[0]

/** Problems with a file's variables and blocks, as nginx would read them. Empty means none found. */
function fileProblems(content: string, hits: { group: string; number: number }[]): string[] {
  const problems: string[] = []
  // 1. In an expression, $7g_x is the regex capture $7 then the text "g_x": the right side of = and quoted strings.
  for (const m of content.matchAll(/^if \(\$\S+ != ?(\S+)\) \{$|^if \(\$\S+ = (\S+)\) \{$/gm)) {
    const rhs = m[1] ?? m[2]
    if (!/^\$(\{[A-Za-z_]|[A-Za-z_])/.test(rhs)) problems.push(`compares with ${rhs}, which nginx reads as a capture`)
  }
  for (const m of content.matchAll(/"((?:[^"\\]|\\.)*)"/g)) {
    if (/(?<!\\)\$[0-9]/.test(m[1]) && !/^\^|~/.test(m[1])) problems.push(`string "${m[1]}" holds a capture reference`)
  }
  // 4. A name over MAX_VARIABLE_NAME fails nginx -t.
  for (const m of content.matchAll(/^set \$(\S+) /gm)) {
    if (m[1].length > MAX_VARIABLE_NAME) problems.push(`$${m[1]} is ${m[1].length} characters: nginx -t fails`)
  }
  // 2. Every fired rule needs its own block, comparing its own map value and lifting its own flag.
  const flag = { bad_bot: 'bot', bad_referer: 'referer', bad_querystring: 'query_string', bad_request: 'request', not_allowed_method: 'method' } as Record<string, string>
  for (const h of hits) {
    const map = h.group === 'not_allowed_method' ? 'not_allowed_method_7g' : `${h.group}_7g`
    const re = new RegExp(`^if \\(\\$${map} = \\$\\S+\\) \\{\\n {4}set \\$7g_drop_bad_${flag[h.group]} 0;\\n\\}$`, 'm')
    if (!re.test(content)) problems.push(`no block lifts ${h.group} rule ${h.number}`)
    if (!new RegExp(`^ {4}set \\$\\S+ ${h.number};$`, 'm').test(content)) problems.push(`nothing sets ${h.number} for ${h.group}`)
  }
  return problems
}

test('faults 1, 2 and 4: letter-led short variables, one block per fired rule, on every sample', () => {
  assert.ok(oauth.ok)
  for (const r of [...ok, oauth]) {
    if (!r.ok) continue
    const file = buildException(r.line, r.matches, 'site', 'x')
    assert.deepEqual(fileProblems(file.content, r.line.hits), [], file.content)
    assert.equal((file.content.match(/^set \$\S+ "";$/gm) ?? []).length, r.line.hits.length, 'one block per fired rule')
  }
  // Controls: the checker finds each fault when it is put back.
  const good = buildException(oauth.line, oauth.matches, 'site', 'x').content
  assert.ok(fileProblems(good.replaceAll('$allow7g_', '$7g_allow_'), oauth.line.hits).some((p) => /capture/.test(p)))
  assert.ok(fileProblems(good.split('\n\nset ')[0], oauth.line.hits).some((p) => /bad_request rule 15/.test(p)))
  assert.ok(fileProblems(good.replaceAll('$allow7g_redirect_uri_', `$allow7g_${'x'.repeat(30)}_`), oauth.line.hits).some((p) => /nginx -t fails/.test(p)))
})

test('fault 3: a rule set off in the query pins that parameter and the path, never the path alone', () => {
  assert.ok(oauth.ok)
  const content = buildException(oauth.line, oauth.matches, 'site', 'x').content
  const conds = conditions(content)
  assert.equal(conds.length, 2)
  const passes = (uri: string, c = conds) => c.map((x) => x.variable === 'request_uri' && x.regex.test(uri))
  assert.deepEqual(passes('/?redirect_uri=http://localhost:8080/callback'), [true, true])
  assert.deepEqual(passes('/?state=abc&redirect_uri=http://localhost:8080/callback&scope=x'), [true, true])
  for (const near of [
    '/?redirect_uri=http://localhost:9999/other',
    '/?redirect_uri=http://localhost:8080/callbackX',
    '/?xredirect_uri=http://localhost:8080/callback',
    '/sample-page/?redirect_uri=http://localhost:8080/callback',
    '/?q=localhost',
    '/',
  ]) {
    assert.deepEqual(passes(near), [false, false], near)
  }
  // Control: the path-only pattern this tool wrote before lets the near misses through.
  const old = conditions(content.replace(/~ "\^\/\\\?\(\.\*&\)\?redirect_uri=[^"]*"/g, '~ "^/(\\?|$)"'))
  assert.deepEqual(passes('/?redirect_uri=http://localhost:9999/other', old), [true, true])

  // Every sample whose rule fired in the query: the logged parameter, changed by one character, no longer matches.
  for (const r of ok) {
    if (!r.ok || !r.line.queryString) continue
    for (const c of conditions(buildException(r.line, r.matches, 'site', 'x').content)) {
      if (c.variable !== 'request_uri') continue
      assert.ok(c.regex.test(r.line.uri), `${c.regex} vs ${r.line.uri}`)
      assert.ok(!c.regex.test(`${r.line.path}?zz=1`), `${c.regex}: the path alone`)
    }
  }
  const rm = ok.find((r) => r.ok && r.line.path === '/wp-json/rankmath/v1/getHead')!
  assert.ok(rm.ok)
  const [c] = conditions(buildException(rm.line, rm.matches, 'site', 'x').content)
  assert.ok(c.regex.test('/wp-json/rankmath/v1/getHead?url=https://example.org'))
  assert.ok(!c.regex.test('/wp-json/rankmath/v1/getHead?url=https://evil.example'))
  assert.ok(!c.regex.test('/wp-json/rankmath/v1/getHead?url=https://example.org.evil.example'))
})

test('paramsAround takes whole parameters', () => {
  const q = 'a=1&redirect_uri=http://localhost:8080/cb&b=2'
  const at = q.indexOf('localhost')
  assert.equal(paramsAround(q, at, at + 9), 'redirect_uri=http://localhost:8080/cb')
  assert.equal(paramsAround(q, 0, 1), 'a=1')
  assert.equal(paramsAround(q, q.length - 1, q.length), 'b=2')
  assert.equal(paramsAround(q, 2, 6), 'a=1&redirect_uri=http://localhost:8080/cb')
})
