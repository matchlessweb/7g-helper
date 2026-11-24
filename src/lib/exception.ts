// The exception file, in the strict form: it lets one request shape through only when the rule that fired is the
// one in the log. That rule stays on for every other request, and the other 7G groups still check this one. Within
// the rule's own group, a matching request skips the group's other rules (nginx stops at the first match), which is
// why the pattern pins the request as narrowly as it can.
// GridPane includes these files after the maps set the drop flags and before it drops the request, and keeps them
// through its updates: per site /var/www/<site>/nginx/*-7g-context.conf, server-wide /etc/nginx/extra.d/*7g-context.conf.

import type { LogLine } from './logline.ts'
import type { RuleMatch } from './match.ts'
import { knownBot } from './verdict.ts'

export type Scope = 'site' | 'server'

export interface ExceptionFile {
  fileName: string
  path: string
  content: string
  reload: string
  /** Should come back with anything but 403 once the file is in place. */
  testAllowed: string
  /** Should still come back 403: proof the rest of 7G is on. */
  testStillBlocked: string
}

const RELOAD = 'nginx -t && gp ngx reload'

/** The GridPane site folder: the logged host without a leading www. */
export function siteFolder(host: string): string {
  return host.toLowerCase().replace(/^www\./, '')
}

function slugify(s: string, max = 40): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, max).replace(/-+$/, '') || 'request'
}

// A literal string as an nginx regex inside double quotes. nginx unescapes \\ and \" in a quoted string before the
// regex sees it, so a literal backslash needs four, and a quote needs one; \. and the like pass through untouched.
export function nginxRegex(literal: string): string {
  return literal
    .replace(/\\/g, '\\\\\\\\')
    .replace(/[.*+?^${}()|[\]]/g, '\\$&')
    .replace(/"/g, '\\"')
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`
}

/** The crawler's own name from a user agent, e.g. GPTBot or facebookexternalhit. */
export function botToken(userAgent: string): string {
  const named = userAgent.match(/\b([a-z][\w.-]*?(?:bot|crawler|spider|externalhit|fetcher|agent))\b/i)
  if (named && !/^mozilla$/i.test(named[1])) return named[1]
  const product = userAgent.match(/\b([a-z][\w.-]{2,})\//gi)?.map((p) => p.slice(0, -1)).find((p) => !/^(mozilla|applewebkit|chrome|safari|gecko|version|mobile)$/i.test(p))
  return product ?? userAgent.slice(0, 40)
}

interface Condition {
  /** The nginx test, e.g. $http_user_agent ~* "GPTBot". */
  test: string
  /** Plain words for the file's header. */
  says: string
  slug: string
}

/** The whole query-string parameters ("name=value", split on &) that hold query[start, end), as one literal. */
export function paramsAround(query: string, start: number, end: number): string {
  const from = start > 0 ? query.lastIndexOf('&', start - 1) + 1 : 0
  const amp = query.indexOf('&', Math.max(end, start + 1))
  return query.slice(from, amp === -1 ? query.length : amp)
}

function pathSlug(path: string): string {
  return slugify(path.split('/').filter(Boolean).slice(-3).join('-'), 32)
}

// Query-string and request rules. Both are tested against $request_uri, the address exactly as sent with its query:
// its query part is byte for byte what the query-string map reads ($query_string), and the path can be pinned in the
// same test. A rule's number alone is not enough scope: nginx's map stops at its first match, so lifting rule N for
// a whole address would also skip every later rule in that group for any query sent there. So the pattern pins the
// parameter that set the rule off, whole, and the path; never the path alone when the match was in the query.
function addressCondition(m: RuleMatch, line: LogLine): Condition {
  const path = line.path || '/'
  const uri = line.uri || path
  const exact = (): Condition => ({
    test: `$request_uri ~ "^${nginxRegex(uri)}$"`,
    says: `exactly ${uri}`,
    slug: path === '/' ? slugify(line.queryString.split('=')[0], 24) : pathSlug(path),
  })
  if (!m.matched) return exact()
  // Where the match sits, as offsets into the query string (negative: inside the path; -1 is the "?").
  const queryAt = m.hit.group === 'bad_querystring' ? 0 : path.length + 1
  const start = m.matched.index - queryAt
  const end = start + m.matched.text.length
  if (m.hit.group === 'bad_request' && end <= -1) {
    // The path itself set the rule off: that one path, with or without a query (the query-string rules still check it).
    return { test: `$request_uri ~ "^${nginxRegex(path)}(\\?|$)"`, says: `requests to ${path}`, slug: pathSlug(path) }
  }
  if (start < 0 || !uri.includes('?')) return exact()
  const param = paramsAround(line.queryString, start, end)
  return {
    test: `$request_uri ~ "^${nginxRegex(path)}\\?(.*&)?${nginxRegex(param)}(&|$)"`,
    says: `requests to ${path} carrying ${param}`,
    slug: path === '/' ? slugify(param.split('=')[0], 24) : pathSlug(path),
  }
}

function condition(m: RuleMatch, line: LogLine): Condition {
  // Without the user agent or referrer in the line, the only safe scope left is the address.
  const group = (m.hit.group === 'bad_bot' && !line.userAgent) || (m.hit.group === 'bad_referer' && !line.referer) ? 'path' : m.hit.group
  if (group === 'bad_querystring' || group === 'bad_request') return addressCondition(m, line)
  switch (group) {
    case 'bad_bot': {
      const text = m.matched?.text
      const token = text && /^[\w .-]{3,40}$/.test(text) ? text : botToken(line.userAgent)
      return {
        test: `$http_user_agent ~* "${nginxRegex(token)}"`,
        says: `a user agent containing "${token}"`,
        slug: slugify(knownBot(line.userAgent)?.name ?? token, 24),
      }
    }
    case 'bad_referer': {
      const host = line.referer.match(/^https?:\/\/([^/?#]+)/i)?.[1] ?? line.referer
      return {
        test: `$http_referer ~* "^https?://${nginxRegex(host)}(/|$)"`,
        says: `links from ${host}`,
        slug: slugify(host, 24),
      }
    }
    default: {
      const path = line.path || '/'
      return {
        test: `$request_uri ~ "^${nginxRegex(path)}(\\?|$)"`,
        says: `requests to ${path}`,
        slug: slugify(path.split('/').filter(Boolean).slice(-3).join('-'), 32),
      }
    }
  }
}

const GROUP_SHORT: Record<RuleMatch['hit']['group'], string> = {
  bad_bot: 'bot',
  bad_referer: 'referer',
  bad_querystring: 'query',
  bad_request: 'request',
  not_allowed_method: 'method',
}

/**
 * nginx -t fails ("could not build variables_hash") on a variable name longer than this, at nginx's default
 * variables_hash_bucket_size of 64, which GridPane keeps. Measured on nginx 1.30: 46 characters pass, 47 fail.
 */
export const MAX_VARIABLE_NAME = 46

/**
 * The exception's own variable. It starts with a letter: in an nginx expression, $7g_x is read as the regex capture
 * $7 followed by the text "g_x", so a comparison with it never matches.
 */
export function exceptionVariable(slug: string, group: RuleMatch['hit']['group'], number: number): string {
  const tail = `_${GROUP_SHORT[group]}_${number}`
  const room = MAX_VARIABLE_NAME - 'allow7g_'.length - tail.length
  const name = `allow7g_${slug.replace(/-/g, '_').slice(0, Math.min(20, Math.max(0, room))).replace(/_+$/, '')}${tail}`.replace('allow7g__', 'allow7g_')
  if (name.length > MAX_VARIABLE_NAME) throw new Error(`variable name too long for nginx: ${name}`)
  return `$${name}`
}

export function buildException(line: LogLine, matches: RuleMatch[], scope: Scope, today: string): ExceptionFile {
  const conds = matches.map((m) => ({ m, c: condition(m, line) }))
  const slug = [...new Set(conds.map(({ c }) => c.slug))].join('-').slice(0, 48).replace(/-+$/, '')
  const fileName = `allow-${slug}-7g-context.conf`
  const site = siteFolder(line.host)
  const path = scope === 'site' ? `/var/www/${site}/nginx/${fileName}` : `/etc/nginx/extra.d/${fileName}`

  const header = [
    `# 7G exception, written by 7G Helper on ${today} from this 7G log line:`,
    `#   ${line.raw}`,
    '#',
    ...conds.map(
      ({ m, c }) => `# Lets through ${c.says}, only when ${m.hit.group} rule ${m.hit.number} is what blocked it.`,
    ),
    `# ${conds.length > 1 ? 'These rules stay' : 'This rule stays'} on for everything else, and the other 7G rule groups still check these requests.`,
    '# nginx stops reading a rule group at its first match, so for a request let through here, the rules after the named',
    '# one in that group are skipped too. That is why the pattern is pinned as tightly as the logged request allows.',
    '# If part of a pinned value changes from one request to the next (a port, a page address, a token), this file will',
    '# not match the next request. Widen only that part by hand, for example with [^&]*, and test both ways again.',
    scope === 'site'
      ? `# Applies to ${site} only.`
      : '# Applies to every 7G-enabled site on this server.',
    '# 7G Helper is independent of GridPane and of 7G. Review this file before you use it.',
    '#',
    `# Save as: ${path}`,
    `# Then run: ${RELOAD}`,
  ]

  const blocks = conds.map(({ m, c }) => {
    const variable = exceptionVariable(c.slug, m.hit.group, m.hit.number)
    return [
      `set ${variable} "";`,
      `if (${c.test}) {`,
      `    set ${variable} ${m.hit.number};`,
      '}',
      `if ($${m.group.variable} = ${variable}) {`,
      `    set $${m.group.dropFlag} 0;`,
      '}',
    ].join('\n')
  })

  const url = `https://${line.host}${line.uri || '/'}`
  const method = line.method && line.method !== 'GET' ? ` -X ${line.method}` : ''
  const isBot = matches.some((m) => m.hit.group === 'bad_bot') && line.userAgent !== ''
  const ua = isBot ? ` -A ${shellQuote(line.userAgent)}` : ''
  const code = `curl -s -o /dev/null -w '%{http_code}\\n'`
  const control = isBot
    ? `${code} -A ${/blexbot/i.test(line.userAgent) ? "'MJ12bot'" : "'BLEXBot'"} ${shellQuote(`https://${line.host}/`)}`
    : `${code} ${shellQuote(`https://${line.host}/.env`)}`

  return {
    fileName,
    path,
    content: `${header.join('\n')}\n\n${blocks.join('\n\n')}\n`,
    reload: RELOAD,
    testAllowed: `${code}${method}${ua} ${shellQuote(url)}`,
    testStillBlocked: control,
  }
}
