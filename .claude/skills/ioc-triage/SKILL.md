---
name: ioc-triage
description: Triage a pasted list of IP addresses or IOCs with the ioc-portal lookup_ip tool: one row per value, counts per verdict, refused values listed. Use when asked to triage, check or enrich IPs.
---

# IOC triage: a pasted list in, one verdict per value out

Follow these steps exactly, every time, so every analyst gets the same shape of answer.

## The only tool

Use only the `lookup_ip` tool of the `ioc-portal` MCP server. In Claude Code it is named
`mcp__ioc-portal__lookup_ip`. It takes one argument, `ip`.

- Use no other tool or source: no web search, no other MCP server, no files.
- Do not use your own knowledge for a verdict, a score or evidence. Every cell comes from the
  tool's answer.
- If `lookup_ip` is not available, do not triage. Say: "The ioc-portal lookup_ip tool is not
  available here, so no values were looked up." and stop.

## Steps

1. **Split the list.** Split the user's text on new lines, commas, semicolons and spaces. Trim
   each value. Ignore empty pieces.
2. **Drop repeats.** If the exact same text appears more than once, keep only the first one.
   Keep the user's order.
3. **Never change a value.** Look up each value exactly as the user wrote it. Do not re-fang
   (`8.8.8[.]8` stays as written), fix typos, strip ports or paths, resolve domains, or add any
   "related" value. Only the values the user gave are looked up.
4. **Look up each value once**, in order: call `lookup_ip` with `ip` set to the value. Call it
   for every value, including ones that do not look like IPv4: the tool decides what it refuses.
5. **Never retry.** If the tool refuses a value or fails, do not call it again for that value,
   in the same or any other form.
6. **Write the output** in the format below, and nothing else: no extra commentary.

## What each tool answer becomes

| Tool answer | Verdict cell | Score | Key evidence | Source problems |
|---|---|---|---|---|
| A normal result | `verdict.level` as returned | `verdict.score` as returned (always a number from 0 to 100) | `verdict.reasons` joined with `; `, or `none` if empty | see below |
| A normal result with level `not_applicable` | `not_applicable` | `-` (the score is 0 but means "not judged", so do not show it) | `<category> address` (e.g. `private address`) | `all skipped (not sent out)` |
| Tool error "That is not a valid IPv4 address..." or "IPv6 is not supported..." or any other portal message about the input | `refused` | `-` | `-` | `-` |
| Tool error "Could not reach the portal at ..." | `not_checked` | `-` | `-` | `portal unreachable` |
| Tool error "No data source could be reached by the portal..." | `not_checked` | `-` | `no sources reachable` |
| Any other tool error (internal error, unexpected answer) | `not_checked` | `-` | `-` | the tool's error message |

**Source problems** for a normal result: list every source whose `status` is not `ok`, joined
with `; `:

- `no_data`: `<name>: no_data`
- `not_configured`: `<name>: not_configured`
- `error`: `<name>: error (<the source's error text>)`

If all three sources are `ok`, write `none`. A failing source is not a failed lookup: the row
keeps the verdict the tool returned.

**Portal unreachable:** as soon as one call gives "Could not reach the portal at ...", stop
calling the tool. That value and every later value get `not_checked` and `portal unreachable`.

## Output format (always these four sections, in this order)

```
## Results

| # | Value | Verdict | Score | Key evidence | Source problems |
|---|---|---|---|---|---|
| 1 | <value as given> | <verdict> | <score> | <key evidence> | <source problems> |

## Counts

| Verdict | Count |
|---|---|
| malicious | <n> |
| suspicious | <n> |
| no_known_bad | <n> |
| not_applicable | <n> |
| refused | <n> |
| not_checked | <n> |
| **Total** | <number of unique values> |

no_data means a source knows nothing about the value, which is not proof it is safe. no_known_bad does not mean safe.

## Refused values

- <value>: <the tool's error message, word for word, without any prefix the app adds such as "Error executing tool lookup_ip:">

## Lookups

lookup_ip called <N> times. No other tools or sources used.
```

Rules for the format:

- Show all six verdict rows in Counts, even when the count is 0. The counts add up to Total.
- If nothing was refused, write `None.` under Refused values.
- If the portal was unreachable, add this line directly under the Results table:
  `Portal unreachable: start the backend (cd backend, then flask --app api run --port 5001) and run the triage again.`
- If any duplicates were dropped, add this line directly under the Results table:
  `Duplicates dropped: <value> (given <n> times)`, one entry per repeated value, joined with `; `.
- `<N>` is the real number of `lookup_ip` calls you made.
