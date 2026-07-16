# The `.klr` language

`.klr` (Killer Rule Language) describes **attacks** (dynamic tests) and **rules**
(static code checks). Files are line-oriented; comments start with `#` or `//`.

## Structure

```klr
project "MyApp"          # optional display name

suite "Authentication" { # optional grouping
    attack login { ... }
    test other { ... }
}

attack standalone { ... } # attacks can also live at the top level

rule "unsafe query" ... }  # static code rules
```

`attack` and `test` are interchangeable (`test` reads nicely for check-style
tests). A `suite` groups them and appears as a heading in the report.

## Attack statements

| Statement | Example | Meaning |
| --------- | ------- | ------- |
| `target` / `endpoint` / `url` | `target "/api/login"` | Path (resolved against `--url`) or absolute `http://…`. |
| `method` | `method POST` | HTTP method. |
| `request` | `request POST "/x"` | Method + target in one line. |
| `send { k = v }` | | JSON request body. |
| `header { k = v }` | | Extra request headers. |
| `payload "…"` | | Raw request body (e.g. a traversal string). |
| `repeat N times` | `repeat 100 times` | Send the request up to N times. |
| `check <name>` | `check authentication` | Expand to built-in expectations. |
| `mutate <field> { … }` | | Fuzz a field with named generators. |
| `fuzz <field>` | `fuzz amount` | Shorthand for a broad `mutate` set. |
| `expect { … }` | | One or more conditions. |
| `severity` | `severity critical` | `critical` / `high` / `medium` / `low`. |
| `message: "…"` | | Shown when the attack fails. |

A block form of `repeat` acts as a loop:

```klr
repeat 100 {
    attack login { target "/login" }
}
```

## Expectations

Inside `expect { … }` (or a single `expect: <cond>`):

- `status <op> <n>` — operators `==`, `!=`, `<`, `>`, `<=`, `>=`
- `response contains "…"` / `response does_not_contain "…"`
- `blocked_after <n>` — a rate-limit / brute-force check
- named booleans — `file_not_exposed true`, `session_invalidated true`,
  `requires_auth true`, `no_sql_error true`

## Checks

`check <name>` expands to expectations:

- `check authentication` → the endpoint must reject unauthenticated access
- `check injection` → no database error may leak
- `check rate_limit` → the endpoint must block abusive clients

## Fuzzing

`mutate <field> { generators }` expands one attack into many variants — one per
generated value — which run in parallel. `fuzz <field>` is a shorthand that
applies a broad default set (`sql_injection`, `xss`, `huge_values`,
`negative_numbers`, `empty`).

Generators: `negative_numbers`, `huge_values`, `decimals`, `zero`, `empty`,
`sql_injection`, `xss`, `null_bytes`, `long_strings`, `unicode`. An unknown
generator injects its own name as the value.

```klr
attack duplicate_payment {
    request POST "/payment"
    send { amount = 100 }
    mutate amount {
        negative_numbers
        huge_values
        decimals
    }
    expect { status != 200 }
}
```

## Static rules

A `rule` runs against your **source code** (via `killer test --project`), not a
live server:

```klr
rule "unsafe database query"
when function contains "query"
and input reaches query
without sanitization
severity high
report: "User input reaches database directly"
```

The static rule engine uses line-level heuristics (does the line hit the sink,
read input or build a dynamic string, and skip sanitization?). It is a pragmatic
first pass — deeper dataflow analysis is on the roadmap.

## Errors

Parse errors carry a stable code and structured fields, for example:

```text
KLR001
expected end of line, found `{`
  File:  security/login.klr
  Line:  14
  Expected:  end of line
  Found:  `{`
```

See [writing-tests.md](writing-tests.md) for a practical walkthrough.
