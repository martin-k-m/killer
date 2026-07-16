# Writing tests

A practical guide to authoring `.klr` attacks.

## Think in terms of secure behavior

A `.klr` attack states how a **secure** system responds. Killer sends the
request, then checks your `expect` block. All expectations hold → the test
passes (the system defended itself). Any fails → a vulnerability is reported.

## A minimal attack

```klr
attack login_rejects_injection {
    request POST "/api/login"
    send { username = "' OR 1=1 --" }
    expect {
        status != 200
        response does_not_contain "token"
    }
    severity critical
}
```

Run it:

```sh
killer test login.klr --url http://localhost:3000
```

## Group related tests into a suite

```klr
suite "Authentication" {
    test protected_requires_auth {
        endpoint "/account"
        check authentication
    }

    attack brute_force {
        request POST "/login"
        repeat 60 times
        expect blocked_after 20
        severity high
    }
}
```

## Fuzz an input

`fuzz` (or `mutate`) turns one attack into many variants that run in parallel —
great for surfacing edge cases:

```klr
attack item_lookup {
    request POST "/api/item"
    send { id = "1" }
    fuzz id           # sql_injection, xss, huge_values, negative_numbers, empty
    check injection   # no database error may leak
    severity high
}
```

```sh
killer test item.klr --url http://localhost:3000 --parallel
```

## Path traversal and sessions

```klr
attack upload {
    endpoint "/upload"
    payload: "../../etc/passwd"
    expect { file_not_exposed true }
    severity high
}

attack session {
    target "/account"
    login user "test"
    steal cookie
    attempt reuse
    expect { session_invalidated true }
    severity high
}
```

## Static rules over your source

Rules don't need a server — point `--project` at your code:

```sh
killer test rules.klr --project .
```

## Tips

- Give every attack a `severity` and a `message`; both show up in reports.
- Prefer `check <name>` for common intent (auth, injection, rate limiting).
- Use `--format json` in CI and `killer report --html` for a shareable report.
- Each attack is tagged with an issue id — run `killer explain <id>` to learn
  more about a failure.
