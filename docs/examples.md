# Examples

Runnable `.klr` files live in [`examples/`](../examples/) and the built-in
suites in [`suites/`](../suites/). This page annotates a few.

## Authentication (SQL injection + rate limit)

[`examples/auth_security.klr`](../examples/auth_security.klr)

```klr
project "MyApplication"

attack authentication {
    target "/api/login"
    send {
        username = "' OR 1=1"
        password = "anything"
    }
    expect {
        status != 200                       # login must be rejected
        response does_not_contain "token"   # and no session token leaked
    }
    severity critical
    message: "SQL injection vulnerability detected"
}
```

```sh
killer test examples/auth_security.klr --url http://localhost:8080
```

## Fuzzing an API input

```klr
suite "API" {
    attack input_injection {
        request POST "/api/item"
        send { id = "1" }
        fuzz id          # expands into many variants, run in parallel
        check injection  # no SQL error may leak
        severity high
    }
}
```

```sh
killer test api.klr --url http://localhost:8080 --parallel
```

## A static code rule

[`examples/database_rules.klr`](../examples/database_rules.klr)

```klr
rule "unsafe database query"
when function contains "query"
and input reaches query
without sanitization
severity high
report: "User input reaches database directly"
```

```sh
killer test examples/database_rules.klr --project .
```

## Built-in suites (no file needed)

```sh
killer test --suite web            --url http://localhost:8080
killer test --suite api            --url http://localhost:8080 --parallel
killer test --suite authentication --url http://localhost:8080
```

## CI gate

```sh
killer ci --base origin/main   # scan + rules + review; non-zero exit on findings
killer github enable           # generate .github/workflows/killer.yml
```
