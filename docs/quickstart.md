# Quickstart

This gets you from install to a real security test in a few minutes.

## 1. Scan a project

```sh
killer scan .
```

Killer walks the directory, detects languages, and prints a report with a 0–100
score. It also records a snapshot under `.killer/` so you can track the score
over time:

```sh
killer history .
```

## 2. Write your first `.klr` test

Create `login.klr`:

```klr
project "MyApp"

attack sql_login_bypass {
    request POST "/api/login"
    send {
        username = "' OR 1=1 --"
        password = "anything"
    }
    expect {
        status != 200
        response does_not_contain "token"
    }
    severity critical
    message: "SQL injection authentication bypass"
}
```

A `.klr` attack describes how a **secure** system should behave. If every
expectation holds, the test passes; if one fails, a vulnerability is reported.

## 3. Run it against a target

```sh
killer test login.klr --url http://localhost:3000
```

You'll get a Jest-like report grouping tests, with pass/fail and an `explain`
hint for any failure:

```text
Tests
  ✗ sql_login_bypass
      ✗ status != 200  observed status 200
      → killer explain KLR-SQLI
```

## 4. Try a built-in suite

No file needed — Killer ships suites you can run immediately:

```sh
killer test --suite authentication --url http://localhost:3000 --parallel
```

## 5. Learn about a finding

```sh
killer explain KLR-SQLI
```

## 6. Gate your CI

```sh
killer github enable      # writes .github/workflows/killer.yml
```

Next: the [CLI reference](cli.md) and the [`.klr` guide](klr-guide.md).
