# Installation

Killer requires a stable Rust toolchain (1.74 or newer).

## From crates.io

```sh
cargo install killer
```

This installs the `killer` binary into `~/.cargo/bin` (make sure that's on your
`PATH`).

## From source

```sh
git clone https://github.com/martin-k-m/killer
cd killer
cargo install --path .
```

## Verify

```sh
killer version
```

You should see the version, the active scan rules, the known issue ids, and the
built-in test suites.

## Windows (GNU toolchain) note

The default `x86_64-pc-windows-gnu` toolchain needs `dlltool` and an assembler
(`as`) on `PATH` to build crates that use `windows-sys`. If you hit a `dlltool`
/ `CreateProcess` error:

- add a MinGW-w64 `bin` directory (from [WinLibs](https://winlibs.com/) or
  MSYS2) to your `PATH`, **or**
- switch to the `x86_64-pc-windows-msvc` toolchain with the Visual Studio Build
  Tools installed.

Next: [Quickstart](quickstart.md).
