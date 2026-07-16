# Installation

Killer requires a stable Rust toolchain (1.74 or newer).

## From source (supported today)

```sh
git clone https://github.com/martin-k-m/killer
cd killer
cargo install --path .
```

This builds an optimized binary and installs `killer` into `~/.cargo/bin`
(make sure that's on your `PATH`).

## From crates.io (coming soon)

Once a release is published, this will work:

```sh
cargo install killer
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
