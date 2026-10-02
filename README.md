# attackmap-analyzer-swift

> [!IMPORTANT]
> **Active development, slow pace.** AttackMap is under active development, but
> progress may be slow until more contributors or co-maintainers join. Help is
> very welcome with the core engine, an analyzer, the macOS app, or the docs —
> see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on
> [mlaify/AttackMap](https://github.com/mlaify/AttackMap/issues) to say hello.
> Security reports are still welcome at [security@mlaify.io](mailto:security@mlaify.io).

Swift ecosystem analyzer plugin for [AttackMap](https://github.com/mlaify/AttackMap).
Auto-discovered via the `attackmap.analyzers` entry point once installed.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Status: early scaffold (v0.1.0).** SwiftPM project detection + a
> `Package.resolved` dependency SBOM. Server-side route extraction and the
> iOS/macOS app attack surface are on the roadmap (below).

## Install

```bash
pip install git+https://github.com/mlaify/attackmap-analyzer-swift.git    # alongside attackmap
```

The analyzer is **experimental and opt-in** (`enabled_by_default=False`): installing
it does not make it run on every scan. Select it explicitly:

```bash
attackmap analyze /path/to/swift/project -m swift
```

Files are walked with `attackmap.sdk.iter_repo_files`: `.build/`, `DerivedData/`,
`Pods/`, `Carthage/` and AttackMap's shared skip list (`build/`, `.git/`,
`node_modules/`, ...) are pruned by their name *inside* the repo, and symlinks out
of the repo are not followed.

## What it does today

- **SwiftPM detection** — recognizes `Package.swift`, `.xcodeproj` / `.xcworkspace`,
  and `.swift` sources; emits a `SwiftPM` framework hint.
- **Dependency SBOM** — parses `Package.resolved` (formats **v1**, **v2**, and **v3**,
  including the copy Xcode stashes under `*.xcworkspace/xcshareddata/swiftpm/`) into
  the scan's dependency inventory, marking direct vs. transitive by cross-referencing
  the `Package.swift` manifest. Swift packages are inventoried but not CVE-matched —
  OSV.dev has no SwiftPM ecosystem yet.
- **Framework hints** — flags server-side frameworks (Vapor, Hummingbird, Kitura,
  Perfect) when declared in the manifest.
- **Entrypoints** — `main.swift` and `@main`.

## Roadmap

- **Server-side routes** ([AttackMap#187](https://github.com/mlaify/AttackMap/issues/187)) — Vapor / Hummingbird route + auth-middleware extraction.
- **iOS/macOS app attack surface** ([AttackMap#188](https://github.com/mlaify/AttackMap/issues/188)) — URL schemes, universal links, `WKWebView` JS eval, Keychain / `UserDefaults` secrets, App Transport Security exceptions, pasteboard, XPC.

Part of the [Swift analyzer epic](https://github.com/mlaify/AttackMap/issues/204).

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

[MIT](LICENSE). Copyright (c) 2026 Matthew Davis and AttackMap Contributors.
