# attackmap-analyzer-swift

> [!NOTE]
> **Development is paused.** This project is not under active development.
> The code remains available for reference, and security reports are still
> welcome at [security@mlaify.io](mailto:security@mlaify.io).

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

Then AttackMap picks it up automatically:

```bash
attackmap analyze /path/to/swift/project
```

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
