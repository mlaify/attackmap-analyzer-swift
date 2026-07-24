# Changelog

All notable changes to `attackmap-analyzer-swift` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-23

### Added

- Initial scaffold (AttackMap #186). `SwiftAnalyzer` implementing the
  `attackmap.analyzers` entry-point contract:
  - **SwiftPM detection** — `Package.swift`, `.xcodeproj` / `.xcworkspace`,
    `.swift` sources; emits a `SwiftPM` framework hint.
  - **`Package.resolved` dependency SBOM** — parses formats v1/v2/v3 (incl. the
    Xcode `xcshareddata/swiftpm/` copy), marking direct vs. transitive against
    `Package.swift`. Emitted as `ecosystem="swiftpm"` (requires attackmap ≥ 0.4.29);
    inventoried, not CVE-matched (OSV has no SwiftPM ecosystem).
  - **Framework hints** for Vapor / Hummingbird / Kitura / Perfect.
  - **Entrypoints** — `main.swift`, `@main`.

Server-side route extraction (#187) and the iOS/macOS app attack surface (#188)
are tracked under the Swift analyzer epic (#204).
