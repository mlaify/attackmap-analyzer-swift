# Changelog

All notable changes to `attackmap-analyzer-swift` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Walk and read the repo with the shared `attackmap.sdk` helpers (`iter_repo_files`, `read_source`, `rel`, `line_of`) instead of local `rglob` + `SKIP_DIRS` walks; `analyze()` now walks the repo once instead of three times (mlaify/AttackMap#253).
- The analyzer is now opt-in while experimental (`enabled_by_default=False`): run it with `attackmap analyze <repo> -m swift` (mlaify/AttackMap#221).

### Fixed

- A repo checked out under a directory named like a skip dir (e.g. `/build/...`) was silently not analyzed, because skip dirs were matched against absolute path parts.
- Symlinked files pointing outside the repo (e.g. a `Package.resolved` or `.swift` source) are no longer followed and analyzed.
- Non-UTF-8 sources are decoded as cp1252/latin-1 instead of with U+FFFD replacement characters.

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
