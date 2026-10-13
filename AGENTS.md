# AGENTS.md

## Project
This repository contains an AttackMap analyzer.

AttackMap analyzers live under:
- `github.com/mlaify`

This repo should implement one analyzer cleanly against the AttackMap core contract.

## Analyzer responsibilities
This analyzer should:
- detect whether it applies to a target repository
- emit structured signals
- remain heuristic but explainable

It must not render reports, own scoring policy, or bypass core's merge/modeling pipeline. Findings, severities and CWE/OWASP mapping for `AppSurfaceIssue`s are core's job (`apple-*` rules).

## Scope
Swift / Apple ecosystem coverage. Two analyzers ship here (`SwiftAnalyzer`, `ObjCAnalyzer`), both **experimental and opt-in** (`enabled_by_default=False`, run with `-m swift`):

- **Server-side routes**: Vapor 4 and Hummingbird 1.x/2.x registrations, prefixes from `grouped`/`group` and from where a `RouteCollection` or controller is mounted, with route-level `auth` / `guards` / `guard_evidence` (AttackMap#256).
- **iOS/macOS app attack surface** (AttackMap#188): `Info.plist` (ATS exceptions, custom URL schemes; read with `plistlib`, never executed), `*.entitlements`, secret-named `*.xcconfig` settings, and Swift code shapes (`evaluateJavaScript` interpolation, secrets in `UserDefaults`/`UIPasteboard`, unchecked `NSXPCListener` peers, dynamic `NSClassFromString`/`dlopen`), reported as `AppSurfaceIssue`s and entry points.
- **Dependency SBOM**: SwiftPM `Package.resolved` (v1–v3), CocoaPods and Carthage lockfiles.
- Files are walked with `attackmap.sdk.iter_repo_files`; `.build/`, `DerivedData/`, `Pods/`, `Carthage/` and core's shared skip list are pruned, and test targets (`Tests/`, `*Tests/`) are skipped.

## Out of scope (for now)
- Type-level resolution: route paths the code computes are kept as `$(Expr)`, and an unknown mount as `$(TypeName)`.
- Mounts that disagree across a Swift package keep their own paths.
- Building, signing or running anything from the scanned repo. Plists and entitlements are parsed as data only.

## Signal v2 alignment
All emissions populate the optional `line`, `evidence_text`, and (where applicable) `confidence` fields on the AttackMap hint models, so insights can cite `path/to/File.swift:NN`.

Confidence policy:
- Structural matches (a route registration, a parsed plist/entitlements key, a resolved package pin) → 0.9–0.95
- Pattern matches on code shapes (`evaluateJavaScript` interpolation, `UserDefaults` secrets) → 0.8
- Severity of app-surface issues is the plugin's best guess per instance (high / medium / low); core keeps the max per rule.

## Testing
Tests write realistic Swift, plist, entitlements and xcconfig snippets to `tmp_path` and assert on the resulting `ScanResult`, never on a single regex in isolation. Test inputs of CODEOWNERS types (`*.entitlements`, `*.xcconfig`, `ExportOptions*.plist`) are written into `tmp_path` inside the test, not committed. New extractors must include both a positive test (signal fires on representative code) and a negative test (signal does **not** fire on look-alikes).
