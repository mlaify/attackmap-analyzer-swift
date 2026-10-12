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

> **Status: experimental.** Vapor / Hummingbird routes with route-level auth, the
> iOS/macOS app attack surface, and a SwiftPM + CocoaPods + Carthage dependency SBOM.
> Requires an AttackMap core with the app-surface contract (mlaify/AttackMap#347).

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
- **Server-side routes** ([AttackMap#187](https://github.com/mlaify/AttackMap/issues/187)) —
  Vapor 4 and Hummingbird 1.x/2.x route registrations (`app.get("users", ":id")`,
  `on(.POST, ...)`, `webSocket`/`ws`, `router.get("/x")`, chained
  `group.get(use:).post(use:)`), with prefixes from `grouped(...)` / `group(...)`
  (closures, bindings and chains), and from where a `RouteCollection` or controller
  is mounted (`register(collection:)`, `addRoutes(to:)`, `addRoutes(_:atPath:)`) when
  every mount in the same Swift package agrees. Each route carries `auth`, `guards`
  and `guard_evidence` (AttackMap#256): `required` when Vapor's
  `X.guardMiddleware()` / `X.redirectMiddleware(...)`, Hummingbird's
  `IsAuthenticatedMiddleware` or an `*Authorization*Middleware` applies, or the
  handler calls `req.auth.require(...)` / `context.requireIdentity()` or guards on
  the caller's identity with a 401. An authenticator alone (`UserAuthenticator()`,
  `SessionAuthenticator`) leaves the route `unknown`, since it only identifies callers
  who send credentials. Role checks in the handler (`guard user.roles.contains(.admin)`)
  are reported as guards. Paths the code computes (`SiteURL.faq.pathComponents`) are
  kept as `$(SiteURL.faq)`, and an unknown mount as `$(TypeName)`. Test targets
  (`Tests/`, `*Tests/`) are skipped.
- **iOS/macOS app attack surface** ([AttackMap#188](https://github.com/mlaify/AttackMap/issues/188)) —
  reported as `AppSurfaceIssue`s, which core turns into `apple-*` findings with CWE/OWASP ids.
  - `Info.plist` (XML or binary, read with `plistlib`, never executed): App Transport
    Security exceptions, i.e. `NSAllowsArbitraryLoads` (medium; low when a scoped key makes
    iOS 10+ ignore it), `...InWebContent` / `...ForMedia`, and per-domain
    `NSExceptionAllowsInsecureHTTPLoads` or a TLS minimum below 1.2 (low). Each custom
    `CFBundleURLSchemes` scheme is an entry point and an `apple-custom-url-scheme` finding
    (low); the handlers (`application(_:open:options:)`,
    `scene(_:openURLContexts:)`, `.onOpenURL`) are reported as entry points.
  - `*.entitlements`: `cs.disable-library-validation`, `allow-dyld-environment-variables`,
    `allow-unsigned-executable-memory`, `disable-executable-page-protection` (medium);
    `get-task-allow` outside a Debug/Dev entitlements file (low); `applinks:` universal-link
    domains as entry points.
  - `*.xcconfig`: secret-named build settings (`API_KEY`, `CLIENT_SECRET`, `AUTH_TOKEN`)
    with a literal value (not `$(...)`, not a placeholder), reported as hard-coded secrets
    with the value masked.
  - Swift code:
    - `evaluateJavaScript("...'\(value)'...")` where a value is interpolated *inside a JS
      string literal* and isn't visibly encoded inline or where it was bound (`sanitized`,
      `escaped`, `json`, ...). Medium when the value is named like input, else low.
    - Secret-named values or keys written to `UserDefaults` (`set(_:forKey:)`,
      `@AppStorage("authToken")`), or copied to `UIPasteboard.general`.
    - `NSXPCListener` services (entry points), and a `shouldAcceptNewConnection` that
      returns `true` without checking the peer's audit token or code signature (high).
    - `NSClassFromString` / `NSSelectorFromString` / `dlopen` on a string built at the
      call site.
    - URL-scheme and universal-link handlers as entry points.
- **Dependency SBOM** — parses `Package.resolved` (formats **v1**, **v2**, and **v3**,
  including the copy Xcode stashes under `*.xcworkspace/xcshareddata/swiftpm/`) into
  the scan's dependency inventory, marking direct vs. transitive by cross-referencing
  the `Package.swift` manifest. SwiftPM pins carry their repository URL, which
  `--cve` matches against OSV's `SwiftURL` ecosystem. CocoaPods `Podfile.lock` pods
  are inventoried (`cocoapods`; direct when listed under `DEPENDENCIES:`, subspecs
  folded into their pod); OSV has no CocoaPods database, so they aren't CVE-matched.
  Carthage `Cartfile.resolved` pins are inventoried as `carthage` (direct when the
  `Cartfile` lists them, a leading `v` dropped from tag versions) with the repository URL,
  so `--cve` matches them against OSV's `SwiftURL` ecosystem like SwiftPM pins.
- **Framework hints** — flags server-side frameworks (Vapor, Hummingbird, Kitura,
  Perfect) when declared in the manifest.
- **Entrypoints** — `main.swift` and `@main`.

## Roadmap

- **Objective-C / Objective-C++** ([AttackMap#190](https://github.com/mlaify/AttackMap/issues/190)) — a second analyzer (`objc`) in this package that shares the app-surface model.

Part of the [Swift analyzer epic](https://github.com/mlaify/AttackMap/issues/204).

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

[MIT](LICENSE). Copyright (c) 2026 Matthew Davis and AttackMap Contributors.
