"""Swift ecosystem analyzer for AttackMap.

- SwiftPM project detection and a dependency SBOM from ``Package.resolved``
  (formats v1/v2/v3) and CocoaPods' ``Podfile.lock``.
- Server-side routes (#187): Vapor 4 and Hummingbird 1.x/2.x, with prefixes,
  mounts and route-level auth (``routes.py``).
- The iOS/macOS app attack surface (#188, ``apple_surface.py``): App Transport
  Security exceptions and custom URL schemes in ``Info.plist``, weakening
  entitlements and universal links, secrets in ``.xcconfig`` files, the
  Carthage SBOM, and in Swift code URL-scheme / universal-link / XPC entry
  points, WKWebView script injection, secrets in UserDefaults or on the
  pasteboard, unvalidated XPC peers and dynamic dispatch on built strings.
- Framework hints and ``main.swift`` / ``@main`` entrypoints.
"""

from __future__ import annotations

import json
import posixpath
import re
from pathlib import Path

from attackmap.sdk import (
    DEFAULT_SKIP_DIRS,
    AnalyzerMetadata,
    DependencyHint,
    EntrypointHint,
    FrameworkHint,
    iter_repo_files,
    line_of,
    read_source,
    rel,
    Route,
    ScanResult,
)

from . import apple_surface
from .routes import extract_repo_routes
from .sbom import parse_podfile_lock

# Swift-specific additions to the shared skip list (which already covers
# build/, .git/, node_modules/, __pycache__/, ...). Matched against directory
# names *inside* the repo only.
SKIP_DIRS = DEFAULT_SKIP_DIRS | {
    ".build",          # SwiftPM build products
    "DerivedData",     # Xcode build products
    "Pods",            # CocoaPods vendored sources
    "Carthage",
}

_MANIFEST_NAMES = {"Package.swift", "Package.resolved", "Podfile.lock"}
_XCODE_BUNDLE_SUFFIXES = {".xcodeproj", ".xcworkspace"}

# Known server-side frameworks worth surfacing when seen in Package.swift deps.
_FRAMEWORK_HINTS: dict[str, str] = {
    "vapor": "Vapor (server-side Swift web framework)",
    "hummingbird": "Hummingbird (server-side Swift web framework)",
    "kitura": "Kitura (server-side Swift web framework)",
    "perfect": "Perfect (server-side Swift web framework)",
}

# `.package(url: "https://github.com/vapor/vapor.git", ...)` and the newer
# `.package(name: "X", url: "...")` / path-based forms.
_PACKAGE_URL_RE = re.compile(r"\.package\s*\([^)]*?url\s*:\s*\"([^\"]+)\"", re.DOTALL)


def _identity_from_url(url: str) -> str:
    """SwiftPM identity = the last path component of the repo URL, lowercased,
    without a trailing ``.git`` (matches how Package.resolved v2/v3 records it)."""
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail.lower()


def _line_of(content: str, needle: str) -> int | None:
    idx = content.find(needle)
    if idx < 0:
        return None
    return line_of(content, idx)


_TEST_DIRS = {"tests", "test", "uitests", "spec", "specs", "fixtures", "__tests__"}


def _is_test_path(rel_path: str) -> bool:
    """SwiftPM/Xcode test code: `Tests/`, `<Target>Tests/`, `FooTests.swift`."""
    parts = rel_path.split("/")
    if any(p.lower() in _TEST_DIRS or p.endswith("Tests") for p in parts[:-1]):
        return True
    return parts[-1].endswith(("Tests.swift", "Test.swift"))


def _in_xcode_bundle(path: Path, root: Path) -> bool:
    """True if ``path`` sits inside a ``*.xcodeproj`` / ``*.xcworkspace`` bundle."""
    return any(Path(part).suffix in _XCODE_BUNDLE_SUFFIXES for part in Path(rel(path, root)).parts[:-1])


class SwiftAnalyzer:
    metadata = AnalyzerMetadata(
        name="swift",
        display_name="Swift Analyzer",
        version="0.1.0",
        description="Swift ecosystem analyzer: Vapor/Hummingbird routes with route-level auth, the iOS/macOS app attack surface (ATS, URL schemes, entitlements, WKWebView, UserDefaults, XPC), and a SwiftPM/CocoaPods/Carthage dependency SBOM.",
        scope="Swift source trees and SwiftPM/Xcode projects: server-side Swift routes (Vapor, Hummingbird), iOS/macOS app projects (Info.plist, entitlements, xcconfig), and resolved Package.resolved / Podfile.lock / Cartfile.resolved dependencies for CVE/SBOM.",
        targets=["swift", "swiftpm", "vapor", "hummingbird"],
        languages=["swift"],
        priority=20,
        experimental=True,  # Heuristic route and app-surface extraction.
        enabled_by_default=False,  # opt-in via `-m swift` while experimental (AttackMap#221)
    )

    @property
    def name(self) -> str:
        return self.metadata.name

    # ---------- Public entry points ----------

    def detect(self, repo_path: str | Path) -> bool:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            return False
        # The walker yields files only, so an Xcode project/workspace bundle is
        # recognized by the files inside it (project.pbxproj, ...).
        for path in iter_repo_files(root, skip_dirs=SKIP_DIRS):
            if path.name in _MANIFEST_NAMES or path.suffix == ".swift":
                return True
            if _in_xcode_bundle(path, root):
                return True
        return False

    def analyze(self, repo_path: str | Path) -> ScanResult:
        root = Path(repo_path).resolve()
        result = ScanResult(root=str(root))
        if not root.exists() or not root.is_dir():
            return result

        # One walk; manifests are processed before Package.resolved because the
        # resolved pins are marked direct against the manifests' dependencies.
        manifests: list[Path] = []
        resolved: list[Path] = []
        pod_locks: list[Path] = []
        sources: list[Path] = []
        for path in iter_repo_files(root, suffixes={".swift"}, names=_MANIFEST_NAMES, skip_dirs=SKIP_DIRS):
            if path.name == "Package.swift":
                manifests.append(path)
            elif path.name == "Package.resolved":
                resolved.append(path)
            elif path.name == "Podfile.lock":
                pod_locks.append(path)
            if path.suffix == ".swift":
                sources.append(path)

        direct = self._analyze_manifest(root, manifests, result)
        self._analyze_resolved(root, resolved, result, direct)
        self._analyze_podfile_locks(root, pod_locks, result)
        self._analyze_entrypoints(root, sources, result)
        self._analyze_routes(root, sources, manifests, result)
        self._analyze_app_surface(root, sources, result)
        return result

    # ---------- iOS/macOS app surface (#188) ----------

    def _analyze_app_surface(self, root: Path, sources: list[Path], result: ScanResult) -> None:
        apple_surface.analyze_project_files(root, result, SKIP_DIRS, is_test=_is_test_path)
        handlers: list[apple_surface.Handler] = []
        for path in sources:
            rel_path = rel(path, root)
            if _is_test_path(rel_path):
                continue
            text = read_source(path)
            if text is not None:
                apple_surface.analyze_swift_source(rel_path, text, result, handlers)
        apple_surface.report_url_schemes(result, handlers)
        apple_surface.finalize_xpc(result)

    # ---------- Routes (#187) ----------

    def _analyze_routes(self, root: Path, sources: list[Path], manifests: list[Path], result: ScanResult) -> None:
        files: list[tuple[str, str]] = []
        for path in sources:
            rel_path = rel(path, root)
            if _is_test_path(rel_path):
                continue  # test apps register throwaway routes
            text = read_source(path)
            if text is not None:
                files.append((rel_path, text))
        package_dirs = [posixpath.dirname(rel(m, root)) for m in manifests]
        for rel_path, hits in sorted(extract_repo_routes(files, package_dirs).items()):
            for hit in hits:
                result.routes.append(Route(
                    path=hit.path, method=hit.method, file=rel_path, line=hit.line,
                    auth=hit.auth, guards=hit.guards, guard_evidence=hit.evidence,
                ))

    # ---------- Podfile.lock (CocoaPods SBOM) ----------

    def _analyze_podfile_locks(self, root: Path, locks: list[Path], result: ScanResult) -> None:
        for lock in locks:
            text = read_source(lock)
            if text is None:
                continue
            rel_path = rel(lock, root)
            for pod in parse_podfile_lock(text):
                result.dependencies.append(DependencyHint(
                    name=pod.name, version=pod.version, ecosystem="cocoapods", file=rel_path,
                    line=pod.line, resolved=True, direct=pod.direct, source_analyzer="swift",
                ))

    # ---------- Package.swift (manifest) ----------

    def _analyze_manifest(self, root: Path, manifests: list[Path], result: ScanResult) -> set[str]:
        """Record SwiftPM + framework hints; return the set of *direct* dependency
        identities declared in the manifest (used to mark resolved pins direct)."""
        direct: set[str] = set()
        for manifest in manifests:
            text = read_source(manifest)
            if text is None:
                continue
            rel_path = rel(manifest, root)
            result.framework_hints.append(FrameworkHint(
                hint="SwiftPM", file=rel_path, line=1,
                evidence_text="Package.swift present — Swift Package Manager project."))
            for m in _PACKAGE_URL_RE.finditer(text):
                url = m.group(1)
                identity = _identity_from_url(url)
                direct.add(identity)
                for key, label in _FRAMEWORK_HINTS.items():
                    if key in identity:
                        result.framework_hints.append(FrameworkHint(
                            hint=label, file=rel_path, line=_line_of(text, url) or 1,
                            evidence_text=f"Declared dependency: {url}"))
        return direct

    # ---------- Package.resolved (SBOM) ----------

    def _analyze_resolved(self, root: Path, resolved_files: list[Path], result: ScanResult, direct: set[str]) -> None:
        for resolved in resolved_files:
            text = read_source(resolved)
            if text is None:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue  # a malformed pin file must not abort the scan
            rel_path = rel(resolved, root)
            for pin in _iter_pins(data):
                identity = (pin.get("identity") or pin.get("package") or "").lower()
                if not identity:
                    continue
                state = pin.get("state") or {}
                version = state.get("version") or ""  # branch/revision pins have no version
                location = pin.get("location") or pin.get("repositoryURL") or ""
                result.dependencies.append(DependencyHint(
                    name=identity,
                    version=version,
                    ecosystem="swiftpm",
                    file=rel_path,
                    resolved=True,
                    direct=identity in direct,
                    evidence_text=location or None,
                    source_analyzer="swift",
                ))

    # ---------- Entrypoints ----------

    def _analyze_entrypoints(self, root: Path, sources: list[Path], result: ScanResult) -> None:
        for path in sources:
            text = read_source(path)
            if text is None:
                continue
            rel_path = rel(path, root)
            if path.name == "main.swift":
                result.entrypoint_hints.append(EntrypointHint(
                    hint="main.swift (top-level executable entrypoint)",
                    file=rel_path, line=1, evidence_text="Swift top-level main.swift"))
            elif "@main" in text:
                result.entrypoint_hints.append(EntrypointHint(
                    hint="@main attribute (executable entrypoint)",
                    file=rel_path, line=_line_of(text, "@main") or 1, evidence_text="@main"))


def _iter_pins(data: object):
    """Yield pin dicts across Package.resolved formats: v1 nests them under
    ``object.pins``; v2/v3 put ``pins`` at the top level."""
    if not isinstance(data, dict):
        return
    pins = data.get("pins")
    if pins is None:
        obj = data.get("object")
        if isinstance(obj, dict):
            pins = obj.get("pins")
    if isinstance(pins, list):
        for pin in pins:
            if isinstance(pin, dict):
                yield pin
