import json
import sys
from pathlib import Path

import pytest

from attackmap_analyzer_swift import SwiftAnalyzer


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


PACKAGE_SWIFT = """// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MyServer",
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.89.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),
    ],
    targets: [.executableTarget(name: "MyServer", dependencies: ["Vapor"])]
)
"""

# Package.resolved v2/v3 (Xcode 13.3+ / SwiftPM): top-level "pins".
RESOLVED_V2 = json.dumps({
    "pins": [
        {"identity": "vapor", "kind": "remoteSourceControl",
         "location": "https://github.com/vapor/vapor.git",
         "state": {"version": "4.89.0", "revision": "abc"}},
        {"identity": "swift-nio", "kind": "remoteSourceControl",
         "location": "https://github.com/apple/swift-nio.git",
         "state": {"version": "2.63.0", "revision": "def"}},
    ],
    "version": 2,
})

# Package.resolved v1 (Xcode 11–13): pins nested under "object".
RESOLVED_V1 = json.dumps({
    "object": {"pins": [
        {"package": "Alamofire", "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
         "state": {"version": "5.8.1", "revision": "xyz"}},
    ]},
    "version": 1,
})


def test_detect_swiftpm_project(tmp_path: Path):
    _write(tmp_path, "Package.swift", PACKAGE_SWIFT)
    assert SwiftAnalyzer().detect(tmp_path) is True


def test_detect_by_source_file(tmp_path: Path):
    _write(tmp_path, "Sources/App/main.swift", 'print("hi")\n')
    assert SwiftAnalyzer().detect(tmp_path) is True


def test_detect_false_on_unrelated_repo(tmp_path: Path):
    _write(tmp_path, "app.py", "print('hi')\n")
    assert SwiftAnalyzer().detect(tmp_path) is False


def test_detect_ignores_build_dir(tmp_path: Path):
    _write(tmp_path, ".build/checkouts/vapor/Package.swift", PACKAGE_SWIFT)
    assert SwiftAnalyzer().detect(tmp_path) is False


def test_framework_and_swiftpm_hints(tmp_path: Path):
    _write(tmp_path, "Package.swift", PACKAGE_SWIFT)
    result = SwiftAnalyzer().analyze(tmp_path)
    hints = [h.hint for h in result.framework_hints]
    assert "SwiftPM" in hints
    assert any("Vapor" in h for h in hints)


def test_resolved_v2_sbom(tmp_path: Path):
    _write(tmp_path, "Package.swift", PACKAGE_SWIFT)
    _write(tmp_path, "Package.resolved", RESOLVED_V2)
    result = SwiftAnalyzer().analyze(tmp_path)
    deps = {d.name: d for d in result.dependencies}
    assert deps["vapor"].version == "4.89.0"
    assert deps["vapor"].ecosystem == "swiftpm"
    assert deps["vapor"].resolved is True
    assert deps["vapor"].direct is True                 # declared in Package.swift
    assert deps["swift-nio"].version == "2.63.0"
    assert deps["swift-nio"].direct is True             # apple/swift-nio is declared
    assert deps["vapor"].source_analyzer == "swift"


def test_resolved_v1_sbom(tmp_path: Path):
    # No Package.swift → no direct set → everything transitive/false.
    _write(tmp_path, "Package.resolved", RESOLVED_V1)
    result = SwiftAnalyzer().analyze(tmp_path)
    deps = {d.name: d for d in result.dependencies}
    assert deps["alamofire"].version == "5.8.1"
    assert deps["alamofire"].direct is False


def test_resolved_in_xcode_workspace_path(tmp_path: Path):
    # Xcode stashes Package.resolved under the workspace's xcshareddata.
    _write(tmp_path, "App.xcworkspace/xcshareddata/swiftpm/Package.resolved", RESOLVED_V2)
    result = SwiftAnalyzer().analyze(tmp_path)
    assert {d.name for d in result.dependencies} == {"vapor", "swift-nio"}


def test_malformed_resolved_does_not_crash(tmp_path: Path):
    _write(tmp_path, "Package.swift", PACKAGE_SWIFT)
    _write(tmp_path, "Package.resolved", "{ this is : not json ]")
    result = SwiftAnalyzer().analyze(tmp_path)   # must not raise
    assert result.dependencies == []


def test_entrypoints(tmp_path: Path):
    _write(tmp_path, "Sources/App/main.swift", 'import Foundation\nprint("run")\n')
    _write(tmp_path, "Sources/App/App.swift", "@main\nstruct App {}\n")
    result = SwiftAnalyzer().analyze(tmp_path)
    hints = " ".join(h.hint for h in result.entrypoint_hints)
    assert "main.swift" in hints
    assert "@main" in hints


def test_metadata_contract():
    m = SwiftAnalyzer().metadata
    assert m.name == "swift"
    assert "swift" in m.languages
    assert SwiftAnalyzer().name == "swift"


def test_detect_xcode_project_bundle(tmp_path: Path):
    _write(tmp_path, "App.xcodeproj/project.pbxproj", "// !$*UTF8*$!\n")
    assert SwiftAnalyzer().detect(tmp_path) is True


def test_experimental_analyzer_is_opt_in():
    m = SwiftAnalyzer().metadata
    assert m.experimental is True
    assert m.enabled_by_default is False


# ---------- Repo walking (AttackMap#253) ----------


def test_repo_under_skip_dir_named_parents_is_analyzed(tmp_path: Path):
    """A checkout under /.../build/out/... must not be skipped (absolute-path bug)."""
    repo = tmp_path / "build" / "out" / "repo"
    _write(repo, "Package.swift", PACKAGE_SWIFT)
    _write(repo, "Package.resolved", RESOLVED_V2)
    _write(repo, "Sources/App/main.swift", 'print("run")\n')
    analyzer = SwiftAnalyzer()
    assert analyzer.detect(repo) is True
    result = analyzer.analyze(repo)
    assert {d.name for d in result.dependencies} == {"vapor", "swift-nio"}
    assert any(h.hint == "SwiftPM" and h.file == "Package.swift" for h in result.framework_hints)
    assert any(e.file == "Sources/App/main.swift" for e in result.entrypoint_hints)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinked_files_outside_repo_not_analyzed(tmp_path: Path):
    outside = tmp_path / "outside"
    _write(outside, "Package.resolved", RESOLVED_V2)
    _write(outside, "Secret.swift", "@main\nstruct Secret {}\n")
    repo = tmp_path / "repo"
    _write(repo, "Package.swift", PACKAGE_SWIFT)
    (repo / "Package.resolved").symlink_to(outside / "Package.resolved")
    (repo / "Secret.swift").symlink_to(outside / "Secret.swift")
    result = SwiftAnalyzer().analyze(repo)
    assert result.dependencies == []
    assert result.entrypoint_hints == []
    assert [h.hint for h in result.framework_hints if h.hint == "SwiftPM"] == ["SwiftPM"]


# ---------- Podfile.lock (CocoaPods SBOM, swift#1) ----------

PODFILE_LOCK = """PODS:
  - AFNetworking (4.0.1):
    - AFNetworking/NSURLSession (= 4.0.1)
  - AFNetworking/NSURLSession (4.0.1)
  - "GoogleUtilities/Environment (7.11.0)":
    - PromisesObjC (< 3.0, >= 1.2)
  - PromisesObjC (2.3.1)
  - LocalPod (0.1.0)

DEPENDENCIES:
  - AFNetworking (~> 4.0)
  - GoogleUtilities/Environment
  - LocalPod (from `../LocalPod`)

SPEC REPOS:
  trunk:
    - AFNetworking
    - GoogleUtilities
    - PromisesObjC

EXTERNAL SOURCES:
  LocalPod:
    :path: "../LocalPod"

SPEC CHECKSUMS:
  AFNetworking: 3bd23d814e976cd148d7d44c3ab78017b744cd58

COCOAPODS: 1.15.2
"""


def test_podfile_lock_sbom(tmp_path: Path):
    _write(tmp_path, "ios/Podfile.lock", PODFILE_LOCK)
    result = SwiftAnalyzer().analyze(tmp_path)
    deps = {d.name: d for d in result.dependencies}
    assert set(deps) == {"AFNetworking", "GoogleUtilities", "PromisesObjC", "LocalPod"}
    afn = deps["AFNetworking"]
    assert (afn.version, afn.ecosystem, afn.file, afn.line) == ("4.0.1", "cocoapods", "ios/Podfile.lock", 2)
    assert afn.resolved is True and afn.direct is True
    assert deps["GoogleUtilities"].version == "7.11.0" and deps["GoogleUtilities"].direct is True
    assert deps["PromisesObjC"].direct is False          # only pulled in transitively
    assert deps["LocalPod"].direct is True


def test_podfile_lock_garbage_does_not_crash(tmp_path: Path):
    import random

    rng = random.Random(1)
    _write(tmp_path, "Podfile.lock", "PODS:\n  - (\n  - X (\nDEPENDENCIES:\n  -\n" + "".join(
        rng.choice('PODS:-() "\n\t:/') for _ in range(2000)))
    SwiftAnalyzer().analyze(tmp_path)  # must not raise
    for cut in range(0, len(PODFILE_LOCK), 5):
        _write(tmp_path, "Podfile.lock", PODFILE_LOCK[:cut])
        SwiftAnalyzer().analyze(tmp_path)
