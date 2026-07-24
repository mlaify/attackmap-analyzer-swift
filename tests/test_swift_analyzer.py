import json
from pathlib import Path

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
