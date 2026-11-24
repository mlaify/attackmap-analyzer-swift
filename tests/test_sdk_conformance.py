"""SDK 1.0 conformance (mlaify/AttackMap#254): attackmap.sdk.testing.assert_conforms."""

from pathlib import Path

from attackmap.sdk.testing import assert_conforms

from attackmap_analyzer_swift import ObjCAnalyzer, SwiftAnalyzer


def _has_signals(result) -> None:
    assert any(isinstance(v, list) and v for v in result.__dict__.values()), "the analyzer emitted nothing"


SAMPLE = {'Package.swift': '// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(name: "s", dependencies: [.package(url: "https://github.com/vapor/vapor.git", from: "4.0.0")])\n', 'Sources/App/routes.swift': 'import Vapor\n\nfunc routes(_ app: Application) throws {\n    app.get("users", ":id") { req in "x" }\n}\n', 'Sources/Legacy/AppDelegate.m': '#import <UIKit/UIKit.h>\n@implementation AppDelegate\n- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)options {\n    return YES;\n}\n@end\n'}


def test_conforms_to_the_sdk(tmp_path: Path) -> None:
    for rel, text in SAMPLE.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    _has_signals(assert_conforms(ObjCAnalyzer(), tmp_path))
    _has_signals(assert_conforms(SwiftAnalyzer(), tmp_path))
