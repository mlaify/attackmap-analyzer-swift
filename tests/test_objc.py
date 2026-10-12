"""Objective-C / Objective-C++ analyzer (AttackMap#190): the `objc` entry point."""

from __future__ import annotations

import random
import tomllib
from pathlib import Path

from attackmap.analyzers import merge_analyzer_results

from attackmap_analyzer_swift import ObjCAnalyzer, SwiftAnalyzer
from attackmap_analyzer_swift.objc import parse

ROOT = Path(__file__).resolve().parents[1]


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _analyze(tmp_path: Path, files: dict[str, str]):
    for rel, content in files.items():
        _write(tmp_path, rel, content)
    return ObjCAnalyzer().analyze(tmp_path)


def _lines(result, kind: str):
    issues = [i for i in result.app_surface_issues if i.kind == kind]
    issues += [w for w in result.code_weaknesses if w.kind == kind]
    return sorted((i.line, i.severity) for i in issues)


OBJC = r'''#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary *)options {
    return [self.router handle:url];
}

- (void)highlight:(NSString *)linkID count:(long)count escaped:(NSString *)escapedTitle {
    [self.webView evaluateJavaScript:[NSString stringWithFormat:@"select('%@', %ld, \"%@\")", linkID, count, escapedTitle] completionHandler:nil];
    [self.webView evaluateJavaScript:[NSString stringWithFormat:@"setSize(%@)", sizeJSON] completionHandler:nil];
    [self.webView evaluateJavaScript:@"noop()" completionHandler:nil];
}

- (void)store:(Token *)token {
    [[NSUserDefaults standardUserDefaults] setObject:token.accessToken forKey:@"session"];
    NSUserDefaults *ud = [[NSUserDefaults alloc] initWithSuiteName:@"group.x"];
    [ud setObject:value forKey:@"password"];
    [NSUserDefaults.standardUserDefaults setValue:[user apiKey] forKey:@"k"];
    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"hasPassword"];
    [[NSUserDefaults standardUserDefaults] setObject:deviceToken forKey:@"deviceToken"];
    [cache setObject:password forKey:@"password"];
    [UIPasteboard generalPasteboard].string = self.password;
    [UIPasteboard generalPasteboard].string = self.shareURL.absoluteString;
}

- (void)load:(NSString *)name {
    Class c = NSClassFromString([NSString stringWithFormat:@"Plugin%@", name]);
    SEL s = NSSelectorFromString(@"initWithHandler:");
    Class d = NSClassFromString(className);
    void *h = dlopen([path stringByAppendingString:@"/lib.dylib"].UTF8String, RTLD_NOW);
}

- (void)log:(NSString *)msg format:(NSString *)format args:(va_list)args {
    NSString *a = [NSString stringWithFormat:msg];
    NSString *b = [NSString stringWithFormat:@"%@", msg];
    NSString *c = [NSString stringWithFormat:NSLocalizedString(@"greeting", nil)];
    NSString *d = [NSString stringWithFormat:format, msg];
    NSString *e = [[NSString alloc] initWithFormat:format arguments:args];
    NSLog(msg);
    NSLog(@"%@", msg);
    // NSLog(msg);
    [text appendFormat:msg];
}

- (void)run:(NSString *)path {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/bin/sh";
    task.arguments = @[@"-c", [NSString stringWithFormat:@"ls %@", path]];
    task.arguments = @[@"-c", @"ls /tmp"];
    system(cmd);
    system("ls");
}

@end

@implementation Helper
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedObject = self;
    [newConnection resume];
    return YES;
}
@end

@implementation CheckedHelper
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    if (![self isValidPeer:newConnection.auditToken]) { return NO; }
    return YES;
}
- (void)start {
    self.listener = [[NSXPCListener alloc] initWithMachServiceName:@"com.example.helper"];
}
@end
'''

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleURLTypes</key>
	<array><dict><key>CFBundleURLSchemes</key><array><string>legacyapp</string></array></dict></array>
</dict>
</plist>
"""


def test_objc_surface_and_native_weaknesses(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {"App/AppDelegate.m": OBJC, "App/Info.plist": INFO_PLIST})
    # `linkID` is quoted and input-named; `count` is %ld; `escapedTitle` is encoded;
    # `sizeJSON` is unquoted.
    assert _lines(result, "apple_webview_js_injection") == [(11, "medium")]
    js = next(i for i in result.app_surface_issues if i.kind == "apple_webview_js_injection")
    assert js.evidence_text.endswith("[interpolated: linkID]")
    assert _lines(result, "apple_insecure_secret_storage") == [(17, "medium"), (19, "medium"), (20, "medium")]
    assert _lines(result, "apple_pasteboard_secret") == [(24, "low")]
    assert _lines(result, "apple_dynamic_dispatch") == [(29, "medium"), (32, "medium")]
    assert _lines(result, "format_string") == [(36, "medium"), (41, "medium"), (44, "medium")]
    assert _lines(result, "native_command_exec") == [(50, "medium"), (52, "medium")]
    # A mach service in the same file: high.
    assert _lines(result, "apple_xpc_unvalidated_peer") == [(59, "high")]
    assert all(w.confidence == "medium" and w.source_kind is None for w in result.code_weaknesses)
    hints = {(h.hint, h.line) for h in result.entrypoint_hints}
    assert ("url_scheme_handler (opens URLs from other apps)", 6) in hints
    assert ("xpc_service: mach service (NSXPCListener(machServiceName:))", 72) in hints
    scheme = [i for i in result.app_surface_issues if i.kind == "apple_custom_url_scheme"]
    assert [i.evidence_text for i in scheme] == ["CFBundleURLSchemes: legacyapp://"]
    assert result.languages == ["objective-c"] and result.files_scanned == 1


def test_detect_needs_objective_c_not_matlab(tmp_path: Path) -> None:
    _write(tmp_path, "analysis/model.m", "function y = f(x)\n  y = x .* 2;\nend\n")
    assert ObjCAnalyzer().detect(tmp_path) is False
    assert ObjCAnalyzer().analyze(tmp_path).files_scanned == 0
    _write(tmp_path, "Sources/Thing.mm", "#import <Foundation/Foundation.h>\n@implementation Thing\n@end\n")
    assert ObjCAnalyzer().detect(tmp_path) is True


def test_test_targets_are_skipped(tmp_path: Path) -> None:
    result = _analyze(tmp_path, {"AppTests/AppDelegateTests.m": OBJC})
    assert result.app_surface_issues == [] and result.code_weaknesses == []


def test_both_analyzers_merge_without_duplicates(tmp_path: Path) -> None:
    files = {
        "App/AppDelegate.m": OBJC,
        "App/Info.plist": INFO_PLIST,
        "App/Main.swift": "import UIKit\n",
    }
    for rel, content in files.items():
        _write(tmp_path, rel, content)
    swift = SwiftAnalyzer().analyze(tmp_path)
    objc = ObjCAnalyzer().analyze(tmp_path)
    merged = merge_analyzer_results([swift, objc], root=tmp_path)
    keys = [(i.kind, i.file, i.line) for i in merged.app_surface_issues]
    assert len(keys) == len(set(keys))
    assert [k for k in keys if k[0] == "apple_custom_url_scheme"] == [("apple_custom_url_scheme", "App/Info.plist", 5)]


def test_objc_entry_point_is_registered() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["entry-points"]["attackmap.analyzers"] == {
        "swift": "attackmap_analyzer_swift:SwiftAnalyzer",
        "objc": "attackmap_analyzer_swift:ObjCAnalyzer",
    }
    meta = ObjCAnalyzer().metadata
    assert (meta.name, meta.experimental, meta.enabled_by_default) == ("objc", True, False)
    assert meta.priority > SwiftAnalyzer().metadata.priority  # swift wins duplicate project-file signals
    assert ObjCAnalyzer().name == "objc"


def test_masking_handles_c_comments_chars_and_strings() -> None:
    text = 'a(1); /* x /* y */ b[2]; c = \'"\'; d = @"]\\"("; e{3} // f(\n'
    src = parse(text)
    assert [text[a:b] for a, b in src.masked] == ["/* x /* y */", "'\"'", '@"]\\"("', "// f("]
    assert sorted((text[a], text[b]) for a, b in src.pairs.items()) == [("(", ")"), ("[", "]"), ("{", "}")]


def test_garbage_never_raises(tmp_path: Path) -> None:
    rng = random.Random(190)
    alphabet = '[]{}()@";:%\'/*\n -cYESreturn'
    for i in range(60):
        chars = list(OBJC)
        for _ in range(rng.randint(1, 40)):
            chars[rng.randrange(len(chars))] = rng.choice(alphabet)
        _write(tmp_path, f"g/F{i}.m", "".join(chars))
    for cut in range(0, len(OBJC), 13):
        _write(tmp_path, f"c/C{cut}.m", "#import <X.h>\n" + OBJC[:cut])
    _write(tmp_path, "n/Noise.m", "#import <X.h>\n" + "".join(rng.choice(alphabet) for _ in range(20000)))
    ObjCAnalyzer().analyze(tmp_path)  # must not raise


def test_objc_bundled_xpc_service_is_low_and_helper_checks_count(tmp_path: Path) -> None:
    template = """#import <Foundation/Foundation.h>
@implementation ServiceDelegate
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedObject = [MyService new];
    [newConnection resume];
    return YES;
}
@end
int main(void) {
    NSXPCListener *listener = [NSXPCListener serviceListener];
    [listener resume];
}
"""
    result = _analyze(tmp_path / "bundled", {"MyService/main.m": template})
    assert _lines(result, "apple_xpc_unvalidated_peer") == [(3, "low")]
    checked = template.replace("    [newConnection resume];", "    if (![self isTrustedPeer:newConnection]) return NO;\n    [newConnection resume];")
    result = _analyze(tmp_path / "checked", {"MyService/main.m": checked})
    assert _lines(result, "apple_xpc_unvalidated_peer") == []
