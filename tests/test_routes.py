"""Vapor / Hummingbird route extraction with route-level auth (AttackMap#187, #256)."""

from __future__ import annotations

import random
from pathlib import Path

from attackmap_analyzer_swift import SwiftAnalyzer
from attackmap_analyzer_swift.routes import extract_repo_routes
from attackmap_analyzer_swift.swiftsrc import parse


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _routes(tmp_path: Path, files: dict[str, str]):
    for rel, text in files.items():
        _write(tmp_path, rel, text)
    return SwiftAnalyzer().analyze(tmp_path).routes


def _by_key(routes):
    return {(r.method, r.path): r for r in routes}


VAPOR_ROUTES = """import Vapor

func routes(_ app: Application) throws {
    app.get { req in "home" }
    app.get("users", ":id") { req -> String in
        req.parameters.get("id") ?? ""
    }
    app.get("files", "**", use: serveFile)
    app.on(.POST, "upload", body: .stream, use: upload)
    // Websockets upgrade over GET.
    app.webSocket("echo") { req, ws in }

    let api = app.grouped("api", "v1")
    api.get("status", use: status)

    let protected = api.grouped(UserAuthenticator(), User.guardMiddleware())
    protected.post("todos", use: createTodo)
    protected.delete("todos", .parameter("todoID"), use: deleteTodo)

    // Only an authenticator: callers without credentials still get through.
    let optional = api.grouped(UserAuthenticator())
    optional.get("feed", use: feed)
    optional.get("me") { req -> String in
        let user = try req.auth.require(User.self)
        return user.name
    }

    app.group("admin") { admin in
        admin.grouped(User.redirectMiddleware(path: "/login")).get("dashboard", use: dashboard)
        admin.group(AdminMiddleware()) {
            $0.get("stats", use: stats)
        }
    }
    app.get(SiteURL.faq.pathComponents, use: faq)

    // app.get("commented") { _ in "no" }
    let s = "app.get(\\"in-a-string\\") { _ in }"
    let id = req.parameters.get("id")
    app.client.get("https://example.com") { req in }
    cache.get("key") { value in }
}
"""


def test_vapor_grouped_and_guarded_routes(tmp_path: Path) -> None:
    routes = _by_key(_routes(tmp_path, {"Sources/App/routes.swift": VAPOR_ROUTES}))
    assert set(routes) == {
        ("GET", "/"),
        ("GET", "/users/{id}"),
        ("GET", "/files/**"),
        ("POST", "/upload"),
        ("GET", "/echo"),
        ("GET", "/api/v1/status"),
        ("POST", "/api/v1/todos"),
        ("DELETE", "/api/v1/todos/{todoID}"),
        ("GET", "/api/v1/feed"),
        ("GET", "/api/v1/me"),
        ("GET", "/admin/dashboard"),
        ("GET", "/admin/stats"),
        ("GET", "/$(SiteURL.faq)"),
    }
    todo = routes[("POST", "/api/v1/todos")]
    assert todo.auth == "required"
    assert todo.guards == ["UserAuthenticator()", "User.guardMiddleware()"]
    assert todo.guard_evidence == 'api.grouped(UserAuthenticator(), User.guardMiddleware())'
    assert todo.file == "Sources/App/routes.swift" and todo.line == 17
    assert routes[("DELETE", "/api/v1/todos/{todoID}")].auth == "required"
    # An authenticator alone doesn't enforce anything...
    assert routes[("GET", "/api/v1/feed")].auth == "unknown"
    # ...unless the handler requires the user itself.
    me = routes[("GET", "/api/v1/me")]
    assert me.auth == "required" and "auth.require" in me.guards
    assert "req.auth.require(User.self)" in (me.guard_evidence or "")
    assert routes[("GET", "/admin/dashboard")].auth == "required"
    assert routes[("GET", "/admin/dashboard")].guards == ['User.redirectMiddleware(path: "/login")']
    # A custom middleware isn't assumed to be a guard.
    assert routes[("GET", "/admin/stats")].auth == "unknown"
    assert routes[("GET", "/")].auth == "unknown"


def test_handler_role_guard_is_reported(tmp_path: Path) -> None:
    routes = _by_key(_routes(tmp_path, {"Sources/App/admin.swift": """import Vapor
func admin(_ app: Application) {
    app.get("admin", "users") { req -> [User] in
        let user = try req.auth.require(User.self)
        guard user.roles.contains(.admin) else { throw Abort(.forbidden) }
        return []
    }
    app.get("admin", "me") { req -> String in
        let user = try req.auth.require(User.self)
        let canEdit = user.roles.contains(.admin)
        return user.name
    }
}
"""}))
    users = routes[("GET", "/admin/users")]
    assert users.guards == ["auth.require", "guard user.roles.contains(.admin) else { throw Abort(.forbidden) }"]
    # A role read that doesn't gate the handler isn't a guard.
    assert routes[("GET", "/admin/me")].guards == ["auth.require"]


VAPOR_COLLECTION = """import Vapor

struct TodoController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let todos = routes.grouped("todos")
        todos.get(use: index)
        todos.group(":todoID") { todo in
            todo.delete(use: delete)
        }
    }
    func index(req: Request) async throws -> [Todo] { [] }
    func delete(req: Request) async throws -> HTTPStatus {
        let user = try req.auth.require(User.self)
        return .ok
    }
}

struct OrphanController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        routes.get("orphan", use: orphan)
    }
}
"""

VAPOR_REGISTER = """import Vapor

func routes(_ app: Application) throws {
    let api = app.grouped("api")
    try api.register(collection: TodoController())
}
"""


def test_vapor_route_collection_takes_its_mount_prefix(tmp_path: Path) -> None:
    routes = _by_key(_routes(tmp_path, {
        "Package.swift": "// swift-tools-version:5.9\n",
        "Sources/App/Controllers/TodoController.swift": VAPOR_COLLECTION,
        "Sources/App/routes.swift": VAPOR_REGISTER,
    }))
    assert set(routes) == {("GET", "/api/todos"), ("DELETE", "/api/todos/{todoID}"), ("GET", "/$(OrphanController)/orphan")}
    assert routes[("DELETE", "/api/todos/{todoID}")].auth == "required"  # handler requires the user
    assert routes[("GET", "/api/todos")].auth == "unknown"


HB2_APP = """import Hummingbird
import HummingbirdAuth

func buildRouter() -> Router<AppRequestContext> {
    let router = Router(context: AppRequestContext.self)
    router.add(middleware: LogRequestsMiddleware(.info))
    router.get("/health") { _, _ in HTTPResponse.Status.ok }
    TodoController(fluent: fluent).addRoutes(to: router.group("api/todos"))
    router.addRoutes(ItemController().endpoints, atPath: "/items")
    router.group("auth")
        .add(middleware: JWTAuthenticator(keys: keys))
        .get("/") { request, context in
            guard let user = context.identity else { throw HTTPError(.unauthorized) }
            return user.name
        }
    router.ws("chat") { _, _ in .upgrade() }
    return router
}
"""

HB2_TODOS = """import Hummingbird

struct TodoController<Context: RequestContext> {
    func addRoutes(to group: RouterGroup<Context>) {
        group
            .get(use: self.list)
            .get(":id", use: self.get)
        group.add(middleware: SessionAuthenticator(users: users))
            .post(use: self.create)
        group.group("admin")
            .addMiddleware {
                BasicAuthenticator { username, _ in nil }
                IsAuthenticatedMiddleware()
            }
            .delete(":id", use: self.deleteId)
    }
    func list(_ request: Request, context: Context) async throws -> [Todo] { [] }
    func create(_ request: Request, context: Context) async throws -> Todo {
        let user = try context.requireIdentity()
        return Todo()
    }
}
"""

HB2_ITEMS = """import Hummingbird

struct ItemController {
    var endpoints: RouteCollection<AppRequestContext> {
        return RouteCollection(context: AppRequestContext.self)
            .get(":id", use: self.get)
            .post(use: self.create)
    }
}
"""


def test_hummingbird2_groups_controllers_and_middleware(tmp_path: Path) -> None:
    routes = _by_key(_routes(tmp_path, {
        "Package.swift": "// swift-tools-version:5.9\n",
        "Sources/App/App+build.swift": HB2_APP,
        "Sources/App/Controllers/TodoController.swift": HB2_TODOS,
        "Sources/App/Controllers/ItemController.swift": HB2_ITEMS,
    }))
    assert set(routes) == {
        ("GET", "/health"),
        ("GET", "/api/todos"),
        ("GET", "/api/todos/{id}"),
        ("POST", "/api/todos"),
        ("DELETE", "/api/todos/admin/{id}"),
        ("GET", "/items/{id}"),
        ("POST", "/items"),
        ("GET", "/auth"),
        ("GET", "/chat"),
    }
    assert routes[("GET", "/health")].auth == "unknown"
    assert routes[("GET", "/api/todos")].auth == "unknown"
    create = routes[("POST", "/api/todos")]
    assert create.auth == "required"
    assert create.guards == ["SessionAuthenticator(users: users)", "requireIdentity"]
    admin = routes[("DELETE", "/api/todos/admin/{id}")]
    assert admin.auth == "required" and "IsAuthenticatedMiddleware()" in admin.guards
    auth = routes[("GET", "/auth")]
    assert auth.auth == "required" and auth.guards[-1] == "guard identity else unauthorized"


def test_hummingbird_add_middleware_applies_to_later_routes_only(tmp_path: Path) -> None:
    routes = _by_key(_routes(tmp_path, {"Sources/App/App.swift": """import Hummingbird
func build() -> Router<Context> {
    let router = Router(context: Context.self)
    router.get("/public") { _, _ in "ok" }
    router.add(middleware: BearerAuthenticator())
    router.add(middleware: IsAuthenticatedMiddleware())
    router.get("/private") { _, _ in "ok" }
    return router
}
func other() {
    let router = Router(context: Context.self)
    router.get("/elsewhere") { _, _ in "ok" }
}
"""}))
    assert routes[("GET", "/public")].auth == "unknown"
    private = routes[("GET", "/private")]
    assert private.auth == "required"
    assert private.guards == ["BearerAuthenticator()", "IsAuthenticatedMiddleware()"]
    assert private.guard_evidence == "router.add(middleware: IsAuthenticatedMiddleware())"
    assert routes[("GET", "/elsewhere")].auth == "unknown"  # another function's router


def test_handler_401_guard_on_the_caller_only(tmp_path: Path) -> None:
    routes = _by_key(_routes(tmp_path, {"Sources/App/Web.swift": """import Hummingbird
struct WebController {
    func addRoutes(to router: Router<Context>) {
        router.post("/documents", use: self.create)
        router.post("/login", use: self.login)
    }
    func create(request: Request, context: Context) async throws -> Response {
        guard let user = context.currentUser, let ownerId = user.id else {
            throw HTTPError(.unauthorized)
        }
        return .ok
    }
    func login(request: Request, context: Context) async throws -> Response {
        let found = try await users.find(name)
        guard let user = found else { throw HTTPError(.unauthorized) }
        return .ok
    }
}
"""}))
    assert routes[("POST", "/$(WebController)/documents")].auth == "required"
    # Rejecting bad credentials in a login handler doesn't gate the route.
    assert routes[("POST", "/$(WebController)/login")].auth == "unknown"


def test_hummingbird1_app_router(tmp_path: Path) -> None:
    routes = _by_key(_routes(tmp_path, {"Sources/App/main.swift": """import Hummingbird
let app = HBApplication(configuration: .init())
app.router.get("/hello") { request -> String in "hi" }
app.router.group("/todos")
    .get(use: list)
    .post(use: create)
try app.start()
"""}))
    assert set(routes) == {("GET", "/hello"), ("GET", "/todos"), ("POST", "/todos")}


def test_disagreeing_mounts_and_separate_packages(tmp_path: Path) -> None:
    controller = """import Hummingbird
struct TodoController {
    func addRoutes(to group: RouterGroup<Context>) {
        group.get(":id", use: self.get)
    }
}
"""
    files = {
        # Two example apps in one repo, each its own Swift package.
        "a/Package.swift": "",
        "a/Sources/App/Todo.swift": controller,
        "a/Sources/App/App.swift": 'import Hummingbird\nfunc f() {\n let router = Router()\n TodoController().addRoutes(to: router.group("todos"))\n}\n',
        "b/Package.swift": "",
        "b/Sources/App/Todo.swift": controller,
        "b/Sources/App/App.swift": 'import Hummingbird\nfunc f() {\n let router = Router()\n TodoController().addRoutes(to: router.group("api/todos"))\n}\n',
        # One package that mounts the same controller twice at different paths.
        "c/Package.swift": "",
        "c/Sources/App/Todo.swift": controller,
        "c/Sources/App/App.swift": 'import Hummingbird\nfunc f() {\n let router = Router()\n TodoController().addRoutes(to: router.group("x"))\n TodoController().addRoutes(to: router.group("y"))\n}\n',
    }
    paths = {(r.file, r.path) for r in _routes(tmp_path, files)}
    assert paths == {
        ("a/Sources/App/Todo.swift", "/todos/{id}"),
        ("b/Sources/App/Todo.swift", "/api/todos/{id}"),
        ("c/Sources/App/Todo.swift", "/$(TodoController)/{id}"),
    }


def test_files_without_a_server_import_or_in_tests_have_no_routes(tmp_path: Path) -> None:
    routes = _routes(tmp_path, {
        "Sources/App/Client.swift": 'import Foundation\nfunc f(app: Application) { app.get("x") { _ in } }\n',
        "Tests/AppTests/RouteTests.swift": 'import Vapor\nfunc t(_ app: Application) { app.get("ok") { _ in "ok" } }\n',
        "Sources/AppTests/X.swift": 'import Vapor\nfunc t(_ app: Application) { app.get("ok2") { _ in "ok" } }\n',
    })
    assert routes == []


def test_routes_survive_truncation_and_garbage() -> None:
    rng = random.Random(187)
    sources = [VAPOR_ROUTES, VAPOR_COLLECTION, HB2_APP, HB2_TODOS, HB2_ITEMS]
    alphabet = '(){}[]."\\#/*\n $0abcget:=letin'
    for src in sources:
        for cut in range(0, len(src), 7):
            extract_repo_routes([("a.swift", src[:cut])])
        for _ in range(40):
            chars = list(src)
            for _ in range(rng.randint(1, 30)):
                chars[rng.randrange(len(chars))] = rng.choice(alphabet)
            extract_repo_routes([("a.swift", "".join(chars))])
    for _ in range(200):
        noise = "import Vapor\n" + "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
        extract_repo_routes([("n.swift", noise)])


def test_swift_lexer_handles_strings_comments_and_deep_nesting() -> None:
    text = 'let a = "x\\(foo("b)"))y"; f(1) /* a /* b */ ( */ g[2] """\nmulti \\(x) "\n""" #"raw \\(" "# h{}'
    src = parse(text)
    assert [text[a:b] for a, b in src.masked] == [
        '"x\\(foo("b)"))y"', "/* a /* b */ ( */", '"""\nmulti \\(x) "\n"""', '#"raw \\(" "#',
    ]
    # Only the code brackets pair: f(1), g[2], h{}.
    assert [(text[a - 1:a + 1], text[b]) for a, b in sorted(src.pairs.items())] == [("f(", ")"), ("g[", "]"), ("h{", "}")]
    # Hostile nesting ends the literal instead of recursing without bound.
    deep = '"' + '\\("' * 5000 + "x"
    parse(deep)
    parse("(" * 20000 + ")" * 3)
