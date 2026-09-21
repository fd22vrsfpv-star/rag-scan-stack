"""AST assertions for guard tests — structure instead of substrings.

Guard tests here frequently assert on the SOURCE of the code under test, because
the code needs a running service or a database to execute. That is legitimate;
asserting on a *substring* of it is not:

    assert 'json={"tool": _tool,' in src          # breaks on reformatting
    assert "sign ?in|log ?in|not authori" in src  # FAILED when the check improved
    assert "def _run_via_listener" in src         # matches a comment or a docstring

The second is not hypothetical: a test pinned the IDOR probe's login regex, so
replacing that check with a better one failed the test rather than the code. A
guard should fail when the BEHAVIOUR it describes goes away, not when the
spelling changes.

These helpers parse the module and ask structural questions. They are tolerant of
formatting, comments and docstrings, and they fail loudly on a syntax error
instead of silently matching nothing.

    from _ast_assert import defines, calls, call_kwarg, call_order, const_elements
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Optional, Union

Source = Union[str, Path]


def _tree(src: Source) -> ast.Module:
    text = Path(src).read_text(encoding="utf-8") if isinstance(src, Path) else src
    return ast.parse(text)


def _callee_name(node: ast.AST) -> Optional[str]:
    """Dotted or bare name of whatever is being called."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _callee_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _calls(tree: ast.Module):
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            name = _callee_name(n.func)
            if name:
                yield name, n


def defines(src: Source, name: str) -> bool:
    """True if the module defines this function (sync or async) or class."""
    tree = _tree(src)
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == name:
            return True
    return False


def calls(src: Source, callee: str) -> bool:
    """True if the module calls `callee`. Matches the full dotted name, or the
    trailing attribute, so both `foo()` and `mod.foo()` satisfy calls(src,'foo')."""
    for name, _ in _calls(_tree(src)):
        if name == callee or name.endswith("." + callee):
            return True
    return False


def call_kwarg(src: Source, callee: str, keyword: str) -> bool:
    """True if some call to `callee` passes `keyword=`."""
    for name, node in _calls(_tree(src)):
        if name == callee or name.endswith("." + callee):
            if any(kw.arg == keyword for kw in node.keywords):
                return True
    return False


def _scope(tree: ast.Module, within: Optional[str]) -> ast.AST:
    if not within:
        return tree
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == within:
            return n
    raise AssertionError(f"function {within!r} not found")


def call_order(src: Source, first: str, second: str, *, within: Optional[str] = None) -> bool:
    """True if the first call to `first` precedes the first call to `second`.

    Replaces the `src.index(a) < src.index(b)` idiom, which also matches the two
    names inside comments and docstrings and so can be satisfied by prose.

    Pass `within="fn"` to scope the question to one function — usually what is
    actually meant. Module scope is a trap when the callee is called from several
    places: `_llm_phase` runs in every phase, and `.scan_as_user` belongs to both
    the ajax spider and the ordinary spider, so the first module-level occurrence
    is some unrelated call and the answer is meaningless.
    """
    scope = _scope(_tree(src), within)
    pos = {}
    for n in ast.walk(scope):
        if not isinstance(n, ast.Call):
            continue
        name = _callee_name(n.func)
        if not name:
            continue
        for want in (first, second):
            if (name == want or name.endswith("." + want)) and want not in pos:
                pos[want] = (n.lineno, n.col_offset)
    if first not in pos or second not in pos:
        return False
    return pos[first] < pos[second]


def ref_order(src: Source, first: str, second: str, *, within: Optional[str] = None) -> bool:
    """Like call_order, but counts a function PASSED BY REFERENCE as a use.

    `_tool(scan_tools.execute_approved_exploit, pid)` never creates a Call node
    for execute_approved_exploit — it hands the function object to a wrapper. A
    call_order() check for it therefore answers False no matter where it sits,
    which reads as "the ordering is violated" when the code is correct.

    Use this for dispatch tables, `_tool(...)`-style wrappers and callbacks; use
    call_order when the thing really is invoked in place.
    """
    scope = _scope(_tree(src), within)
    pos = {}
    for n in ast.walk(scope):
        name = None
        if isinstance(n, ast.Call):
            name = _callee_name(n.func)
        elif isinstance(n, ast.Attribute):
            name = n.attr
        elif isinstance(n, ast.Name):
            name = n.id
        if not name:
            continue
        for want in (first, second):
            if name == want or name.endswith("." + want):
                at = (n.lineno, n.col_offset)
                if want not in pos or at < pos[want]:
                    pos[want] = at
    if first not in pos or second not in pos:
        return False
    return pos[first] < pos[second]


def const_elements(src: Source, name: str) -> Optional[set]:
    """Elements of a module-level set/list/tuple constant, or the KEYS of a dict
    constant. None when the name is not assigned at module level.

    Use this to check a registry (an allowlist, a RENDERERS map) instead of
    asserting a quoted member appears somewhere in the file — which a comment
    mentioning the member would also satisfy.
    """
    tree = _tree(src)
    for n in tree.body:
        if not isinstance(n, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            continue
        v = n.value
        if isinstance(v, (ast.Set, ast.List, ast.Tuple)):
            return {e.value for e in v.elts if isinstance(e, ast.Constant)}
        if isinstance(v, ast.Dict):
            return {k.value for k in v.keys if isinstance(k, ast.Constant)}
    return None


def calls_with(src: Source, callee: str, *, args=(), kwargs=None) -> bool:
    """True if some call to `callee` passes these constant arguments.

    `args` is matched against the leading positional arguments; `kwargs` against
    keyword arguments by name and value. Both are subsets — extra arguments are
    fine, because a guard should describe what must be passed, not freeze the
    whole signature.

        calls_with(src, "_get_setting", args=["web_research.proxy"])
        calls_with(src, "llm_query", kwargs={"task": "web_search"})

    Replaces `'_get_setting("web_research.proxy"' in src`, which breaks the
    moment someone wraps the line or swaps the quote style.
    """
    kwargs = kwargs or {}
    want_args = list(args)
    for name, node in _calls(_tree(src)):
        if not (name == callee or name.endswith("." + callee)):
            continue
        got = [a.value if isinstance(a, ast.Constant) else _MISSING for a in node.args]
        if len(got) < len(want_args) or any(g != w for g, w in zip(got, want_args)):
            continue
        ok = True
        for k, v in kwargs.items():
            kw = next((x for x in node.keywords if x.arg == k), None)
            if kw is None or not isinstance(kw.value, ast.Constant) or kw.value.value != v:
                ok = False
                break
        if ok:
            return True
    return False


def arg_default(src: Source, func: str, arg: str):
    """Default value of a FUNCTION parameter, or `_MISSING`.

    `field_default` covers annotated attributes; this covers
    `def scan(..., do_ajax_spider: bool = False)`. Same reason: a guard about a
    DEFAULT should not also pin the parameter's type annotation.
    """
    for n in ast.walk(_tree(src)):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) or n.name != func:
            continue
        a = n.args
        positional = list(a.posonlyargs) + list(a.args)
        defaults = list(a.defaults)
        # defaults align to the TAIL of the positional list
        offset = len(positional) - len(defaults)
        for i, prm in enumerate(positional):
            if prm.arg == arg and i >= offset:
                d = defaults[i - offset]
                return d.value if isinstance(d, ast.Constant) else _MISSING
        for prm, d in zip(a.kwonlyargs, a.kw_defaults):
            if prm.arg == arg and d is not None:
                return d.value if isinstance(d, ast.Constant) else _MISSING
    return _MISSING


def decorated_routes(src: Source) -> set:
    """Every ``(method, path)`` declared by an @app.<verb>("/path") decorator.

    Replaces `assert '@app.get("/parsers/missing"' in src`, which is satisfied by
    the string appearing in a comment and breaks on a reformat or a change of
    decorator object (`@app` vs `@router`). The decorator OBJECT is ignored on
    purpose — what matters is that the route exists, not what it is registered on.
    """
    out = set()
    for n in ast.walk(_tree(src)):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for d in n.decorator_list:
            if not isinstance(d, ast.Call) or not isinstance(d.func, ast.Attribute):
                continue
            verb = d.func.attr.lower()
            if verb not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            for a in d.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    out.add((verb, a.value))
                    break
    return out


def field_default(src: Source, container: str, field: str):
    """The literal default of an annotated attribute, or `_MISSING`.

    Handles both plain `x: bool = False` and pydantic `x: Optional[bool] =
    Field(False, ...)`. `container` is the class (or function) the attribute
    lives in; pass None for module level.

    Use it for "this must default OFF" style guards. The substring form
    (`"do_ajax_spider: bool = False" in src`) pins the annotation's exact
    spelling, so widening the type to Optional[bool] breaks a test that was only
    ever about the default.
    """
    tree = _tree(src)
    scope = None
    if container:
        for n in ast.walk(tree):
            if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and n.name == container:
                scope = n
                break
        if scope is None:
            return _MISSING
    else:
        scope = tree
    for n in ast.walk(scope):
        if not isinstance(n, ast.AnnAssign) or n.value is None:
            continue
        if not (isinstance(n.target, ast.Name) and n.target.id == field):
            continue
        v = n.value
        # pydantic Field(default, ...) — the default is the first positional arg,
        # or the `default=` keyword
        if isinstance(v, ast.Call):
            fname = _callee_name(v.func) or ""
            if fname.endswith("Field"):
                if v.args and isinstance(v.args[0], ast.Constant):
                    return v.args[0].value
                for kw in v.keywords:
                    if kw.arg == "default" and isinstance(kw.value, ast.Constant):
                        return kw.value.value
                return _MISSING
        if isinstance(v, ast.Constant):
            return v.value
    return _MISSING


class _Missing:
    """Distinct from None, which is a legitimate default."""
    def __repr__(self):
        return "<no default found>"
    def __bool__(self):
        return False


_MISSING = _Missing()


def string_constants(src: Source) -> set:
    """Every string literal in the module — docstrings and comments excluded for
    comments (comments are not in the AST at all). Use when a test must prove a
    specific flag or key is USED, not merely mentioned in prose."""
    return {n.value for n in ast.walk(_tree(src))
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def assigns_const(src: Source, name: str, value) -> bool:
    """True if a module-level `name = <value>` literal assignment exists."""
    for n in _tree(src).body:
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in n.targets):
            if isinstance(n.value, ast.Constant) and n.value.value == value:
                return True
    return False


def function_source(src: Source, name: str) -> Optional[str]:
    """The source segment of one function — for the rare case a test genuinely
    needs to inspect a body, scoped to that function rather than the whole file."""
    text = Path(src).read_text(encoding="utf-8") if isinstance(src, Path) else src
    tree = ast.parse(text)
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.get_source_segment(text, n)
    return None
