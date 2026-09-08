#!/usr/bin/env python3
"""Deterministic upstream CSS extraction + namespacing (07-02).

Reads the immutable vendored originals under fixtures/upstream-ui/original/,
extracts the upstream CSS (linked stylesheets or inline <style> blocks), and
emits Next-importable scoped stylesheets under web/src/app/upstream-css/.

Every selector is prefixed with a per-page scope class (`.up-<scope>`) so
upstream presentation cannot leak into the retained internal UI:
- `:root`/`html`/`body` -> `.<scope>`
- `*`                   -> `.<scope>, .<scope> *`
- everything else       -> `.<scope> <selector>` (each comma compound prefixed)

Keyframes blocks are copied without selector rewriting. The transform is pure
and deterministic; tests compare the committed output byte-for-byte.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ORIGINALS = REPO_ROOT / "fixtures" / "upstream-ui" / "original"
OUT_DIR = REPO_ROOT / "web" / "src" / "app" / "upstream-css"

# (scope class, source kind, source path)
SOURCES: list[tuple[str, str, str]] = [
    ("up-main", "link", "UI/메인페이지.css"),
    ("up-start", "style", "UI/기능.html"),
    ("up-quiz", "style", "UI/취향테스트.html"),
    ("up-photo", "style", "UI/사진 기능.html"),
    ("up-etc", "link", "UI/기타.css"),
]


def extract_css(kind: str, rel_path: str) -> str:
    data = (ORIGINALS / rel_path).read_text(encoding="utf-8")
    if kind == "link":
        return data
    blocks = re.findall(r"<style>(.*?)</style>", data, flags=re.DOTALL)
    if len(blocks) != 1:
        raise ValueError(f"expected exactly one <style> block in {rel_path}, got {len(blocks)}")
    return blocks[0]


@dataclass
class Node:
    header: str  # selector or at-rule prelude ("" for root)
    at: bool = False
    keyframes: bool = False
    body: str = ""  # declarations for plain rules
    children: list["Node"] = field(default_factory=list)


def parse_block(css: str, start: int) -> tuple[Node, int]:
    """Parse one rule/at-rule starting at `start` (which points at its header)."""
    brace = css.index("{", start)
    header = css[start:brace].strip()
    if header.startswith("@keyframes") or header.startswith("@-webkit-keyframes"):
        depth = 1
        cursor = brace + 1
        while depth > 0:
            char = css[cursor]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            cursor += 1
        return Node(header=header, keyframes=True, body=css[brace + 1 : cursor - 1]), cursor
    if header.startswith("@"):
        children: list[Node] = []
        cursor = brace + 1
        while True:
            while cursor < len(css) and css[cursor] in " \t\r\n":
                cursor += 1
            if css[cursor] == "}":
                return Node(header=header, at=True, children=children), cursor + 1
            child, cursor = parse_block(css, cursor)
            children.append(child)
    close = css.index("}", brace)
    return Node(header=header, body=css[brace + 1 : close].strip()), close + 1


def parse(css: str) -> list[Node]:
    nodes: list[Node] = []
    cursor = 0
    while cursor < len(css):
        while cursor < len(css) and css[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= len(css):
            break
        node, cursor = parse_block(css, cursor)
        nodes.append(node)
    return nodes


def prefix_selector(selector: str, scope: str) -> str:
    selector = selector.strip()
    if selector in {":root", "html", "body"}:
        return f".{scope}"
    if selector == "*":
        return f".{scope}, .{scope} *"
    compounds = [part.strip() for part in selector.split(",")]
    return ", ".join(f".{scope} {part}" for part in compounds)


def render(nodes: list[Node], scope: str, depth: int) -> list[str]:
    indent = "  " * depth
    lines: list[str] = []
    for node in nodes:
        if node.keyframes:
            lines.append(f"{indent}{node.header}{{{node.body}}}")
        elif node.at:
            lines.append(f"{indent}{node.header}{{")
            lines.extend(render(node.children, scope, depth + 1))
            lines.append(f"{indent}}}")
        else:
            selector = prefix_selector(node.header, scope)
            lines.append(f"{indent}{selector}{{{node.body}}}")
    return lines


def scope_css(css: str, scope: str) -> str:
    return "\n".join(render(parse(css), scope, 0)) + "\n"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for scope, kind, rel_path in SOURCES:
        css = extract_css(kind, rel_path)
        scoped = scope_css(css, scope)
        (OUT_DIR / f"{scope}.css").write_text(scoped, encoding="utf-8")
        print(f"{scope}.css  <-  {rel_path}  ({len(scoped)} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
