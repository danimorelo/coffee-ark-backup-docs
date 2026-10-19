#!/usr/bin/env python3
"""Local structural and privacy-hygiene checks; not semantic/legal acceptance."""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PAGES = {"index.html", "privacy.html", "terms.html"}
FILES = PAGES | {"styles.css", ".nojekyll"}
FORBIDDEN_TAGS = {"script", "iframe", "frame", "frameset", "form", "input", "button", "select", "textarea", "object", "embed", "video", "audio", "canvas", "img", "svg", "style", "base", "template"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


def check(condition, message):
    if not condition:
        raise ValueError(message)


class Page(HTMLParser):
    def __init__(self, name):
        super().__init__(convert_charrefs=True)
        self.name, self.stack, self.ids, self.links = name, [], set(), []
        self.counts, self.current, self.nav_links = {}, [], []
        self.title, self.viewport, self.lang, self.doctype = "", False, False, False
    def handle_decl(self, declaration):
        check(declaration.lower() == "doctype html", self.name + ": unexpected declaration")
        self.doctype = True
    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        check(len(attrs) == len(pairs), self.name + ": duplicate attribute")
        self.counts[tag] = self.counts.get(tag, 0) + 1
        check(tag not in FORBIDDEN_TAGS, self.name + ": forbidden element")
        check(not any(k.startswith("on") or k in {"hidden", "style", "srcdoc", "inert", "contenteditable"} for k in attrs), self.name + ": unsafe or hidden attributes")
        check(attrs.get("aria-hidden") not in {"true", "1"}, self.name + ": hidden content")
        if tag == "html":
            self.lang = attrs.get("lang") == "en"
        if tag == "meta":
            check("http-equiv" not in attrs, self.name + ": active meta directive")
            if attrs.get("name") == "viewport":
                self.viewport = attrs.get("content") == "width=device-width, initial-scale=1"
        if "id" in attrs:
            check(attrs["id"] not in self.ids, self.name + ": duplicate id")
            self.ids.add(attrs["id"])
        if tag == "link":
            check(attrs.get("rel") == "stylesheet" and attrs.get("href") == "styles.css", self.name + ": unexpected resource")
        if tag not in {"a", "link"}:
            check(not any(k in attrs for k in ("href", "src", "srcset", "action", "poster", "data")), self.name + ": unexpected resource attribute")
        for key in ("href", "src"):
            if key in attrs:
                self.links.append(attrs[key])
        if tag == "a" and "nav" in self.stack:
            self.nav_links.append(attrs.get("href"))
            if "aria-current" in attrs:
                check(attrs["aria-current"] == "page", self.name + ": invalid current marker")
                self.current.append(attrs.get("href"))
        if tag not in VOID:
            self.stack.append(tag)
    def handle_endtag(self, tag):
        check(bool(self.stack) and self.stack[-1] == tag, self.name + ": invalid HTML nesting")
        self.stack.pop()
    def handle_data(self, data):
        if self.stack and self.stack[-1] == "title":
            self.title += data
    def finish(self):
        check(self.doctype and self.lang and self.viewport and self.title.strip(), self.name + ": missing document metadata")
        check(not self.stack, self.name + ": unclosed element")
        for tag in ("html", "head", "body", "title", "main", "h1", "nav"):
            check(self.counts.get(tag) == 1, self.name + ": requires exactly one " + tag)
        check(self.current == [self.name] and set(self.nav_links) == PAGES and len(self.nav_links) == 3, self.name + ": incomplete current navigation")


def private_hygiene(text):
    patterns = {
        "contact email": r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}",
        "private host": r"(?:tailscale|\.ts\.net|localhost|127\.0\.0\.1|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)",
        "local path": r"(?:/Users/|/home/|\.config/|\.pgpass|\.agekey)",
        "credential": r"(?:AGE-SECRET-KEY-|-----BEGIN|ya29\.|1//[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{15,}|AIza[A-Za-z0-9_-]{20,}|client_secret\s*[:=]|refresh_token\s*[:=])",
        "private identifier": r"(?:\b[a-z0-9]{20}\b|\b[A-Za-z0-9_-]{28,}\b|\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b)",
        "private IP": r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b",
    }
    for description, pattern in patterns.items():
        check(not re.search(pattern, text, re.I), "public content contains " + description)


def main():
    try:
        check(DOCS.is_dir() and not DOCS.is_symlink(), "missing regular docs directory")
        check({p.name for p in DOCS.iterdir()} == FILES, "unexpected docs inventory")
        check(all(p.is_file() and not p.is_symlink() for p in DOCS.iterdir()), "nonregular public file")
        check((DOCS / ".nojekyll").read_bytes() == b"", ".nojekyll must be empty")
        parsed = {}
        for name in sorted(PAGES):
            source = (DOCS / name).read_text(encoding="utf-8")
            private_hygiene(source)
            page = Page(name); page.feed(source); page.close(); page.finish()
            parsed[name] = page
        for page in parsed.values():
            for link in page.links:
                value = urlsplit(link)
                check(not value.scheme and not value.netloc and not value.query and not link.startswith(("/", "\\")), page.name + ": nonlocal link")
                decoded = unquote(value.path)
                check("\\" not in decoded and not any(p == ".." for p in decoded.split("/")), page.name + ": escaping link")
                target = (DOCS / (decoded or page.name)).resolve()
                check(target.parent == DOCS.resolve() and target.name in FILES and target.is_file(), page.name + ": broken local link")
                if value.fragment:
                    check(target.name in parsed and value.fragment in parsed[target.name].ids, page.name + ": broken fragment")
        css = (DOCS / "styles.css").read_text(encoding="utf-8")
        private_hygiene(css)
        check(not re.search(r"(?:@import|url\s*\(|expression\s*\(|javascript:|\\[0-9a-f]{1,6}|/\*)", css, re.I), "external/obfuscated CSS")
        check(not re.search(r"(?:display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse)|opacity\s*:\s*0(?:[;\s}]|\.0)|font-size\s*:\s*0|color\s*:\s*transparent|clip\s*:|clip-path\s*:|text-indent\s*:\s*-|position\s*:\s*(?:absolute|fixed)|(?<![-\w])content\s*:)", css, re.I), "dangerous hidden CSS")
        check("focus-visible" in css and "@media" in css, "missing keyboard focus/mobile styles")
        print("PASS: 3 HTML pages; exact 5-file public inventory; local links/assets; structure, navigation, hidden-content and privacy-hygiene checks.")
        print("Semantic/legal review remains independent; this check does not authorize publication.")
        return 0
    except ValueError as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    except Exception:
        print("FAIL: static site checks failed; inspect the local source before publishing.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
