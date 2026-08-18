#!/usr/bin/env python3
"""Validate the FuguOracle specification.

The script validates:
  - the links (relative targets and fragments resolve),
  - the anchors (unit anchors precede a heading and carry the document code),
  - the register (one STATUS.md row per unit, valid states, valid notes),
  - the rule definitions (bold-lead list items, unique numbers, correct prefix),
  - the citations (unit, rule, and decision IDs resolve to a definition),
  - the phase lint ("Done by" values name a roadmap phase).

Exit status is 0 when the specification is consistent, 1 otherwise.
"""

import re
import sys
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "spec"
META_DOCS = {"CLAUDE.md", "index.md", "decisions.md", "roadmap.md", "STATUS.md"}
STATES = {"open", "partial", "done", "n-a"}
DASH = "—"

ANCHOR_RE = re.compile(r'<a id="([a-z0-9-]+)"></a>')
RULE_RE = re.compile(r"^\s*-\s+\*\*([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\*\*\s+" + DASH)
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")

errors = []


def err(where, message):
    errors.append(f"{where}: {message}")


def read(path):
    return path.read_text(encoding="utf-8")


def strip_fences(text):
    """Blank out fenced code blocks, and keep the line count."""
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append("")
            continue
        out.append("" if fenced else line)
    return out


def slugify(heading):
    """GitHub-style heading slug, simplified."""
    slug = heading.strip().lower()
    slug = re.sub(r"[^\w\s-]", "", slug, flags=re.UNICODE)
    return re.sub(r"\s+", "-", slug).strip("-")


def table_rows(lines, section):
    """Yield the cell lists of the first table after the given heading."""
    in_section = False
    started = False
    for line in lines:
        if HEADING_RE.match(line):
            if in_section and started:
                return
            in_section = HEADING_RE.match(line).group(1).strip() == section
            continue
        if not in_section or not line.strip().startswith("|"):
            if started:
                return
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(set(c) <= {"-", " ", ":"} for c in cells):
            started = True
            continue
        if started:
            yield cells


def first_table_rows(lines):
    """Yield the cell lists of the first table in the file."""
    started = False
    for line in lines:
        if not line.strip().startswith("|"):
            if started:
                return
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(set(c) <= {"-", " ", ":"} for c in cells):
            started = True
            continue
        if started:
            yield cells


def parse_documents():
    """Read the document table of index.md: code -> file name."""
    lines = strip_fences(read(SPEC / "index.md"))
    docs = {}
    for cells in table_rows(lines, "Specification documents"):
        if len(cells) < 2:
            continue
        code = cells[0]
        m = LINK_RE.search(cells[1])
        if not re.fullmatch(r"[A-Z]{2,6}", code) or not m:
            err("index.md", f"bad document row: {cells}")
            continue
        docs[code] = m.group(1)
    if not docs:
        err("index.md", "no document table found")
    return docs


def parse_units(docs):
    """Collect units and rules from every topic document."""
    units = {}   # UNIT-ID -> doc file
    rules = {}   # RULE-ID -> UNIT-ID
    anchors = {} # file -> set of anchor ids
    for code, fname in sorted(docs.items()):
        path = SPEC / fname
        if not path.is_file():
            err("index.md", f"document {fname} does not exist")
            continue
        lines = strip_fences(read(path))
        anchors[fname] = set()
        current = None
        for i, line in enumerate(lines):
            m = ANCHOR_RE.search(line)
            if m:
                aid = m.group(1)
                anchors[fname].add(aid)
                if not aid.startswith(code.lower() + "-"):
                    err(fname, f'anchor "{aid}" does not start with "{code.lower()}-"')
                nxt = next((l for l in lines[i + 1:] if l.strip()), "")
                if not HEADING_RE.match(nxt):
                    err(fname, f'anchor "{aid}" does not precede a heading')
                unit = aid.upper()
                if unit in units:
                    err(fname, f"duplicate unit {unit}")
                units[unit] = fname
                current = unit
                continue
            if HEADING_RE.match(line) and current:
                nxt_anchor = next(
                    (l for l in lines[i + 1:] if l.strip()), "")
                # A heading ends the current unit unless it is the unit's
                # own heading, which directly follows the anchor.
                prev = next((l for l in reversed(lines[:i]) if l.strip()), "")
                if not ANCHOR_RE.search(prev):
                    current = None
            rm = RULE_RE.match(line)
            if rm:
                rid = rm.group(1)
                if current is None:
                    err(fname, f"rule {rid} sits outside every unit")
                    continue
                if not re.fullmatch(re.escape(current) + r"-\d+", rid):
                    err(fname, f"rule {rid} does not extend unit {current}")
                    continue
                if rid in rules:
                    err(fname, f"duplicate rule {rid}")
                rules[rid] = current
        if not anchors[fname]:
            err(fname, "document has no unit anchors")
    return units, rules, anchors


def parse_phases():
    lines = strip_fences(read(SPEC / "roadmap.md"))
    phases = set()
    for cells in first_table_rows(lines):
        if cells and re.fullmatch(r"P\d+", cells[0]):
            phases.add(cells[0])
    if not phases:
        err("roadmap.md", "no phase table found")
    return phases


def parse_decisions():
    lines = strip_fences(read(SPEC / "decisions.md"))
    ids = set()
    for cells in first_table_rows(lines):
        if cells and re.fullmatch(r"D-\d{2}", cells[0]):
            ids.add(cells[0])
    if not ids:
        err("decisions.md", "no decision table found")
    return ids


def check_register(units, phases):
    lines = strip_fences(read(SPEC / "STATUS.md"))
    seen = set()
    for cells in table_rows(lines, "Units"):
        if len(cells) != 4:
            err("STATUS.md", f"unit row needs 4 cells: {cells}")
            continue
        m = re.search(r"\[([A-Z0-9-]+)\]", cells[0])
        unit = m.group(1) if m else cells[0]
        state, done_by, note = cells[1], cells[2], cells[3]
        if unit in seen:
            err("STATUS.md", f"duplicate register row for {unit}")
        seen.add(unit)
        if unit not in units:
            err("STATUS.md", f"register row for unknown unit {unit}")
            continue
        if state not in STATES:
            err("STATUS.md", f"{unit}: unknown state \"{state}\"")
        if state == "n-a":
            if done_by not in ("", DASH):
                err("STATUS.md", f"{unit}: an n-a unit has no \"Done by\" value")
        elif done_by not in phases:
            err("STATUS.md", f"{unit}: \"Done by\" value \"{done_by}\" is not a phase")
        if state == "done" and "](" not in note:
            err("STATUS.md", f"{unit}: a done note needs a link to code or tests")
        if state == "partial" and note in ("", DASH):
            err("STATUS.md", f"{unit}: a partial note must name each absent part")
    for unit in sorted(units):
        if unit not in seen:
            err("STATUS.md", f"unit {unit} has no register row")
    # Retired IDs must not collide with live units.
    for cells in table_rows(lines, "Retired IDs"):
        if cells and cells[0] in units:
            err("STATUS.md", f"retired ID {cells[0]} still exists as a unit")
    # Code roots must name known documents.
    known = {p.name for p in SPEC.glob("*.md")}
    for cells in table_rows(lines, "Code roots"):
        if cells and cells[0] not in known:
            err("STATUS.md", f"code root row names unknown document {cells[0]}")


def check_links(anchors):
    """Every relative link in spec/*.md resolves, fragment included."""
    heading_slugs = {}
    for path in SPEC.glob("*.md"):
        slugs = set()
        for line in strip_fences(read(path)):
            hm = HEADING_RE.match(line)
            if hm:
                slugs.add(slugify(hm.group(1)))
        heading_slugs[path.name] = slugs
        for m in ANCHOR_RE.finditer(read(path)):
            heading_slugs[path.name].add(m.group(1))
    for path in SPEC.glob("*.md"):
        for line in strip_fences(read(path)):
            for m in LINK_RE.finditer(line):
                target = m.group(1)
                if re.match(r"[a-z]+://", target) or target.startswith("mailto:"):
                    continue
                frag = None
                if "#" in target:
                    target, frag = target.split("#", 1)
                base = path if target == "" else (path.parent / target)
                if target and not base.exists():
                    err(path.name, f"broken link to {target}")
                    continue
                if frag and base.suffix == ".md":
                    if frag not in heading_slugs.get(base.name, set()):
                        err(path.name, f"broken fragment {base.name}#{frag}")


def check_citations(docs, units, rules, decisions):
    """Every ID-shaped token with a known document code resolves."""
    token_re = re.compile(r"\b([A-Z]{2,6}(?:-[A-Z0-9]+)+)\b")
    for path in SPEC.glob("*.md"):
        if path.name == "CLAUDE.md":
            continue
        for line in strip_fences(read(path)):
            for m in token_re.finditer(line):
                token = m.group(1)
                code = token.split("-", 1)[0]
                if code not in docs:
                    continue
                if token in units or token in rules:
                    continue
                base = re.sub(r"-\d+$", "", token)
                if base in units:
                    err(path.name, f"citation {token} names no defined rule")
                else:
                    err(path.name, f"citation {token} names no defined unit")
            for m in re.finditer(r"\bD-\d{2}\b", line):
                if m.group(0) not in decisions:
                    err(path.name, f"citation {m.group(0)} names no decision")


def main():
    docs = parse_documents()
    # Every non-meta document in spec/ must sit in the document table.
    listed = set(docs.values())
    for path in sorted(SPEC.glob("*.md")):
        if path.name not in META_DOCS and path.name not in listed:
            err(path.name, "document is not in the document table of index.md")
    units, rules, anchors = parse_units(docs)
    phases = parse_phases()
    decisions = parse_decisions()
    check_register(units, phases)
    check_links(anchors)
    check_citations(docs, units, rules, decisions)
    if errors:
        for e in errors:
            print(f"spec-check: {e}", file=sys.stderr)
        print(f"spec-check: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print(
        f"spec-check: OK ({len(docs)} documents, {len(units)} units, "
        f"{len(rules)} rules, {len(decisions)} decisions, {len(phases)} phases)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
