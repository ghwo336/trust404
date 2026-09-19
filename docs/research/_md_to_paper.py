#!/usr/bin/env python3
"""Convert the Track 1 research note Markdown to a paper-styled Typst source.

Content is preserved; only structure/markup is translated for typesetting.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

MD_PATH = Path(__file__).with_name("track1-malice-patterns.md")
TYP_PATH = Path(__file__).with_name("track1-malice-patterns.typ")

PREAMBLE = r'''// Auto-generated — formatting only.
#set document(
  title: "@@DOCTITLE@@",
  author: "TRUST404",
  keywords: ("smart contracts", "rug pull", "honeypot", "TRUST404"),
)

#set page(
  paper: "us-letter",
  margin: (top: 1.05in, bottom: 1.0in, left: 1.05in, right: 1.05in),
  header: context {
    if counter(page).get().first() > 1 {
      set text(size: 8.5pt, font: ("Times New Roman", "@@CJKFONT@@"), fill: rgb("#333333"))
      grid(
        columns: (1fr, auto),
        column-gutter: 1em,
        align: (left + horizon, right + horizon),
        text(style: "italic")[@@RUNNING@@],
        text(tracking: 0.6pt)[TRUST404  ·  Track 1],
      )
      v(0.18em)
      line(length: 100%, stroke: 0.4pt + rgb("#222222"))
    }
  },
  footer: context {
    set text(size: 9pt, font: "Times New Roman", fill: rgb("#333333"))
    v(0.12em)
    line(length: 100%, stroke: 0.35pt + rgb("#222222"))
    v(0.28em)
    align(center)[
      #counter(page).display("— 1 —")
    ]
  },
)

#set text(
  font: ("Times New Roman", "STIX Two Text", "@@CJKFONT@@"),
  size: 11pt,
  lang: "@@LANG@@",
  hyphenate: @@HYPHEN@@,
  cjk-latin-spacing: auto,
)

#set par(
  justify: true,
  leading: 0.76em,
  spacing: 0.82em,
  linebreaks: "optimized",
)

#set heading(numbering: none, hanging-indent: 0pt)
#show heading: set block(sticky: true)

#show heading.where(level: 2): it => {
  set text(size: 12.4pt, weight: "bold", font: ("Times New Roman", "@@CJKFONT@@"))
  set par(justify: false, first-line-indent: 0pt)
  block(breakable: false, sticky: true, above: 1.55em, below: 0.62em, {
    it.body
    v(0.18em)
    line(length: 100%, stroke: 0.55pt + rgb("#1a1a1a"))
  })
}

#show heading.where(level: 3): it => {
  set text(size: 11.15pt, weight: "bold", style: "italic", font: ("Times New Roman", "@@CJKFONT@@"))
  set par(justify: false)
  block(breakable: false, sticky: true, above: 1.2em, below: 0.48em, it.body)
}

#set list(
  indent: 0.35em,
  body-indent: 0.55em,
  marker: ([•], [–], [·]),
  spacing: 0.42em,
)
#set enum(
  indent: 0.35em,
  body-indent: 0.55em,
  spacing: 0.42em,
)

#show raw: set text(font: "Courier New", size: 8.85pt)
#show link: set text(fill: rgb("#1a365d"))
#show link: it => underline(stroke: 0.4pt + rgb("#1a365d"), offset: 1.4pt, it)
#show list: block.with(above: 0.5em, below: 1.15em)
#show enum: block.with(above: 0.5em, below: 1.15em)

#let paper-meta(rows) = {
  set text(size: 10pt)
  set par(leading: 0.7em, spacing: 0.2em, justify: false)
  block(
    width: 100%,
    inset: (x: 12pt, y: 10pt),
    fill: rgb("#f6f4ef"),
    stroke: (left: 2.2pt + rgb("#1a1a1a")),
    {
      table(
        columns: (0.88in, 1fr),
        column-gutter: 11pt,
        stroke: none,
        inset: (x: 0pt, y: 3.4pt),
        align: (right + top, left + top),
        ..rows
      )
    },
  )
}

#let bib-entry(head, links, body) = {
  set par(leading: 0.7em, justify: true)
  block(width: 100%, above: 1.0em, below: 0.42em, {
    block(head)
    if links != none {
      block(text(size: 9.3pt, links))
    }
    block(text(size: 10.7pt, body))
  })
}

#let md-quote(body) = {
  set text(size: 10.6pt, style: "italic")
  set par(leading: 0.78em, justify: true)
  block(
    width: 100%,
    above: 0.85em,
    below: 0.85em,
    inset: (left: 14pt, right: 8pt, y: 7pt),
    stroke: (left: 1.8pt + rgb("#555555")),
    body,
  )
}

#let md-table(ncols, headers, rows, colspec: none) = {
  let cols = if colspec != none {
    colspec
  } else if ncols == 2 {
    (1.55in, 1fr)
  } else if ncols == 3 {
    (1.28in, 1fr, 1.22in)
  } else if ncols == 4 {
    (1.38in, 0.72in, 1fr, 1.22in)
  } else {
    (1fr,) * ncols
  }
  set text(size: 8.25pt, hyphenate: false)
  set par(leading: 0.64em, justify: false, spacing: 0.2em)
  block(width: 100%, above: 0.7em, below: 0.75em, breakable: true, {
    table(
      columns: cols,
      align: (x, y) => left + top,
      stroke: none,
      inset: (x: 5.2pt, y: 4.4pt),
      fill: (_, y) => if y == 0 { rgb("#efeee8") } else { none },
      table.hline(stroke: 0.95pt + rgb("#1a1a1a")),
      table.header(..headers.map(h => strong(h))),
      table.hline(stroke: 0.4pt + rgb("#1a1a1a")),
      ..rows.flatten(),
      table.hline(stroke: 0.95pt + rgb("#1a1a1a")),
    )
  })
}
'''


def fill_preamble(lang: str, doc_title: str, running_title: str) -> str:
    cjk = "KoPubBatang" if lang == "ko" else "NanumMyeongjo"
    running = running_title.replace("\\", "\\\\").replace("&", "\\&")
    title = doc_title.replace("\\", "\\\\").replace('"', '\\"')
    return (
        PREAMBLE.replace("@@DOCTITLE@@", title)
        .replace("@@RUNNING@@", running)
        .replace("@@CJKFONT@@", cjk)
        .replace("@@LANG@@", lang)
        .replace("@@HYPHEN@@", "false" if lang == "ko" else "true")
    )


def escape_typst_plain(text: str) -> str:
    """Escape Typst markup in already-processed plain text."""
    return (
        text.replace("\\", "\\\\")
        .replace("#", r"\#")
        .replace("$", r"\$")
        .replace("@", r"\@")
        .replace("<", r"\<")
        .replace(">", r"\>")
        .replace("*", r"\*")
        .replace("_", r"\_")
        .replace("[", r"\[")
        .replace("]", r"\]")
    )


def typst_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def convert_inline(text: str) -> str:
    """Markdown inline → Typst markup. Placeholders avoid nested-escape bugs."""
    codes: list[str] = []
    links: list[tuple[str, str]] = []
    bolds: list[str] = []
    italics: list[str] = []

    def save_code(m: re.Match[str]) -> str:
        codes.append(m.group(1))
        return f"\x00C{len(codes) - 1}\x00"

    text = re.sub(r"`([^`]+)`", save_code, text)

    def save_link(m: re.Match[str]) -> str:
        links.append((m.group(1), m.group(2)))
        return f"\x00L{len(links) - 1}\x00"

    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", save_link, text)

    def save_bold(m: re.Match[str]) -> str:
        bolds.append(m.group(1))
        return f"\x00B{len(bolds) - 1}\x00"

    text = re.sub(r"\*\*(.+?)\*\*", save_bold, text)

    def save_italic(m: re.Match[str]) -> str:
        italics.append(m.group(1))
        return f"\x00I{len(italics) - 1}\x00"

    text = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", save_italic, text)

    text = escape_typst_plain(text)

    def restore_italic(m: re.Match[str]) -> str:
        inner = escape_typst_plain(italics[int(m.group(1))])
        return f"_{inner}_"

    text = re.sub(r"\x00I(\d+)\x00", restore_italic, text)

    def restore_bold(m: re.Match[str]) -> str:
        inner = escape_typst_plain(bolds[int(m.group(1))])
        return f"*{inner}*"

    text = re.sub(r"\x00B(\d+)\x00", restore_bold, text)

    def restore_link(m: re.Match[str]) -> str:
        label, url = links[int(m.group(1))]
        inner = escape_typst_plain(label)
        return f"#link({typst_string(url)})[{inner}]"

    text = re.sub(r"\x00L(\d+)\x00", restore_link, text)

    def restore_code(m: re.Match[str]) -> str:
        code = codes[int(m.group(1))]
        # Soft-wrap ALL_CAPS rule IDs at underscores; keep leading _foo intact.
        if re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9*]+)+", code):
            code = code.replace("_", "_\u200b")
        if "`" in code:
            return "#raw(" + typst_string(code) + ")"
        return "`" + code + "`"

    text = re.sub(r"\x00C(\d+)\x00", restore_code, text)
    return text


def split_table_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def is_sep_row(cells: list[str]) -> bool:
    return all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) is not None for c in cells if c != "")


def collect_list(lines: list[str], start: int) -> tuple[str, int]:
    """Collect a markdown list (possibly nested) into Typst."""
    items: list[tuple[int, str, str]] = []
    i = start
    n = len(lines)
    while i < n:
        raw = lines[i]
        if not raw.strip():
            # peek: if next is still a list item, skip the blank
            j = i + 1
            while j < n and not lines[j].strip():
                j += 1
            if j < n and re.match(r"^\s*(?:[-*] |\d+\. )", lines[j]):
                i += 1
                continue
            break
        m = re.match(r"^(\s*)([-*] |\d+\. )(.*)$", raw)
        if not m:
            # continuation of previous item
            if items and raw.startswith(" "):
                indent, kind, body = items[-1]
                items[-1] = (indent, kind, body + " " + raw.strip())
                i += 1
                continue
            break
        indent = len(m.group(1).replace("\t", "    "))
        kind = "enum" if re.match(r"\d+\. ", m.group(2)) else "list"
        items.append((indent, kind, m.group(3)))
        i += 1

    if not items:
        return "", start

    min_indent = min(ind for ind, _, _ in items)

    def emit(index: int, parent_indent: int, depth: int) -> tuple[str, int]:
        chunks: list[str] = []
        kind = None
        while index < len(items):
            ind, k, body = items[index]
            if ind < parent_indent:
                break
            if ind > parent_indent and kind is not None:
                nested, index = emit(index, ind, depth + 1)
                chunks[-1] = chunks[-1].rstrip() + "\n" + nested
                continue
            if ind != parent_indent:
                break
            if kind is None:
                kind = k
            marker = "+" if kind == "enum" else "-"
            pad = "  " * depth
            chunks.append(f"{pad}{marker} {convert_inline(body)}")
            index += 1
        block = "\n".join(chunks)
        return block + "\n", index

    body, _ = emit(0, min_indent, 0)
    return body + "\n", i


def convert_table(lines: list[str], start: int) -> tuple[str, int]:
    rows: list[list[str]] = []
    i = start
    n = len(lines)
    while i < n and lines[i].strip().startswith("|"):
        cells = split_table_row(lines[i])
        if not is_sep_row(cells):
            rows.append(cells)
        i += 1
    if not rows:
        return "", i
    ncols = max(len(r) for r in rows)
    norm = [r + [""] * (ncols - len(r)) for r in rows]
    header = norm[0]
    data = norm[1:]

    def cell_to_typst(c: str) -> str:
        return "[" + convert_inline(c) + "]"

    headers_typ = ", ".join(cell_to_typst(c) for c in header)
    row_typ = ",\n    ".join(
        "(" + ", ".join(cell_to_typst(c) for c in row) + ")" for row in data
    )
    # Heuristic: 2-col predicate tables want a narrower first column.
    colspec = "none"
    h0 = header[0].strip()
    h0l = h0.lower()
    if ncols == 2 and (h0l in {"predicate", "lookalike"} or h0 in {"술어", "유사 형태"}):
        colspec = "(1.85in, 1fr)"
    elif ncols == 3 and (h0l == "sub-field" or h0 == "하위 분야"):
        colspec = "(1.55in, 1fr, 0.72in)"
    elif ncols == 3 and (h0l == "source" or h0 == "출처"):
        colspec = "(1.22in, 1fr, 1.7in)"
    elif ncols == 3 and ("pattern" in h0l or h0 == "패턴"):
        colspec = "(1.28in, 1fr, 1.22in)"
    elif ncols == 3 and ("lookalike" in h0l or "유사" in h0):
        colspec = "(1.45in, 1fr, 1fr)"
    elif ncols == 4:
        colspec = "(1.72in, 0.92in, 1fr, 1.08in)"

    out = (
        f"#md-table({ncols}, ({headers_typ},), (\n"
        f"    {row_typ},\n"
        f"  ), colspec: {colspec})\n\n"
    )
    return out, i


def convert_document(md: str, lang: str = "en") -> str:
    lines = md.splitlines()
    doc_title = "TRUST404 Track 1"
    for line in lines:
        if line.startswith("# "):
            doc_title = line[2:].strip()
            break
    if lang == "ko":
        running = "악성 컨트랙트 다크 패턴"
        kicker = "[TRUST404 연구 노트]"
        date_line = "[2026년 9월 19일]"
        meta_col = "0.72in"
    else:
        running = "Malicious Contract Dark Patterns: Literature & Taxonomy"
        kicker = "[#smallcaps[Trust404 Research Note]]"
        date_line = "[19 September 2026]"
        meta_col = "0.88in"

    out: list[str] = [fill_preamble(lang, doc_title, running), "\n"]
    # Korean labels are short; keep the meta first-column width in the call site.
    _ = meta_col
    i = 0
    n = len(lines)
    saw_title = False
    meta_done = False

    # Title
    while i < n and not lines[i].startswith("# "):
        i += 1
    if i < n and lines[i].startswith("# "):
        title = lines[i][2:].strip()
        saw_title = True
        i += 1
        # Collect leading metadata bullets
        meta_rows: list[tuple[str, str]] = []
        while i < n:
            if not lines[i].strip():
                i += 1
                continue
            if lines[i].strip() == "---":
                i += 1
                break
            m = re.match(r"^- \*\*([^*]+):\*\*\s*(.*)$", lines[i])
            if m:
                meta_rows.append((m.group(1), m.group(2)))
                i += 1
                continue
            break
        out.append('#align(center)[\n')
        out.append('  #set par(spacing: 0.35em, leading: 0.78em, justify: false)\n')
        out.append('  #text(size: 9pt, tracking: 0.9pt, weight: "bold", fill: rgb("#222222"))')
        out.append(f'{kicker}\n')
        out.append('  #v(0.28em)\n')
        out.append('  #line(length: 42%, stroke: 0.6pt + rgb("#1a1a1a"))\n')
        out.append('  #v(0.62em)\n')
        if ": " in title:
            left, right = title.split(": ", 1)
            title_markup = f"{convert_inline(left)}:#linebreak(){convert_inline(right)}"
        else:
            title_markup = convert_inline(title)
        out.append(f'  #text(size: 16.2pt, weight: "bold", hyphenate: false)[{title_markup}]\n')
        out.append('  #v(0.48em)\n')
        out.append(f'  #text(size: 10.5pt, style: "italic"){date_line}\n')
        out.append(']\n')
        out.append('#v(0.7em)\n\n')
        if meta_rows:
            parts = []
            for label, value in meta_rows:
                parts.append(
                    f'[*{escape_typst_plain(label)}:*], [{convert_inline(value)}],'
                )
            out.append("#paper-meta((\n  " + "\n  ".join(parts) + "\n))\n")
            out.append("#v(0.55em)\n\n")
        meta_done = True

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if stripped == "---":
            i += 1
            continue

        if line.startswith("### "):
            out.append(f"=== {convert_inline(line[4:].strip())}\n\n")
            i += 1
            continue

        if line.startswith("## "):
            out.append(f"== {convert_inline(line[3:].strip())}\n\n")
            i += 1
            continue

        if line.startswith("# "):
            # Should not happen twice; treat as H2 if it does.
            out.append(f"= {convert_inline(line[2:].strip())}\n\n")
            i += 1
            continue

        if stripped.startswith("|"):
            block, i = convert_table(lines, i)
            out.append(block)
            continue

        if stripped.startswith(">"):
            quote_lines = []
            while i < n and lines[i].strip().startswith(">"):
                q = re.sub(r"^>\s?", "", lines[i])
                quote_lines.append(q)
                i += 1
            body = convert_inline(" ".join(s.strip() for s in quote_lines if s.strip()))
            out.append(f"#md-quote[{body}]\n\n")
            continue

        if re.match(r"^(\s*)([-*] |\d+\. )", line):
            block, i = collect_list(lines, i)
            out.append(block + "\n#parbreak()\n")
            continue

        def is_structural(s: str) -> bool:
            st = s.strip()
            if not st:
                return True
            if st == "---" or st.startswith("|") or st.startswith("#") or st.startswith(">"):
                return True
            if re.match(r"^([-*] |\d+\. )", st):
                return True
            return False

        def is_link_only_line(s: str) -> bool:
            return bool(re.match(r"^\[[^\]]+\]\([^)]+\)", s.strip()))

        # Bibliographic entries: bold title · venue, optional link line, then body.
        if re.match(r"^\*\*.+\*\*.*·", stripped):
            head = convert_inline(stripped)
            i += 1
            links_typ = "none"
            if i < n and is_link_only_line(lines[i]):
                links_typ = "[" + convert_inline(lines[i].strip()) + "]"
                i += 1
            body_lines: list[str] = []
            while i < n and not is_structural(lines[i]):
                body_lines.append(lines[i].strip())
                i += 1
            body_typ = (
                "[" + convert_inline(" ".join(body_lines)) + "]"
                if body_lines
                else "[#h(0pt)]"
            )
            out.append(f"#bib-entry([{head}], {links_typ}, {body_typ})\n\n")
            continue

        # Paragraph: join wrapped lines until blank / structural marker
        para = [stripped]
        i += 1
        while i < n:
            nxt = lines[i]
            ns = nxt.strip()
            if is_structural(nxt):
                break
            para.append(ns)
            i += 1
        text = convert_inline(" ".join(para))
        out.append(text + "\n\n")

    _ = saw_title, meta_done
    return "".join(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("md", nargs="?", default=str(MD_PATH))
    parser.add_argument("-o", "--output")
    parser.add_argument("--lang", choices=["en", "ko"])
    args = parser.parse_args()
    md_path = Path(args.md)
    lang = args.lang or ("ko" if ".ko." in md_path.name else "en")
    out_path = Path(args.output) if args.output else md_path.with_suffix(".typ")
    md = md_path.read_text(encoding="utf-8")
    typ = convert_document(md, lang=lang)
    out_path.write_text(typ, encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
