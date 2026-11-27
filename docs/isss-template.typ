// (c) Javier Fernandez @ JotaSoft 2026
// ============================================================
// INDUSTRIAL STRENGTH SOFTWARE SERVICES — Typst print template
// Ported from colors_and_type.css (ISSSDesignSystem_f35b98)
// ============================================================

// ─── EDITION ───────────────────────────────────────────────
// `ebook` (the default) is the A4 design. `print` is a Lulu paperback, 7 x 10 in with bleed,
// built with `--input edition=print --input print-pages=N` (`scripts/doc-print.sh` and
// print-check set both).
#let edition = sys.inputs.at("edition", default: "ebook")
#assert(edition in ("ebook", "print"), message: "edition must be ebook or print")
#let for-print = edition == "print"
// The value for the ebook, or for the print edition.
#let pv(ebook, print) = if for-print { print } else { ebook }

// ─── RAW COLOR PALETTE ─────────────────────────────────────
// Print: neutrals are black ink only (luma), and the paper is the white sheet.
#let c-black      = pv(rgb("#0E0E0E"), luma(0))
#let c-ink        = pv(rgb("#1A1A1A"), luma(0))
#let c-steel-900  = pv(rgb("#242424"), luma(36))
#let c-steel-800  = pv(rgb("#2E2E2E"), luma(46))
#let c-steel-700  = pv(rgb("#3A3A3A"), luma(58))
#let c-steel-600  = pv(rgb("#4A4A4A"), luma(74))
#let c-steel-500  = pv(rgb("#666666"), luma(102))
#let c-steel-400  = pv(rgb("#888888"), luma(136))
#let c-steel-300  = pv(rgb("#AAAAAA"), luma(170))
#let c-steel-200  = pv(rgb("#CCCCCC"), luma(185))
// Lulu's floor for Standard Color is a 20% tint, so the lightest print grey is luma(204);
// steel-200 sits at luma(185) so it never merges with steel-100 in print.
#let c-steel-100  = pv(rgb("#E5E5E5"), luma(204))
#let c-paper      = pv(rgb("#F0EBE1"), luma(255))
#let c-white      = pv(rgb("#FAFAF8"), luma(255))

#let c-amber-600  = rgb("#C98A00")
#let c-amber-500  = rgb("#E5A000")
#let c-amber-400  = rgb("#F5B800")
#let c-amber-300  = rgb("#FFCC33")
#let c-amber-200  = rgb("#FFE280")
#let c-amber-100  = pv(rgb("#FFF4CC"), rgb("#FFEDB3"))  // print: a 30% yellow tint

#let c-red        = rgb("#CC2200")
#let c-red-light  = rgb("#FF3311")
#let c-green      = rgb("#1A7A3C")
#let c-blue       = rgb("#0A4A7A")

// ─── SEMANTIC (light / print surface) ──────────────────────
#let bg-base         = c-white
#let bg-raised       = c-paper
#let bg-sunken       = rgb("#E8E3D8")
#let fg-primary      = c-black
#let fg-secondary    = c-steel-600
#let fg-muted        = c-steel-400
#let brand-primary   = c-amber-400
#let brand-deep      = c-amber-600
#let border-default  = c-steel-200
#let border-strong   = c-steel-400
// Amber that stays readable as text on white paper.
#let amber-txt       = pv(c-amber-600, rgb("#8F6200"))

// ─── FONT STACKS ───────────────────────────────────────────
#let font-display = "Barlow"          // Barlow Condensed, stretch 75%
#let font-body    = "Space Grotesk"
#let font-mono    = "IBM Plex Mono"
#let font-math    = "DejaVu Math TeX Gyre"

#let PAGE-MARGIN = 20mm

// ─── PRINT GEOMETRY ────────────────────────────────────────
// Lulu's 0.125 in bleed on every side of the 7 x 10 in trim, its 0.5 in safety margin, and
// its gutter for the page count on the spine side.
#let bleed = pv(0mm, 0.125in)
#let print-pages = int(sys.inputs.at("print-pages", default: "0"))
#assert(not for-print or print-pages > 0, message: "print edition needs --input print-pages=N")
#let gutter = if print-pages > 600 { 0.75in } else if print-pages > 400 { 0.625in } else if print-pages > 150 { 0.5in } else if print-pages > 60 { 0.125in } else { 0in }
// The ebook's measure is A4 less its margins. Print keeps 138 mm where the gutter and the
// outside safety margin allow it; the extra 1 mm holds hyphens hung into the margin.
#let text-width = pv(210mm - 2 * PAGE-MARGIN, calc.min(138mm, 7in - 0.5in - gutter - 0.5in - 1mm))
#let page-margin-inside = pv(PAGE-MARGIN, 0.5in + gutter + bleed)
#let page-margin-outside = pv(PAGE-MARGIN, 7in - 0.5in - gutter - text-width + bleed)
#let page-margin-top = 22mm + bleed
#let page-margin-bottom = 20mm + bleed

// ─── TYPE HELPERS ──────────────────────────────────────────

// Display — massive, industrial, condensed
#let display(size: 44pt, fill: fg-primary, body) = text(
  font: font-display, stretch: 75%, weight: 800, size: size,
  fill: fill, tracking: -0.5pt,
)[#upper(body)]

// Label / UI — mono, uppercase, widest tracking
#let label(fill: amber-txt, size: 7pt, body) = text(
  font: font-mono, weight: 500, size: size, fill: fill, tracking: 1.4pt,
)[#upper(body)]

#let label-sm(fill: fg-muted, body) = text(
  font: font-mono, weight: 500, size: 5.8pt, fill: fill, tracking: 1.2pt,
)[#upper(body)]

// Inline code
#let cd(body) = text(font: font-mono, size: 8.2pt, fill: c-ink)[#body]

// ISSS-native emphasis (Space Grotesk ships no italic)
#let key(body) = text(weight: 700, fill: fg-primary)[#body]
#let hot(body) = text(weight: 700, fill: amber-txt)[#body]

// ─── COMPONENTS ────────────────────────────────────────────

// Amber-chipped mono kicker over a heavy rule
#let rule-strong() = line(length: 100%, stroke: 1.6pt + fg-primary)
#let rule-hair()   = line(length: 100%, stroke: 0.5pt + border-default)

// Dark terminal/spec panel for code.
// `body` must be a RAW block (``` fenced ```) so that underscores, angle
// brackets and asterisks in source code are never parsed as markup.
// No global `show raw.where(block: true)` rule exists, precisely so that
// building a raw element in here cannot recurse.
// Not breakable: an algorithm listing that splits across a page boundary
// reads as two fragments. All panels here fit within one page.
#let codepanel(title: none, body) = {
  block(width: 100%, breakable: false, above: 14pt, below: 14pt)[
    #if title != none {
      block(width: 100%, fill: pv(c-black, none), stroke: pv(none, (left: 3pt + brand-primary, bottom: 0.5pt + border-default)),
        inset: (x: pv(10pt, 6pt), y: 6pt), below: 0pt)[
        #label(fill: pv(brand-primary, amber-txt), size: 6.4pt, title)
      ]
    }
    #block(
      width: 100%, fill: pv(c-ink, none), stroke: pv(none, (left: 3pt + brand-primary)),
      // Print: narrower side padding so listings fit the 7 in measure.
      inset: (x: pv(10pt, 6pt), y: 10pt),
      radius: 0pt, breakable: false, above: 0pt,
    )[
      #set text(font: font-mono, size: pv(7.8pt, 7.4pt), fill: pv(c-paper, c-ink))  // print: 0.95x
      #set par(leading: 0.62em, justify: false)
      #body
    ]
  ]
}

// Signal callout — amber (note), red (trap), green (verified), blue (info)
#let callout(kind: "note", title, body) = {
  let accent = if kind == "trap" { c-red }
    else if kind == "ok" { c-green }
    else if kind == "info" { c-blue }
    else { pv(brand-deep, amber-txt) }
  let tint = if kind == "trap" { rgb(204, 34, 0, 16) }
    else if kind == "ok" { rgb(26, 122, 60, 16) }
    else if kind == "info" { rgb(10, 74, 122, 16) }
    else { rgb(245, 184, 0, 34) }
  block(
    width: 100%, fill: pv(tint, none), inset: (x: 11pt, y: 9pt),
    stroke: (left: 2.5pt + accent), radius: 0pt,
    above: 13pt, below: 13pt, breakable: false,
  )[
    #label(fill: accent, size: 6.4pt, title)
    #v(4pt, weak: true)
    #set text(size: 8.6pt)
    #set par(leading: 0.62em)
    #body
  ]
}

// Spec-sheet key/value strip
#let spec(..pairs) = {
  let items = pairs.pos()
  block(width: 100%, above: 10pt, below: 10pt)[
    #table(
      columns: (auto, 1fr),
      stroke: none,
      inset: (x: 0pt, y: 3.4pt),
      column-gutter: 14pt,
      ..items.map(p => (
        label(fill: fg-muted, size: 6.2pt, p.at(0)),
        text(size: 8.4pt, weight: 500)[#p.at(1)],
      )).flatten()
    )
  ]
}

// Data table — black header, mono uppercase heads, steel hairlines
#let dtable(columns: auto, align: auto, head, ..rows) = {
  block(width: 100%, above: 13pt, below: 6pt)[
    #table(
      columns: columns,
      align: align,
      inset: (x: 7pt, y: 5.5pt),
      stroke: (x, y) => (
        top: if y == 0 { pv(none, 1.5pt + fg-primary) } else if y == 1 { 1.2pt + fg-primary }
             else { 0.4pt + border-default },
        bottom: none, left: none, right: none,
      ),
      fill: (x, y) => if y == 0 and not for-print { c-black } else { none },
      // `set text` inside the header too, so that a header cell containing
      // math is shrunk to label size rather than rendering at body size.
      table.header(
        ..head.map(h => {
          set text(size: 6.2pt)
          show math.equation: set text(size: 6.6pt, fill: pv(brand-primary, c-ink))
          label(fill: pv(brand-primary, c-ink), size: 6.2pt, h)
        })
      ),
      // Print: cells are ragged right; justified, the narrower measure's columns open wide gaps.
      ..rows.pos().flatten().map(c => if for-print {
        set par(justify: false)
        text(size: 8.3pt)[#c]
      } else { text(size: 8.3pt)[#c] })
    )
  ]
}

// Numbered equation block
#let eqn(body, tag: none) = {
  block(width: 100%, above: 12pt, below: 12pt)[
    #grid(
      columns: (1fr, auto),
      align: (center + horizon, right + horizon),
      body,
      if tag != none { label(fill: amber-txt, size: 6.8pt)[(#tag)] } else { [] },
    )
  ]
}

// ─── DOCUMENT SHELL ────────────────────────────────────────
#let isss-doc(
  title: "",
  subtitle: "",
  author: "",
  contact: "",
  date: "",
  docid: "",
  running: "",
  copyright: "",
  abstract: none,
  meta: (),
  body,
) = {
  set page(
    width: pv(210mm, 7in + 2 * bleed), height: pv(297mm, 10in + 2 * bleed),
    margin: pv((x: PAGE-MARGIN, top: 22mm, bottom: 20mm), (inside: page-margin-inside,
      outside: page-margin-outside, top: page-margin-top, bottom: page-margin-bottom)),
    fill: pv(bg-raised, none),
    // Print keeps the running head and folio inside Lulu's 0.5 in safety margin.
    header-ascent: pv(30%, 4mm), footer-descent: pv(30%, 4mm),
    header: context {
      if counter(page).get().first() > 1 {
        block(width: 100%)[
          #grid(
            columns: (1fr, auto),
            label(fill: fg-muted, size: 5.8pt, running),
            label(fill: fg-muted, size: 5.8pt, docid),
          )
          #v(3pt, weak: true)
          #line(length: 100%, stroke: 1pt + brand-primary)
        ]
      }
    },
    footer: context {
      block(width: 100%)[
        #line(length: 100%, stroke: 0.5pt + border-default)
        #v(3pt, weak: true)
        #grid(
          columns: (1fr, auto),
          label-sm[#if copyright != "" [#copyright — #date] else [#author — #date]],
          // Zero-pad to two digits. `display("01")` would render page 10
          // as "010", since the pattern repeats rather than widening.
          text(font: font-mono, weight: 600, size: 8pt, fill: fg-primary)[
            #context {
              let n = counter(page).get().first()
              if n < 10 { "0" + str(n) } else { str(n) }
            }
          ],
        )
      ]
    },
  )

  set text(font: font-body, size: 9.4pt, fill: fg-primary, lang: "en")
  set par(justify: true, leading: 0.68em, spacing: 0.95em, first-line-indent: 0pt)
  show math.equation: set text(font: font-math, size: 9.6pt)

  // Links
  show link: it => text(fill: pv(brand-deep, c-ink), weight: 500)[#it]

  // Lists
  set list(indent: 6pt, body-indent: 6pt, spacing: 0.72em)
  set enum(indent: 6pt, body-indent: 6pt, spacing: 0.72em)
  show list.item: it => block(inset: (left: 0pt))[#it]

  // Inline raw
  set raw(theme: "isss-print.tmTheme") if for-print
  show raw.where(block: false): it => box(
    fill: pv(bg-sunken, none), inset: (x: 2.6pt, y: 1pt), outset: (y: 2.4pt), radius: 0pt,
    text(font: font-mono, size: 8.1pt, fill: c-ink)[#it],
  )

  // NOTE: there is deliberately no `show raw.where(block: true)` rule here.
  // Block code always goes through `codepanel`, which wraps a raw element;
  // a global show rule would re-fire on that element. Call it explicitly.

  // Headings
  set heading(numbering: "1.1")
  show heading.where(level: 1): it => {
    block(width: 100%, above: 26pt, below: 12pt, breakable: false)[
      #line(length: 100%, stroke: 2.4pt + fg-primary)
      #v(6pt, weak: true)
      #grid(
        columns: (auto, 1fr),
        column-gutter: 12pt,
        align: (left + top, left + top),
        block(fill: brand-primary, inset: (x: 7pt, y: 4pt))[
          // Zero-pad to two digits without the "010" that display("01")
          // produces once the counter reaches 10.
          #text(font: font-mono, weight: 600, size: 9pt, fill: c-black)[
            #context {
              let n = counter(heading).get().first()
              if n < 10 { "0" + str(n) } else { str(n) }
            }
          ]
        ],
        display(size: 25pt)[#it.body],
      )
    ]
  }
  show heading.where(level: 2): it => block(above: 17pt, below: 8pt, breakable: false)[
    #grid(
      columns: (auto, 1fr),
      column-gutter: 8pt,
      align: (left + horizon, left + horizon),
      label(fill: amber-txt, size: 7.4pt)[#counter(heading).display("1.1")],
      text(font: font-display, stretch: 75%, weight: 700, size: 14.5pt)[
        #upper(it.body)
      ],
    )
    #v(3pt, weak: true)
    #line(length: 100%, stroke: 0.8pt + border-strong)
  ]
  show heading.where(level: 3): it => block(above: 13pt, below: 5pt, breakable: false)[
    #text(font: font-body, weight: 600, size: 10pt)[#it.body]
  ]

  // ── TITLE PAGE ──
  // `pad` with negative offsets (rather than `place`) so the band stays in
  // the layout flow and the abstract below it cannot be overlapped.
  let cover-ink = pv(c-paper, c-ink)
  let cover-sub = pv(c-steel-300, c-steel-600)
  let band = block(
    width: pv(210mm, 100%), fill: pv(c-black, none),
    inset: pv((x: PAGE-MARGIN, top: 26mm, bottom: 18mm), (top: 8mm, bottom: 10mm)),
  )[
    #label(fill: pv(brand-primary, amber-txt), size: 7pt)[Industrial Strength Software Services]
    #v(2pt)
    #label-sm(fill: c-steel-500)[Technical Report · #docid]
    #v(16pt)
    #display(size: 43pt, fill: cover-ink)[#title]
    #v(7pt)
    #line(length: 46%, stroke: 3pt + brand-primary)
    #v(11pt)
    #text(font: font-display, stretch: 75%, weight: 600, size: 16pt, fill: cover-sub)[
      #upper(subtitle)
    ]
    #v(20pt)
    #grid(
      columns: (1fr, 1fr, 1fr),
      column-gutter: 10pt,
      // The credit carries its own role, so its label is hidden; it still holds the baseline.
      [#hide(label-sm[Author]) \ #v(2pt)
       #text(size: 9pt, fill: cover-ink, weight: 500)[#author]],
      ..if contact != "" {
        ([#label-sm(fill: c-steel-500)[Contact] \ #v(2pt)
          #text(font: font-mono, size: 8pt, fill: cover-ink)[#contact]],)
      },
      [#label-sm(fill: c-steel-500)[Issued] \ #v(2pt)
       #text(font: font-mono, size: 8pt, fill: cover-ink)[#date]],
    )
    #if copyright != "" {
      v(14pt)
      label-sm(fill: c-steel-500)[#copyright]
    }
  ]
  if for-print { block(below: 12mm, band) } else { pad(x: -PAGE-MARGIN, top: -22mm, bottom: 12mm, band) }

  if abstract != none {
    block(width: 100%, inset: (left: 0pt))[
      #label(size: 7pt)[Abstract]
      #v(5pt, weak: true)
      #rule-strong()
      #v(7pt, weak: true)
      #set text(size: 9.6pt)
      #set par(leading: 0.7em)
      #abstract
    ]
  }

  v(10pt)
  if meta.len() > 0 {
    label(size: 6.6pt)[Document control]
    v(4pt, weak: true)
    rule-hair()
    spec(..meta)
    rule-hair()
  }

  // The title page stands alone; sections then flow continuously, since the
  // rule + amber number chip already reads as a section break mid-page.
  pagebreak()
  body
  // The print edition's length, for `typst query` (scripts/doc-print.sh picks the gutter).
  if for-print { context [#metadata(counter(page).final().first()) <print-page-count>] }
}
