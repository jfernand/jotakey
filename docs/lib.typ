// Diagram helpers for the Jotakey document, in ISSS style.
#import "isss-template.typ": *

// A byte-layout strip: fields = ((name, width-in-bytes-or-label, weight), ...)
// `w` is a relative width (fr) used for drawing; `size` is the printed size.
#let bytefield(caption: none, ..fields) = {
  let fs = fields.pos()
  block(width: 100%, above: 12pt, below: 12pt, breakable: false)[
    #grid(
      columns: fs.map(f => f.at(2) * 1fr),
      gutter: 0pt,
      ..fs.enumerate().map(((i, f)) => block(
        width: 100%, height: 30pt, inset: 4pt,
        fill: if calc.rem(i, 2) == 0 { c-ink } else { c-steel-800 },
        stroke: (right: 0.6pt + c-steel-600),
      )[
        #align(center + horizon)[
          #text(font: font-mono, size: 6.8pt, fill: c-paper, weight: 600)[#f.at(0)] \
          #text(font: font-mono, size: 6pt, fill: brand-primary)[#f.at(1)]
        ]
      ])
    )
    #if caption != none {
      v(3pt)
      label-sm[#caption]
    }
  ]
}

// Sequence diagram: actors and messages (from, to, label); from == to is a local step.
#let sequence(actors, msgs, caption: none) = {
  let n = actors.len()
  let row-h = 24pt
  let lifeline = block(width: 100%, height: row-h, place(center, line(angle: 90deg, length: row-h, stroke: 0.5pt + border-strong)))
  let arrow(txt, fwd, k) = {
    // Start and end on the lifelines: half a column in from each edge of the span.
    let half = 50% / k
    block(width: 100%, height: row-h, {
      for j in range(k) {
        place(left + top, dx: (100% / k) * j + half, line(angle: 90deg, length: row-h, stroke: 0.5pt + border-strong))
      }
      pad(left: half, right: half, top: 2pt)[
        #align(center)[#box(fill: bg-raised, inset: (x: 3pt))[#text(size: 7.2pt)[#txt]]]
        #v(-1pt)
        #grid(
          columns: if fwd { (1fr, auto) } else { (auto, 1fr) },
          align: horizon,
          ..if fwd {
            (line(length: 100%, stroke: 1pt + fg-primary), text(size: 8pt, fill: brand-deep)[#sym.triangle.filled.r])
          } else {
            (text(size: 8pt, fill: brand-deep)[#sym.triangle.filled.l], line(length: 100%, stroke: 1pt + fg-primary))
          }
        )
      ]
    })
  }
  let note(txt) = block(width: 100%, height: row-h, inset: (x: 4pt, y: 3pt))[
    #block(width: 100%, height: 100%, fill: rgb(245, 184, 0, 46), stroke: (left: 2pt + brand-primary), inset: (x: 4pt))[
      #align(center + horizon)[#text(size: 6.8pt)[#txt]]
    ]
  ]
  block(width: 100%, above: 12pt, below: 12pt, breakable: false)[
    #grid(
      columns: (1fr,) * n,
      row-gutter: 0pt,
      ..actors.map(a => block(width: 100%, fill: c-black, inset: 5pt)[
        #align(center)[#label(fill: brand-primary, size: 6.4pt, a)]
      ]),
      ..msgs.map(m => {
        let (a, b, txt) = m
        let lo = calc.min(a, b)
        let hi = calc.max(a, b)
        let cells = range(lo).map(_ => lifeline)
        if a == b {
          cells.push(note(txt))
        } else {
          cells.push(grid.cell(colspan: hi - lo + 1, arrow(txt, b > a, hi - lo + 1)))
        }
        cells + range(hi + 1, n).map(_ => lifeline)
      }).flatten(),
    )
    #if caption != none {
      v(3pt)
      label-sm[#caption]
    }
  ]
}

// A stack of labelled layers (top = first). Each layer: (title, detail, tone)
// tone: "dark" | "amber" | "light"
#let layers(caption: none, ..ls) = {
  block(width: 100%, above: 12pt, below: 12pt, breakable: false)[
    #for l in ls.pos() {
      let (title, detail, tone) = l
      let (bg, fg) = if tone == "dark" { (c-ink, c-paper) } else if tone == "amber" { (brand-primary, c-black) } else { (c-steel-100, c-black) }
      block(width: 100%, fill: bg, inset: (x: 9pt, y: 6pt), below: 2pt)[
        #grid(columns: (34%, 1fr), column-gutter: 10pt,
          text(font: font-display, stretch: 75%, weight: 700, size: 11pt, fill: fg)[#upper(title)],
          text(size: 7.6pt, fill: fg)[#detail])
      ]
    }
    #if caption != none {
      v(3pt)
      label-sm[#caption]
    }
  ]
}

// Pull quote / key statement.
#let keypoint(body) = block(width: 100%, inset: (left: 10pt, y: 4pt), stroke: (left: 2.5pt + brand-primary), above: 12pt, below: 12pt)[
  #text(font: font-display, stretch: 75%, weight: 700, size: 13pt)[#upper(body)]
]
