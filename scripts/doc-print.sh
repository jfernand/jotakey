#!/usr/bin/env bash
# (c) Javier Fernandez @ JotaSoft 2026
# Build the print edition of the report: a Lulu paperback, 7 x 10 in with 0.125 in bleed.
# Lulu's gutter depends on the page count, and the page count on the gutter, so build until
# the count the template was given is the count it produced (the template exposes it as
# `<print-page-count>`). Usage: scripts/doc-print.sh [OUT.pdf]  (default docs/jotakey-print.pdf)
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-docs/jotakey-print.pdf}
typst_args=(--root . --font-path docs/fonts --ignore-system-fonts --input edition=print)
pages=100
for _ in 1 2 3 4; do
  got=$(typst eval "${typst_args[@]}" --input "print-pages=$pages" --in docs/jotakey.typ \
    'query(<print-page-count>).first().value')
  if [ "$got" = "$pages" ]; then
    typst compile "${typst_args[@]}" --input "print-pages=$pages" docs/jotakey.typ "$out"
    echo "print edition: $pages pages -> $out"
    exit 0
  fi
  pages=$got
done
echo "print edition: page count did not settle (last $pages)" >&2
exit 1
