# Fonts

The fonts the document is set in, so every build (local or CI) produces the same PDF:
`typst compile --font-path docs/fonts --ignore-system-fonts …` (`just doc`, `just doc-print`).

| Family | Files | Licence |
|---|---|---|
| Barlow Condensed | `BarlowCondensed-*.ttf` | SIL Open Font License 1.1, `BarlowCondensed-OFL.txt` |
| Space Grotesk | `SpaceGrotesk-*.ttf` | SIL Open Font License 1.1, `SpaceGrotesk-OFL.txt` |
| IBM Plex Mono | `IBMPlexMono-*.ttf` | SIL Open Font License 1.1 (Reserved Font Name "Plex"), `IBMPlexMono-OFL.txt` |
| DejaVu Math TeX Gyre | `DejaVuMathTeXGyre.ttf` | Bitstream Vera licence (DejaVu changes public domain), `DejaVuMathTeXGyre-LICENSE.txt` |

The licence texts come from the families' upstream distributions (google/fonts for the OFL
fonts, Debian's fonts-dejavu-extra for DejaVu). The fonts are unmodified.
