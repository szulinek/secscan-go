# LH.pl Report Style

## Palette

Use the palette from `assets/brand/lh-colors.json`:

- Primary: `#003C7E` for report headers, brand marks, table headers, and high-emphasis accents.
- Secondary: `#00AEEF` for subtle highlights, score accents, and non-critical informational emphasis.
- Success: `#16A34A` for passing states and healthy scores.
- Warning: `#F59E0B` for medium-risk warnings and attention states.
- Danger: `#DC2626` for critical/high-risk failures.
- Text: `#111827` for primary copy.
- Muted: `#667085` for metadata, labels, and secondary copy.
- Background: `#F5F7FA` for screen backgrounds.
- Surface: `#FFFFFF` for cards and printable panels.
- Border: `#E5E7EB` for separators and card outlines.

## Layout

- Keep reports single-file HTML with inline CSS and no JavaScript.
- Use a constrained page width, generous section spacing, and readable line lengths.
- Start reports with a product-like cover containing the `LH.pl` text mark, report name, score, risk grade when available, host/IP, and generation date.
- Use clear section headings and compact metadata cards for scanability.
- Keep tables dense but calm: left-aligned text, small uppercase headers, and enough padding for PDF readability.

## Cards

- Cards use white surfaces, 8px radius, thin borders, and a restrained shadow on screen.
- Avoid nesting decorative cards inside cards.
- Use card groups for summaries, findings, host sections, module summaries, and compare panels.
- Ensure cards have `page-break-inside: avoid` / `break-inside: avoid` so PDF output does not split important content mid-card.

## Severity And Status

- Critical/high: danger red accents.
- Medium/warn: warning amber accents.
- Low/info: secondary blue accents.
- Pass/success: success green accents.
- Badges should be compact, uppercase, high-contrast, and consistent across single, batch, and compare reports.

## Print And PDF Rules

- PDF output must remain readable in `wkhtmltopdf` and Chromium-based renderers.
- Do not rely on external fonts, network assets, JavaScript, or large binary files.
- In print, force a white background, remove shadows, preserve borders, and avoid splitting cards/tables where possible.
- Keep contrast high enough for grayscale printouts.

## Avoid

- Do not add decorative image assets unless they are small, local, and necessary.
- Do not add external CSS, scripts, analytics, web fonts, or remote images.
- Do not use large gradients, low-contrast text, oversized decorative shapes, or marketing-heavy layouts that obscure findings.
- Do not change audit logic, JSON models, scoring, CLI behavior, or module checks as part of styling changes.
