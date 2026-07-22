# Ondris website

Single self-contained static page (`index.html`), no build tooling required
to serve it — deploy that one file as-is.

## Editing

`index.html` is generated from `template.html` by inlining the fonts in
`fonts/*.b64` as base64 `@font-face` data URIs (kept out of `template.html`
directly so the source stays readable). To make a change:

1. Edit `template.html`.
2. Run `python3 build.py` from this directory.
3. Commit both `template.html` and the regenerated `index.html`.

## Regenerating the fonts

The `fonts/*.b64` files are IBM Plex Mono (400/600/700) and IBM Plex Serif
(400/400 italic/600), Latin subset only, fetched once from Google Fonts and
base64-encoded so the page has zero external requests at runtime. To
refresh them:

```bash
curl -s -A "Mozilla/5.0" \
  "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=IBM+Plex+Serif:ital,wght@0,400;0,600;1,400&display=swap" \
  -o plex.css
# extract the "latin" (not latin-ext) woff2 URL for each weight/style from
# plex.css, download each, then: base64 -w 0 file.woff2 > fonts/name.b64
```

## Live network stats

The hero's stat strip fetches `http://51.89.226.44:8080/chain/info`
client-side (CORS-enabled on the node). If that testnet seed is offline or
unreachable, the stats fall back to `n/a` — the page never blocks on it.
