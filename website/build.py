#!/usr/bin/env python3
"""Bakes template.html into index.html by inlining the IBM Plex font
files (fonts/*.b64) as base64 data URIs. Re-run this after editing
template.html. The font files themselves were fetched once from Google
Fonts and base64-encoded; see README.md in this folder for how to
regenerate them if a weight/style needs to change.
"""
import pathlib

HERE = pathlib.Path(__file__).parent

MAPPING = {
    "__MONO400__": "mono-400.b64",
    "__MONO600__": "mono-600.b64",
    "__MONO700__": "mono-700.b64",
    "__SERIF400__": "serif-400.b64",
    "__SERIF400I__": "serif-400i.b64",
    "__SERIF600__": "serif-600.b64",
}


def main():
    tpl = (HERE / "template.html").read_text(encoding="utf-8")
    for placeholder, fname in MAPPING.items():
        b64 = (HERE / "fonts" / fname).read_text(encoding="utf-8").strip()
        if placeholder not in tpl:
            raise SystemExit(f"missing placeholder {placeholder} in template.html")
        tpl = tpl.replace(placeholder, b64)
    out = HERE / "index.html"
    out.write_text(tpl, encoding="utf-8")
    print(f"wrote {out} ({len(tpl):,} bytes)")


if __name__ == "__main__":
    main()
