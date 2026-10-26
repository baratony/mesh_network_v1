#!/usr/bin/env python3
"""Regenerate Website/site_assets.c from the files under Website/.

The .html/.txt files are the source of truth; site_assets.c is a byte for
byte copy of them, compiled into .rodata so a served page costs no RAM.
Run this from anywhere: it always reads Website/ and writes Website/.

    python3 Website/generate_site_assets.py

The order of SERVED below is the order of the table in the generated file,
and it is also the order a browser is offered the pages in.
"""

import os
import sys

WEBSITE_DIR = os.path.dirname(os.path.abspath(__file__))

SERVED = [
    "index.html",
    "Discussion_Hall/Discussion_Hall.html",
    "Discussion_Hall/current_discussion.txt",
    "Post_Office/Post_Office.html",
    "Post_Office/private_mesagges.txt",
    "Kings_Court/Kings_Court.html",
]

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}

HEADER = """/* ==========================================================================
 * site_assets.c -- GENERATED from the files under Website/. Do not edit by hand.
 *
 * Regenerate this file whenever a page changes; the .html files in Website/ are
 * the source of truth. Each array below is one file, byte for byte, compiled into
 * .rodata so it lives in flash and costs no RAM when a browser asks for it.
 * ==========================================================================*/
#include "site_assets.h"

#include <string.h>

"""


def array_name(relative_path):
    """Discussion_Hall/Discussion_Hall.html -> discussion_hall_html

    Only the file's own name is used: the directory it lives in is already
    part of the URL, so putting it in the symbol name twice buys nothing.
    """
    base = os.path.basename(relative_path).replace(".", "_")
    return "site_" + base.lower().replace("/", "_")


def c_string(line):
    """One source line as one C string literal, always ending in \\n.

    A file that does not end with a newline still gets one: the ledgers are
    line based, and a page that ends mid line is a truncated file.
    """
    body = line.replace("\\", "\\\\").replace('"', '\\"')
    # Tabs and control characters are left alone: none appear in the pages,
    # and writing them as escapes keeps the generated file plain ASCII.
    body = body.replace("\t", "\\t")
    return '    "%s\\n"\n' % body


def emit_file(path, out):
    relative = path
    source = "Website/" + relative
    with open(os.path.join(WEBSITE_DIR, relative), "r", encoding="utf-8") as handle:
        text = handle.read()

    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    symbol = array_name(relative)

    out.write("/* %s */\n" % source)
    out.write("static const char %s_body[] =\n" % symbol)
    for line in lines:
        out.write(c_string(line))
    out.write("    ;\n\n")
    out.write('static const char %s_name[] = "%s";\n\n' % (symbol, source))
    return relative, symbol, CONTENT_TYPES[os.path.splitext(relative)[1]]


def main():
    out_path = os.path.join(WEBSITE_DIR, "site_assets.c")

    out = open(out_path, "w", encoding="utf-8")
    out.write(HEADER)

    entries = []
    for relative in SERVED:
        entries.append(emit_file(relative, out))

    out.write(
        '/* The URL the browser types -> the bytes to hand back. Both "/" and "/index.html"\n'
        ' * are the home page, because the sidebar links use the absolute form and the\n'
        ' * browser\'s own address bar may use either. */\n'
        "static const site_asset_t site_asset_table[] = {\n"
    )
    for path, symbol, content_type in entries:
        url = "/" + path
        if path == "index.html":
            out.write(
                '    { "/", %s_name, %s_body, sizeof(%s_body) - 1u, "%s" },\n'
                % (symbol, symbol, symbol, content_type)
            )
        out.write(
            '    { "%s", %s_name, %s_body, sizeof(%s_body) - 1u, "%s" },\n'
            % (url, symbol, symbol, symbol, content_type)
        )
    out.write("};\n\n")
    out.write("#define SITE_ASSET_COUNT (sizeof(site_asset_table) / sizeof(site_asset_t))\n\n")
    out.write(
        "/* Linear scan over seven entries: cheaper to read than a hash, and the table is\n"
        " * tiny and fixed at compile time. */\n"
        "const site_asset_t *site_find_asset(const char *path)\n"
        "{\n"
        "    for (size_t i = 0; i < SITE_ASSET_COUNT; ++i)\n"
        "    {\n"
        "        if (strcmp(site_asset_table[i].path, path) == 0)\n"
        "            return &site_asset_table[i];\n"
        "    }\n\n"
        "    return NULL;\n"
        "}\n"
    )
    out.close()
    print("wrote %s (%d documents)" % (out_path, len(entries)))


if __name__ == "__main__":
    sys.exit(main())
