/* ==========================================================================
 * site_assets.h -- the static part of the hosted site.
 *
 * The four HTML pages (index, Discussion Hall, Post Office, Curia Regis) and
 * the two text files they fetch are compiled into the program as read-only
 * byte arrays. There is no filesystem on a Pico, so "the website" has to live
 * in the image itself. It sits in .rodata, which is in flash and is read
 * through execute-in-place addressing, so serving a 15 kB page costs no RAM.
 *
 * site_assets.c is GENERATED from the files under Website/. To change a page,
 * edit the .html file and regenerate; never hand-edit site_assets.c.
 * ==========================================================================*/
#ifndef SITE_ASSETS_H
#define SITE_ASSETS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One servable document. `path` is the URL the browser asks for, exactly as
 * it appears in the request line. */
typedef struct
{
    const char *path;         /* e.g. "/Discussion_Hall/Discussion_Hall.html" */
    const char *name;         /* source file name, only used in error messages */
    const char *body;         /* the bytes of the file */
    size_t length;            /* byte count, excluding the NUL terminator */
    const char *content_type; /* what the browser needs to render it */
} site_asset_t;

/* Look a URL path up in the table. Returns NULL when nothing matches, which
 * is what makes site_server.c fall through to the action router. */
const site_asset_t *site_find_asset(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SITE_ASSETS_H */
