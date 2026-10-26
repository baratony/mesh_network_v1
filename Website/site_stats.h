/* ==========================================================================
 * site_stats.h -- the live numbers and text the hosted pages show.
 *
 * WHY THIS EXISTS
 * ---------------
 * Website/site_assets.h holds the part of the site that never changes: the
 * pages are compiled into flash. Everything else on the site is a fact about
 * THIS node - how many neighbours it has, whose letters it is holding, how
 * long its RSA key is - and those facts live on the FTP server, which only
 * Core 1 may touch while it owns the radio.
 *
 * So the two cores meet here:
 *
 *   Core 1  writes. It re-reads the ledger files and calls the setters below.
 *   Core 0  reads. While answering a browser it calls site_stats_get() and
 *             never starts an FTP transfer of its own, which is what keeps a
 *             page load from ever being blocked by a file transfer.
 *
 * A value that has never been written simply is not there: site_stats_get()
 * returns NULL and the page shows nothing where it would have shown a
 * placeholder. Nothing in this file invents a number.
 *
 * THE RACE
 * --------
 * Core 1 writes while Core 0 reads, without a lock: a page rendered in the
 * middle of a refresh can show one value from before it and one from after.
 * That is the intended cost - the alternative is holding the network lock
 * across a whole page, and a browser would then wait for a file transfer.
 * ==========================================================================*/
#ifndef SITE_STATS_H
#define SITE_STATS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- sizes ---------------------------------------------------------------
 * The long store is sized like the ledgers themselves (Radio/radio.c caps
 * every text file at 2048 bytes), so a file can always be published whole.
 * The short store holds numbers and addresses, which never need more. */
#define SITE_STATS_NAME_MAX 32
#define SITE_STATS_TEXT_MAX 2048
#define SITE_STATS_TEXT_COUNT 4
#define SITE_STATS_VALUE_MAX 64
#define SITE_STATS_VALUE_COUNT 12

/* --- writing -------------------------------------------------------------
 * Both setters replace an existing name rather than adding a second entry,
 * so calling them once a round is what keeps the tables from filling.
 * A name longer than SITE_STATS_NAME_MAX, or a value that does not fit its
 * store, is refused rather than truncated. */

/* A number, an address, or any short string. */
void site_stats_set(const char *name, const char *value);

/* A whole file, or anything else that can be kilobytes long. */
void site_stats_set_text(const char *name, const uint8_t *text, size_t length);

/* --- reading ---------------------------------------------------------- */

/* Look a name up in either store. Returns NULL when nothing has ever been
 * written for it; otherwise the bytes of the value and, through *length, how
 * many there are. The bytes stay valid until the next write to that name. */
const uint8_t *site_stats_get(const char *name, size_t *length);

#ifdef __cplusplus
}
#endif

#endif /* SITE_STATS_H */
