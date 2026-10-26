/* ==========================================================================
 * site_stats.c -- see site_stats.h.
 * ==========================================================================*/
#include "site_stats.h"

#include <stdio.h>
#include <string.h>

/* --- the two stores ------------------------------------------------------
 * A slot is free while its name is still all NULs; no caller ever passes an
 * empty name, so that is unambiguous. The tables are small and looked up by
 * linear scan: there are a handful of names in the whole program. */

typedef struct
{
    char name[SITE_STATS_NAME_MAX];
    char value[SITE_STATS_VALUE_MAX];
} site_stats_value_t;

typedef struct
{
    char name[SITE_STATS_NAME_MAX];
    size_t length;
    uint8_t text[SITE_STATS_TEXT_MAX];
} site_stats_text_t;

static site_stats_value_t site_values[SITE_STATS_VALUE_COUNT];
static site_stats_text_t site_texts[SITE_STATS_TEXT_COUNT];

/* --- short values ------------------------------------------------------- */

void site_stats_set(const char *name, const char *value)
{
    if (name == NULL || value == NULL || name[0] == '\0')
        return;

    size_t name_length = strlen(name);
    size_t value_length = strlen(value);

    if (name_length >= SITE_STATS_NAME_MAX || value_length >= SITE_STATS_VALUE_MAX)
    {
        printf("[SITE] stat %s does not fit\n", name);
        return;
    }

    site_stats_value_t *slot = NULL;

    for (size_t i = 0; i < SITE_STATS_VALUE_COUNT; ++i)
    {
        if (site_values[i].name[0] == '\0')
        {
            slot = &site_values[i];
            break;
        }

        if (strcmp(site_values[i].name, name) == 0)
        {
            slot = &site_values[i];
            break;
        }
    }

    if (slot == NULL)
    {
        printf("[SITE] no free slot for stat %s\n", name);
        return;
    }

    /* A slot being reused keeps the old name, which is what makes the
     * lookup above find it again. */
    if (slot->name[0] == '\0')
    {
        memcpy(slot->name, name, name_length);
        slot->name[name_length] = '\0';
    }

    memcpy(slot->value, value, value_length);
    slot->value[value_length] = '\0';
}

/* --- long text ---------------------------------------------------------- */

void site_stats_set_text(const char *name, const uint8_t *text, size_t length)
{
    if (name == NULL || name[0] == '\0')
        return;

    if (text == NULL || length > SITE_STATS_TEXT_MAX)
    {
        printf("[SITE] text %s is too long (%u bytes)\n", name, (unsigned)length);
        return;
    }

    if (strlen(name) >= SITE_STATS_NAME_MAX)
    {
        printf("[SITE] text name %s is too long\n", name);
        return;
    }

    site_stats_text_t *slot = NULL;

    for (size_t i = 0; i < SITE_STATS_TEXT_COUNT; ++i)
    {
        if (site_texts[i].name[0] == '\0')
        {
            slot = &site_texts[i];
            break;
        }

        if (strcmp(site_texts[i].name, name) == 0)
        {
            slot = &site_texts[i];
            break;
        }
    }

    if (slot == NULL)
    {
        printf("[SITE] no free slot for text %s\n", name);
        return;
    }

    if (slot->name[0] == '\0')
    {
        size_t name_length = strlen(name);
        memcpy(slot->name, name, name_length);
        slot->name[name_length] = '\0';
    }

    if (text != NULL && length > 0)
        memcpy(slot->text, text, length);

    slot->length = length;
}

/* --- reading ------------------------------------------------------------ */

const uint8_t *site_stats_get(const char *name, size_t *length)
{
    if (name == NULL || name[0] == '\0')
        return NULL;

    for (size_t i = 0; i < SITE_STATS_TEXT_COUNT; ++i)
    {
        if (site_texts[i].name[0] != '\0' && strcmp(site_texts[i].name, name) == 0)
        {
            if (length != NULL)
                *length = site_texts[i].length;
            return site_texts[i].text;
        }
    }

    for (size_t i = 0; i < SITE_STATS_VALUE_COUNT; ++i)
    {
        if (site_values[i].name[0] != '\0' && strcmp(site_values[i].name, name) == 0)
        {
            if (length != NULL)
                *length = strlen(site_values[i].value);
            return (const uint8_t *)site_values[i].value;
        }
    }

    return NULL;
}
