/* ==========================================================================
 * site_actions.h -- what the buttons on the hosted site actually DO.
 *
 * Every interactive control in the HTML (a "Send" button, a "Reset Node"
 * button, a folder switch, ...) is rewritten to issue an HTTP request to this
 * node:
 *
 *     GET  /action/<name>?<args>          (short arguments go in the query)
 *     POST /action/<name>?<args>          (a long body goes in the POST body)
 *
 * site_server.c parses the request and calls the matching handler below. The
 * implementations live in mesh_network_v1.c, next to the packet handlers, so
 * a button can do anything the node can do: send a packet, change an output,
 * rebuild a key, restart itself.
 *
 * The argument strings are NOT NUL-terminated C strings handed to you as
 * separate allocations: they are decoded (percent-unescaped, '+' -> space)
 * into fixed static buffers owned by site_server.c. They are always valid,
 * always NUL-terminated, and never longer than the limits documented here.
 * ==========================================================================*/
#ifndef SITE_ACTIONS_H
#define SITE_ACTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

/* --- Discussion Hall -----------------------------------------------------
 * The "Send" button in the compose window.
 * message: up to 200 characters, as typed by the visitor.
 */
void site_action_discussion_send(const char *message);

/* --- Post Office ---------------------------------------------------------
 * The "Send" button of the compose form.
 * recipient: up to 100 characters, the addressee as typed.
 * message:   up to 1400 characters of letter body (the POST body).
 */
void site_action_post_send(const char *recipient, const char *message);

/* The "Refresh" button: re-read the letter list from the node's own storage. */
void site_action_post_refresh(void);

/* The "Inbox" / "All Messages" switches in the sidebar.
 * folder is either "inbox" or "all". */
void site_action_post_show_folder(const char *folder);

/* The "Compose" nav button and the "Compose Letter" sidebar shortcut. */
void site_action_compose_open(void);

/* The "-" minimise button in the compose window's title bar. */
void site_action_compose_toggle(void);

/* --- Curia Regis (Kings Court) -------------------------------------------
 * "Reset Node": restart this node and reconnect it to the mesh. */
void site_action_node_reset(void);

/* "Regenerate Keys": build a fresh RSA key pair for this node. */
void site_action_keys_regenerate(void);

#ifdef __cplusplus
}
#endif

#endif /* SITE_ACTIONS_H */
