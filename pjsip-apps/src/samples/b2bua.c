/*
 * Minimal B2BUA for PJSIP 2.15.x (UDP/TLS aware)
 * - Headless (null sound device) for containers/servers
 * - Auto-bridges media between legs via PJSUA conf bridge
 * - Auto-enables TLS if needed by ID/REG URIs or env
 * - Optional registration with credentials
 * - Does NOT log sensitive values (URIs, usernames, passwords, IPs)
 *
 * Environment (values are NOT logged):
 *   LOC_ID_URI        : local account AOR for phone side (default: ID_URI or sip:anon@invalid)
 *   ID_URI            : kept for backward compat, used if LOC_ID_URI not set
 *   UP_ID_URI         : upstream account AOR (optional; if not set but UP_REG_URI is set, uses placeholder)
 *   UP_REG_URI        : upstream registrar (sips:...)
 *   UP_PROXY          : upstream proxy to route ALL upstream requests through
 *   UP_OUTBOUND_PROXY : alias for UP_PROXY (optional)
 *   AUTH_USER/PASS    : fallback auth for upstream if UP_AUTH_* not set
 *   UP_AUTH_USER/PASS : upstream auth credentials
 *   REALM/UP_REALM    : realm or "*" (default "*")
 *   OUTBOUND_PROXY    : global outbound proxy (applies to all accounts)
 *   SIP_PORT          : local UDP port (default 5061)
 *   TLS_PORT          : local TLS port (default 5061)
 *   TRANSPORT         : "udp", "tls", "both", "tls-only" (optional; auto-detected otherwise)
 *   TLS_VERIFY        : 0/1 verify server cert (default 0)
 *   TLS_CA_FILE       : path to CA bundle (optional)
 *   TLS_CERT_FILE     : client cert file (optional)
 *   TLS_PRIVKEY_FILE  : client private key (optional)
 *   TLS_PASSWORD      : private key password (optional)
 *   DEST_URI          : single-destination mode (used if per-direction not set)
 *   DEST_TO_UPSTREAM  : when phone calls in, dial this upstream URI
 *   DEST_TO_LOCAL     : when upstream calls in, dial this phone URI
 *   UP_DEST_URI       : alias for DEST_TO_UPSTREAM; LOC_DEST_URI for DEST_TO_LOCAL
 *   LOG_LEVEL         : console log level (default 3)
 */

#include <pjsua-lib/pjsua.h>
#include <pjlib.h>
#include <stdlib.h>
#include <string.h>
#include <pjsip/sip_uri.h>

#define THIS_APP   "b2bua"
#define MAX_CALLS  PJSUA_MAX_CALLS

static int peer_map[MAX_CALLS];
static pjsua_acc_id g_acc_loc = PJSUA_INVALID_ID; /* Local (phone-facing) */
static pjsua_acc_id g_acc_up  = PJSUA_INVALID_ID; /* Upstream (provider)  */
static pjsua_transport_id g_udp_tid = PJSUA_INVALID_ID;
static pjsua_transport_id g_tls_tid = PJSUA_INVALID_ID;

/* ---------------- Utilities ---------------- */

static const char* env_str(const char *key, const char *defv)
{
    const char *v = getenv(key);
    return (v && *v) ? v : defv;
}

static int env_int(const char *key, int defv)
{
    const char *v = getenv(key);
    return (v && *v) ? atoi(v) : defv;
}

static pj_bool_t uri_needs_tls(const char *uri)
{
    if (!uri || !*uri) return PJ_FALSE;
    if (!pj_ansi_strncmp(uri, "sips:", 5)) return PJ_TRUE;
    if (pj_ansi_strstr(uri, "transport=tls")) return PJ_TRUE;
    return PJ_FALSE;
}

static pj_bool_t want_tls_from_env(void)
{
    const char *t = env_str("TRANSPORT", NULL);
    if (!t) return PJ_FALSE;
    if (!pj_ansi_stricmp(t, "tls")) return PJ_TRUE;
    if (!pj_ansi_stricmp(t, "tls-only")) return PJ_TRUE;
    if (!pj_ansi_stricmp(t, "both")) return PJ_TRUE;
    return PJ_FALSE;
}


static pj_bool_t want_udp_from_env(void)
{
    const char *t = env_str("TRANSPORT", NULL);
    if (!t) return PJ_TRUE; /* default UDP */
    if (!pj_ansi_stricmp(t, "udp")) return PJ_TRUE;
    if (!pj_ansi_stricmp(t, "both")) return PJ_TRUE;
    return PJ_FALSE;
}

/* Normalize sip: URIs with ;transport=tls to sips: for registration/dialing */
static const char* to_sips_if_tls(const char *uri, char *out, unsigned outsz)
{
    if (!uri || !*uri || !out || outsz == 0) return uri;
    if (!pj_ansi_strncmp(uri, "sip:", 4)) {
        const char *tp = pj_ansi_strstr(uri, "transport=tls");
        if (tp) {
            /* Rewrite leading scheme only; keep the rest intact (including ;transport=tls). */
            pj_ansi_snprintf(out, outsz, "sips:%s", uri+4);
            return out;
        }
    }
    return uri;
}

static void set_codec_preferences(void)
{
    /* Prefer G.711 (PCMU/PCMA) for phone side, keep AMR/AMR-WB enabled for upstream.
     * Also enable iLBC (and a few common legacy codecs) at lower priority so
     * phones that don’t offer G.711 can still connect. */
    pjsua_codec_info ci[64];
    unsigned cnt = (unsigned)(sizeof(ci)/sizeof(ci[0]));
    if (pjsua_enum_codecs(ci, &cnt) != PJ_SUCCESS)
        return;

    for (unsigned i = 0; i < cnt; ++i) {
        pj_str_t id = ci[i].codec_id;
        const char *s = id.ptr;
        pj_size_t n = id.slen;
        if (!s || n == 0) continue;

        /* Raise PCMU/PCMA priority by matching prefix "PCMU/" or "PCMA/" */
        if ((n >= 5 && !pj_ansi_strnicmp(s, "PCMU/", 5)) ||
            (n >= 5 && !pj_ansi_strnicmp(s, "PCMA/", 5)))
        {
            pjsua_codec_set_priority(&id, PJMEDIA_CODEC_PRIO_HIGHEST-1);
            continue;
        }

        /* Keep AMR/AMR-WB enabled; ensure at least normal priority */
        if ((n >= 4 && !pj_ansi_strnicmp(s, "AMR/", 4)) ||
            (n >= 7 && !pj_ansi_strnicmp(s, "AMR-WB/", 7)))
        {
            pjsua_codec_set_priority(&id, PJMEDIA_CODEC_PRIO_NORMAL);
            continue;
        }

        /* Keep telephone-event enabled (DTMF relay) */
        if ((n >= 16 && !pj_ansi_strnicmp(s, "telephone-event/", 16))) {
            pjsua_codec_set_priority(&id, PJMEDIA_CODEC_PRIO_NORMAL);
            continue;
        }

        /* Allow iLBC to interop with some phones (e.g., Grandstream default) */
        if ((n >= 5 && !pj_ansi_strnicmp(s, "ILBC/", 5)) ||
            (n >= 5 && !pj_ansi_strnicmp(s, "iLBC/", 5)))
        {
            pjsua_codec_set_priority(&id, PJMEDIA_CODEC_PRIO_NORMAL-10);
            continue;
        }

        /* Allow G726 variants at low priority (many desk phones offer it) */
        if ((n >= 7 && !pj_ansi_strnicmp(s, "G726-16/", 8)) ||
            (n >= 7 && !pj_ansi_strnicmp(s, "G726-24/", 8)) ||
            (n >= 7 && !pj_ansi_strnicmp(s, "G726-32/", 8)) ||
            (n >= 7 && !pj_ansi_strnicmp(s, "G726-40/", 8)))
        {
            pjsua_codec_set_priority(&id, PJMEDIA_CODEC_PRIO_NORMAL-20);
            continue;
        }

        /* Everything else disabled */
        pjsua_codec_set_priority(&id, PJMEDIA_CODEC_PRIO_DISABLED);
    }
}


static void disconnect_peer_if_any(pjsua_call_id call_id)
{
    int other = (call_id >= 0 && call_id < MAX_CALLS) ? peer_map[call_id] : -1;
    if (other >= 0 && other < MAX_CALLS) {
        peer_map[other] = -1;
        peer_map[call_id] = -1;
        pjsua_call_hangup(other, 486, NULL, NULL);
    }
}

static void disconnect_peer_with_status(pjsua_call_id src_id, int code, const pj_str_t *reason)
{
    int other = (src_id >= 0 && src_id < MAX_CALLS) ? peer_map[src_id] : -1;
    if (other >= 0 && other < MAX_CALLS) {
        /* Decide best action by peer role/state */
        pjsua_call_info oi;
        pj_bool_t have_info = (pjsua_call_get_info(other, &oi) == PJ_SUCCESS);

        /* Propagate the precise status to the peer leg:
         * - If peer is UAS and still EARLY, send final response (e.g., 486/603)
         * - If peer is UAC and still EARLY, send CANCEL with mapped Reason
         * - Otherwise, send BYE with the code
         */
        if (have_info && oi.state < PJSIP_INV_STATE_CONFIRMED && oi.role == PJSIP_ROLE_UAS) {
            pjsua_call_answer(other, code, (reason ? reason : NULL), NULL);
        } else {
            pjsua_call_hangup(other, code, (reason ? reason : NULL), NULL);
        }

        peer_map[other] = -1;
        peer_map[src_id] = -1;
    }
}

static void try_bridge(pjsua_call_id a)
{
    if (a < 0 || a >= MAX_CALLS) return;
    int b = peer_map[a];
    if (b < 0 || b >= MAX_CALLS) return;

    pjsua_call_info ia, ib;
    if (pjsua_call_get_info(a, &ia) != PJ_SUCCESS) return;
    if (pjsua_call_get_info(b, &ib) != PJ_SUCCESS) return;

    if (ia.media_status == PJSUA_CALL_MEDIA_ACTIVE &&
        ib.media_status == PJSUA_CALL_MEDIA_ACTIVE)
    {
        pjsua_conf_connect(ia.conf_slot, ib.conf_slot);
        pjsua_conf_connect(ib.conf_slot, ia.conf_slot);
        PJ_LOG(3, (THIS_APP, "Media bridged between call legs"));
    }
}

/* ---------------- Callbacks ---------------- */

static void on_call_state(pjsua_call_id call_id, pjsip_event *e)
{
    PJ_UNUSED_ARG(e);
    pjsua_call_info ci;
    if (pjsua_call_get_info(call_id, &ci) != PJ_SUCCESS) return;

    if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
        /* Prefer to propagate the actual upstream/downstream final status code to the opposite leg.
         * For example, if upstream returns 486/603/480/etc, send the same code back to the phone leg
         * instead of a hardcoded 486. If we initiated CANCEL on the other side, PJSUA will translate
         * this hangup to a proper CANCEL/487 as appropriate. */
        int code = ci.last_status;
        pj_str_t reason = ci.last_status_text;
        if (code <= 0 || code == 200) {
            /* Fallback when the library didn't record a meaningful final code. */
            code = 486;
            reason.ptr = NULL;
            reason.slen = 0;
        }
        disconnect_peer_with_status(call_id, code, (reason.slen ? &reason : NULL));
        PJ_LOG(3, (THIS_APP, "Call %d disconnected (propagated code=%d)", call_id, code));
    } else if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
        PJ_LOG(3, (THIS_APP, "Call %d confirmed", call_id));
        /* If this is the outbound leg confirmed, answer the inbound */
        int peer = (call_id>=0 && call_id<MAX_CALLS)? peer_map[call_id] : -1;
        if (peer >= 0 && peer < MAX_CALLS) {
            pjsua_call_info pi;
            if (pjsua_call_get_info(peer, &pi) == PJ_SUCCESS) {
                if (pi.state < PJSIP_INV_STATE_CONFIRMED && pi.role == PJSIP_ROLE_UAS) {
                    pjsua_call_answer(peer, 200, NULL, NULL);
                }
            }
        }
        try_bridge(call_id);
    }
}

static void on_call_media_state(pjsua_call_id call_id)
{
    pjsua_call_info ci;
    if (pjsua_call_get_info(call_id, &ci) != PJ_SUCCESS) return;

    if (ci.media_status == PJSUA_CALL_MEDIA_ACTIVE) {
        PJ_LOG(3, (THIS_APP, "Call %d media active", call_id));
        try_bridge(call_id);
    }
}

static void extract_user_from_ruri(pjsip_rx_data *rdata, char *out, unsigned outsz)
{
    if (!out || outsz==0) return;
    out[0] = '\0';
    if (!rdata || !rdata->msg_info.msg) return;

    pjsip_msg *msg = rdata->msg_info.msg;
    if (!msg->line.req.uri) return;

    pjsip_uri *uri = msg->line.req.uri;
    pjsip_sip_uri *sip_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(uri);
    if (!sip_uri) return;

    pj_str_t user = sip_uri->user;
    if (user.slen <= 0 || !user.ptr) return;
    unsigned n = (user.slen < (int)(outsz-1)) ? (unsigned)user.slen : (outsz-1);
    pj_ansi_strncpy(out, user.ptr, n);
    out[n] = '\0';
}

static void subst_user_template(const char *tmpl, const char *user, char *out, unsigned outsz)
{
    /* Robustly replace "{user}" placeholder. Also handle malformed "{user...}" */
    if (!out || outsz==0) return;
    out[0] = '\0';
    if (!tmpl) return;

    const char *p = tmpl;
    unsigned used = 0;
    pj_bool_t awaiting_closing_brace = PJ_FALSE;

    while (*p && used < outsz-1) {
        if (*p == '{' && pj_ansi_strncmp(p, "{user", 5) == 0) {
            /* Found opening placeholder */
            const char *after = p + 5;
            if (*after == '}') {
                /* Proper form {user} */
                after++;
            } else {
                /* Malformed/open form {user...}, remember to drop a later '}' once */
                awaiting_closing_brace = PJ_TRUE;
            }
            /* Insert user */
            if (user && *user && used < outsz-1) {
                unsigned ulen = (unsigned)pj_ansi_strlen(user);
                unsigned nun = (ulen < (outsz-1-used)) ? ulen : (outsz-1-used);
                pj_ansi_strncpy(out+used, user, nun);
                used += nun;
            }
            p = after;
            continue;
        }
        if (*p == '}' && awaiting_closing_brace) {
            /* Skip this closing brace corresponding to malformed {user...} */
            awaiting_closing_brace = PJ_FALSE;
            p++;
            continue;
        }
        /* Copy regular char */
        out[used++] = *p++;
    }

    out[(used < outsz)? used : (outsz-1)] = '\0';
}

/* Extract display-name and SIP URI from From header if present */
static void extract_from_identity(pjsip_rx_data *rdata,
                                  char *name_out, unsigned name_sz,
                                  char *uri_out,  unsigned uri_sz)
{
    if (name_out && name_sz) name_out[0] = '\0';
    if (uri_out && uri_sz)   uri_out[0] = '\0';
    if (!rdata || !rdata->msg_info.msg) return;

    pjsip_fromto_hdr *from = rdata->msg_info.from;
    if (!from || !from->uri) return;

    /* name (display) */
    if (name_out && name_sz && from->name.slen > 0 && from->name.ptr) {
        unsigned n = (from->name.slen < (int)(name_sz-1)) ? (unsigned)from->name.slen : (name_sz-1);
        pj_ansi_strncpy(name_out, from->name.ptr, n);
        name_out[n] = '\0';
    }

    /* Build SIP AOR from URI parts */
    pjsip_uri *uri = pjsip_uri_get_uri(from->uri);
    if (!uri) return;
    if (PJSIP_URI_SCHEME_IS_SIP(uri) || PJSIP_URI_SCHEME_IS_SIPS(uri)) {
        pjsip_sip_uri *su = (pjsip_sip_uri*)uri;
        const char *scheme = PJSIP_URI_SCHEME_IS_SIPS(uri) ? "sips" : "sip";
        char user[160] = {0};
        char host[256] = {0};
        if (su->user.slen > 0 && su->user.ptr) {
            unsigned un = (su->user.slen < (int)sizeof(user)-1) ? (unsigned)su->user.slen : (sizeof(user)-1);
            pj_ansi_strncpy(user, su->user.ptr, un);
            user[un] = '\0';
        }
        if (su->host.slen > 0 && su->host.ptr) {
            unsigned hn = (su->host.slen < (int)sizeof(host)-1) ? (unsigned)su->host.slen : (sizeof(host)-1);
            pj_ansi_strncpy(host, su->host.ptr, hn);
            host[hn] = '\0';
        }
        if (uri_out && uri_sz && host[0]) {
            if (user[0]) pj_ansi_snprintf(uri_out, uri_sz, "%s:%s@%s", scheme, user, host);
            else         pj_ansi_snprintf(uri_out, uri_sz, "%s:%s", scheme, host);
        }
    } else {
        /* Fallback: print URI generically */
        if (uri_out && uri_sz) {
            pj_ssize_t len;
            len = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, from->uri, uri_out, uri_sz);
            if (len < 0) uri_out[0] = '\0';
            else uri_out[(len < (pj_ssize_t)uri_sz ? len : (pj_ssize_t)uri_sz-1)] = '\0';
        }
    }
}

static void on_incoming_call(pjsua_acc_id acc_id,
                             pjsua_call_id call_id,
                             pjsip_rx_data *rdata)
{
    PJ_UNUSED_ARG(rdata);

    /* Determine routing based on which account received the call. */
    const char *dest_to_up    = env_str("DEST_TO_UPSTREAM", env_str("UP_DEST_URI", env_str("DEST_URI", NULL)));
    const char *dest_to_local = env_str("DEST_TO_LOCAL",  env_str("LOC_DEST_URI", NULL));

    /* Optional templates using {user} from Request-URI */
    const char *tmpl_up   = env_str("DEST_TO_UPSTREAM_TMPL", NULL);
    const char *tmpl_loc  = env_str("DEST_TO_LOCAL_TMPL", NULL);

    char userbuf[128];
    extract_user_from_ruri(rdata, userbuf, sizeof(userbuf));

    char dyn_up[512] = {0};
    char dyn_loc[512] = {0};

    if (!dest_to_up && tmpl_up && *userbuf) {
        subst_user_template(tmpl_up, userbuf, dyn_up, sizeof(dyn_up));
        if (*dyn_up) dest_to_up = dyn_up;
    }
    if (!dest_to_local && tmpl_loc && *userbuf) {
        subst_user_template(tmpl_loc, userbuf, dyn_loc, sizeof(dyn_loc));
        if (*dyn_loc) dest_to_local = dyn_loc;
    }

    /* Fallback construction for phone->upstream using realm/domain when template not provided */
    if (acc_id == g_acc_loc && !dest_to_up && *userbuf) {
        const char *up_dom = env_str("UP_DOMAIN", env_str("UP_REALM", env_str("REALM", NULL)));
        const char *tp = env_str("UP_TRANSPORT_PARAM", ";transport=tls");
        if (up_dom && *up_dom) {
            pj_ansi_snprintf(dyn_up, sizeof(dyn_up), "sip:%s@%s%s", userbuf, up_dom, tp);
            dest_to_up = dyn_up;
        }
    }

    const char *dest = NULL;
    if (acc_id == g_acc_loc) {
        /* Phone -> Upstream */
        dest = dest_to_up;
    } else if (acc_id == g_acc_up) {
        /* Upstream -> Phone */
        dest = dest_to_local;
    } else {
        /* Fallback to single-destination mode */
        dest = env_str("DEST_URI", NULL);
    }

    if (!dest) {
        PJ_LOG(1, (THIS_APP,
            "No destination configured for this direction. Set DEST_TO_UPSTREAM/DEST_TO_LOCAL or *_TMPL (values not printed)."));
        pjsua_call_answer(call_id, 480, NULL, NULL);
        return;
    }

    /* Ring inbound while we place the outbound leg. For local leg, attach
     * identity headers so phone shows callee number instead of account name. */
    if (acc_id == g_acc_loc) {
        pj_pool_t *pool = pjsua_pool_create("tmp_hdr", 512, 512);
        pjsua_msg_data msg; pjsua_msg_data_init(&msg);
        if (*userbuf) {
            const char *udom = env_str("UP_DOMAIN", env_str("UP_REALM", env_str("REALM", "invalid")));
            char hval[256];
            char rpidv[320];
            pj_str_t H_PAI = pj_str((char*)"P-Asserted-Identity");
            pj_str_t H_RPID = pj_str((char*)"Remote-Party-ID");
            pj_str_t H_PCPID = pj_str((char*)"P-Called-Party-ID");
            pj_str_t V_PAI, V_RPID;
            pj_ansi_snprintf(hval, sizeof(hval), "\"%s\" <sip:%s@%s>", userbuf, userbuf, udom);
            pj_cstr(&V_PAI, hval);
            pjsip_generic_string_hdr *pai = pjsip_generic_string_hdr_create(pool, &H_PAI, &V_PAI);
            pj_list_push_back(&msg.hdr_list, (pjsip_hdr*)pai);

            /* Also add Remote-Party-ID (some phones prefer this) */
            pj_ansi_snprintf(rpidv, sizeof(rpidv), "\"%s\" <sip:%s@%s>;party=called;id-type=subscriber;screen=yes;privacy=off",
                             userbuf, userbuf, udom);
            pj_cstr(&V_RPID, rpidv);
            pjsip_generic_string_hdr *rpid = pjsip_generic_string_hdr_create(pool, &H_RPID, &V_RPID);
            pj_list_push_back(&msg.hdr_list, (pjsip_hdr*)rpid);

            /* P-Called-Party-ID (reuse same value; includes screen=yes;privacy=off) */
            pj_str_t V_PCPID; pj_cstr(&V_PCPID, rpidv);
            pjsip_generic_string_hdr *pcpid = pjsip_generic_string_hdr_create(pool, &H_PCPID, &V_PCPID);
            pj_list_push_back(&msg.hdr_list, (pjsip_hdr*)pcpid);
        }
        pjsua_call_answer2(call_id, NULL, 180, NULL, &msg);
        pj_pool_release(pool);
    } else {
        pjsua_call_answer(call_id, 180, NULL, NULL);
    }

    pjsua_call_setting opt;
    pjsua_call_setting_default(&opt);
    opt.aud_cnt = 1;
    opt.vid_cnt = 0;

    /* For phone -> upstream, many IMS cores require ;user=phone on E.164 */
    char dest_buf[512] = {0};
    if (acc_id == g_acc_loc && dest && !pj_ansi_strstr(dest, ";user=")) {
        /* if dialed user looks numeric/plus, append ;user=phone */
        if (userbuf[0] == '+' || (userbuf[0] && pj_isdigit((unsigned char)userbuf[0]))) {
            pj_ansi_snprintf(dest_buf, sizeof(dest_buf), "%s%s", dest,
                             (pj_ansi_strchr(dest, ';') ? ";user=phone" : ";user=phone"));
            dest = dest_buf;
        }
    }

    /* Normalize destination URI if ;transport=tls -> sips, when enabled */
    char sips_buf[512] = {0};
    const char *final_dest = dest;
    if (env_int("DIAL_USE_SIPS", 0))
        final_dest = to_sips_if_tls(dest, sips_buf, sizeof(sips_buf));
    pj_str_t dst_uri;
    pj_cstr(&dst_uri, final_dest);
    /* Debug log for dialing */
    pjsua_acc_id out_acc = acc_id;
    if (acc_id == g_acc_loc && g_acc_up != PJSUA_INVALID_ID)
        out_acc = g_acc_up;
    else if (acc_id == g_acc_up && g_acc_loc != PJSUA_INVALID_ID)
        out_acc = g_acc_loc;
    PJ_LOG(3, (THIS_APP, "Dialing upstream dest: %s (out_acc=%d)", final_dest, (int)out_acc));

    /* Optional: attach caller identity headers when upstream -> local so phones don't show "b2bua" */
    pjsua_msg_data md; pj_bool_t use_md = PJ_FALSE; pj_pool_t *id_pool = NULL;
    if (acc_id == g_acc_up) {
        char from_name[128] = {0};
        char from_aor[256]  = {0};
        extract_from_identity(rdata, from_name, sizeof(from_name), from_aor, sizeof(from_aor));
        if (from_aor[0]) {
            pj_pool_t *pool = pjsua_pool_create("id_hdr", 512, 512);
            pjsua_msg_data_init(&md);
            /* Build P-Asserted-Identity */
            pj_str_t H_PAI = pj_str((char*)"P-Asserted-Identity");
            char buf_pai[384];
            if (from_name[0]) pj_ansi_snprintf(buf_pai, sizeof(buf_pai), "\"%s\" <%s>", from_name, from_aor);
            else              pj_ansi_snprintf(buf_pai, sizeof(buf_pai), "<%s>", from_aor);
            pj_str_t V_PAI; pj_cstr(&V_PAI, buf_pai);
            pjsip_generic_string_hdr *pai = pjsip_generic_string_hdr_create(pool, &H_PAI, &V_PAI);
            pj_list_push_back(&md.hdr_list, (pjsip_hdr*)pai);

            /* Build Remote-Party-ID as calling */
            pj_str_t H_RPID = pj_str((char*)"Remote-Party-ID");
            char buf_rpid[416];
            if (from_name[0])
                pj_ansi_snprintf(buf_rpid, sizeof(buf_rpid), "\"%s\" <%s>;party=calling;id-type=subscriber;screen=yes;privacy=off",
                                 from_name, from_aor);
            else
                pj_ansi_snprintf(buf_rpid, sizeof(buf_rpid), "<%s>;party=calling;id-type=subscriber;screen=yes;privacy=off",
                                 from_aor);
            pj_str_t V_RPID; pj_cstr(&V_RPID, buf_rpid);
            pjsip_generic_string_hdr *rpid = pjsip_generic_string_hdr_create(pool, &H_RPID, &V_RPID);
            pj_list_push_back(&md.hdr_list, (pjsip_hdr*)rpid);

            use_md = PJ_TRUE;
            id_pool = pool;
        }
    }

    /* Place outbound using the opposite account if available, otherwise same acc */
    pjsua_call_id out_id = PJSUA_INVALID_ID;
    pj_status_t st = pjsua_call_make_call(out_acc, &dst_uri, &opt, NULL,
                                          use_md ? &md : NULL, &out_id);
    if (id_pool) { pj_pool_release(id_pool); id_pool = NULL; }
    if (st != PJ_SUCCESS) {
        PJ_LOG(1, (THIS_APP, "Failed to create outbound leg"));
        pjsua_call_hangup(call_id, 500, NULL, NULL);
        return;
    }

    /* Pair legs; inbound will be answered when outbound becomes confirmed */
    peer_map[call_id] = out_id;
    peer_map[out_id]  = call_id;
    /* no immediate 200 OK here; wait for peer leg to be confirmed */
    PJ_LOG(3, (THIS_APP, "Inbound answered; outbound leg started"));
}

/* ---------------- Main ---------------- */

int main(void)
{
    pj_status_t st;

    for (int i = 0; i < MAX_CALLS; ++i) peer_map[i] = -1;

    st = pjsua_create();
    if (st != PJ_SUCCESS) return 1;

    /* Global config */
    pjsua_config cfg;
    pjsua_config_default(&cfg);
    cfg.cb.on_incoming_call    = &on_incoming_call;
    cfg.cb.on_call_state       = &on_call_state;
    cfg.cb.on_call_media_state = &on_call_media_state;
    /* Ensure ;lr is appended to route/proxy URIs */
    cfg.force_lr = PJ_TRUE;

    /* Global outbound proxy (optional; prefer UP_PROXY for upstream-only) */
    const char *ob = env_str("OUTBOUND_PROXY", NULL);
    if (ob && *ob) {
        cfg.outbound_proxy_cnt = 1;
        cfg.outbound_proxy[0] = pj_str((char*)ob);
    }

    /* Optional User-Agent override to mimic specific UA */
    const char *ua = env_str("USER_AGENT", NULL);
    if (ua && *ua) {
        cfg.user_agent = pj_str((char*)ua);
    }

    pjsua_logging_config log_cfg;
    pjsua_logging_config_default(&log_cfg);
    log_cfg.console_level = env_int("LOG_LEVEL", 3);

    pjsua_media_config media_cfg;
    pjsua_media_config_default(&media_cfg);
    media_cfg.no_vad = PJ_TRUE;

    st = pjsua_init(&cfg, &log_cfg, &media_cfg);
    if (st != PJ_SUCCESS) {
        pjsua_destroy();
        return 1;
    }

    /* Null sound device: no actual audio HW required */
    pjsua_set_null_snd_dev();
    /* Prefer G.711 for phones; keep AMR available for upstream */
    set_codec_preferences();

    /* Determine transports needed */
    const char *loc_id_uri  = env_str("LOC_ID_URI", env_str("ID_URI", "sip:anon@invalid"));
    const char *up_id_uri   = env_str("UP_ID_URI", NULL);
    const char *up_reg_uri  = env_str("UP_REG_URI", env_str("REG_URI", NULL));
    pj_bool_t needs_tls = (uri_needs_tls(up_id_uri) || uri_needs_tls(up_reg_uri) || want_tls_from_env());
    pj_bool_t needs_udp = want_udp_from_env() || (!needs_tls); /* default UDP if nothing specified */

    /* Create UDP transport when requested */
    if (needs_udp) {
        pjsua_transport_config ucfg;
        pjsua_transport_config_default(&ucfg);
        ucfg.port = (unsigned)env_int("SIP_PORT", 5061);
        st = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &ucfg, &g_udp_tid);
        if (st != PJ_SUCCESS) {
            PJ_LOG(1, (THIS_APP, "Failed to create UDP transport"));
            pjsua_destroy();
            return 1;
        }
    }

    /* Create TLS transport when requested */
    if (needs_tls) {
        pjsua_transport_config tcfg;
        pjsua_transport_config_default(&tcfg);
        tcfg.port = (unsigned)env_int("TLS_PORT", 5061);

        /* Optional published/bound addresses for TLS */
        const char *tls_pub  = env_str("TLS_PUBLIC_ADDR", NULL);
        const char *tls_bind = env_str("TLS_BOUND_ADDR", NULL);
        if (tls_pub && *tls_pub)  tcfg.public_addr = pj_str((char*)tls_pub);
        if (tls_bind && *tls_bind) tcfg.bound_addr  = pj_str((char*)tls_bind);

        int verify = env_int("TLS_VERIFY", 0);
        tcfg.tls_setting.verify_server = verify ? PJ_TRUE : PJ_FALSE;
        tcfg.tls_setting.verify_client = PJ_FALSE; /* usually not needed */

        const char *caf = env_str("TLS_CA_FILE", NULL);
        const char *crt = env_str("TLS_CERT_FILE", NULL);
        const char *key = env_str("TLS_PRIVKEY_FILE", NULL);
        const char *pwd = env_str("TLS_PASSWORD", NULL);

        if (caf && *caf) tcfg.tls_setting.ca_list_file = pj_str((char*)caf);
        if (crt && *crt) tcfg.tls_setting.cert_file    = pj_str((char*)crt);
        if (key && *key) tcfg.tls_setting.privkey_file = pj_str((char*)key);
        if (pwd && *pwd) tcfg.tls_setting.password     = pj_str((char*)pwd);

        st = pjsua_transport_create(PJSIP_TRANSPORT_TLS, &tcfg, &g_tls_tid);
        if (st != PJ_SUCCESS) {
            PJ_LOG(1, (THIS_APP, "Failed to create TLS transport"));
            pjsua_destroy();
            return 1;
        }
    }

    /* Start the stack */
    st = pjsua_start();
    if (st != PJ_SUCCESS) {
        pjsua_destroy();
        return 1;
    }

    /* Local (phone-facing) account on UDP (or default transport). */
    {
        pjsua_acc_config acc_cfg;
        pjsua_acc_config_default(&acc_cfg);

        acc_cfg.id = pj_str((char*)loc_id_uri);
        acc_cfg.register_on_acc_add = PJ_FALSE;
        if (g_udp_tid != PJSUA_INVALID_ID)
            acc_cfg.transport_id = g_udp_tid;

        /* Optional: adjust Contact shown to local phones to avoid showing
         * username "b2bua" as callee name on devices. Build Contact from
         * envs or use LOC_FORCE_CONTACT verbatim if provided. */
        const char *fc = env_str("LOC_FORCE_CONTACT", NULL);
        if (fc && *fc) {
            acc_cfg.force_contact = pj_str((char*)fc);
        } else {
            const char *chost = env_str("LOC_CONTACT_HOST", env_str("IPV4_ADDRESS", NULL));
            int cport = env_int("SIP_PORT", 5061);
            const char *cuser = env_str("LOC_CONTACT_USER", NULL);
            const char *cdsp  = env_str("LOC_CONTACT_DISPLAY", NULL);
            if (chost && *chost) {
                char buf[256];
                if (cdsp && *cdsp) {
                    if (cuser && *cuser)
                        pj_ansi_snprintf(buf, sizeof(buf), "\"%s\" <sip:%s@%s:%d>", cdsp, cuser, chost, cport);
                    else
                        pj_ansi_snprintf(buf, sizeof(buf), "\"%s\" <sip:%s:%d>", cdsp, chost, cport);
                } else {
                    if (cuser && *cuser)
                        pj_ansi_snprintf(buf, sizeof(buf), "sip:%s@%s:%d", cuser, chost, cport);
                    else
                        pj_ansi_snprintf(buf, sizeof(buf), "sip:%s:%d", chost, cport);
                }
                acc_cfg.force_contact = pj_str(buf);
            }
        }

        /* RTP base port/range */
        acc_cfg.rtp_cfg.port = (unsigned)env_int("RTP_PORT", 52000);
        acc_cfg.rtp_cfg.port_range = 200;

        st = pjsua_acc_add(&acc_cfg, PJ_TRUE, &g_acc_loc);
        if (st != PJ_SUCCESS) {
            PJ_LOG(1, (THIS_APP, "Failed to add local account"));
            pjsua_destroy();
            return 1;
        }
    }

    /* Upstream account on TLS with optional registration/credentials. */
    if (up_id_uri || up_reg_uri) {
        pjsua_acc_config acc_cfg;
        pjsua_acc_config_default(&acc_cfg);

        const char *up_user  = env_str("UP_AUTH_USER", env_str("AUTH_USER", NULL));
        const char *up_pass  = env_str("UP_AUTH_PASS", env_str("AUTH_PASS", NULL));
        const char *up_realm = env_str("UP_REALM",     env_str("REALM", "*"));
        const char *up_proxy = env_str("UP_PROXY", env_str("UP_OUTBOUND_PROXY", NULL));

        /* Route ALL upstream requests through the given upstream proxy */
        if (up_proxy && *up_proxy) {
            acc_cfg.proxy_cnt = 1;
            acc_cfg.proxy[0] = pj_str((char*)up_proxy);
        }

        if (up_id_uri && *up_id_uri)
            acc_cfg.id = pj_str((char*)up_id_uri);
        else
            acc_cfg.id = pj_str("sip:upstream@invalid");

        if (up_reg_uri && *up_reg_uri) {
            {
                char reg_buf[512] = {0};
                const char *rnorm = up_reg_uri;
                if (env_int("REG_USE_SIPS", 1))
                    rnorm = to_sips_if_tls(up_reg_uri, reg_buf, sizeof(reg_buf));
                acc_cfg.reg_uri = pj_str((char*)rnorm);
            }
            acc_cfg.register_on_acc_add = PJ_TRUE;
        } else {
            acc_cfg.register_on_acc_add = PJ_FALSE;
        }

        if (g_tls_tid != PJSUA_INVALID_ID)
            acc_cfg.transport_id = g_tls_tid;

        /* RTP base port/range */
        acc_cfg.rtp_cfg.port = (unsigned)env_int("RTP_PORT", 52000);
        acc_cfg.rtp_cfg.port_range = 200;

        /* REGISTER request target and Contact formatting for upstream */
        if (acc_cfg.register_on_acc_add && (up_reg_uri && *up_reg_uri)) {
            /* RFC 5626 Outbound: ensure ;ob and instance/reg-id appear */
            acc_cfg.use_rfc5626 = PJ_TRUE;

            const char *iid = env_str("UP_INSTANCE_ID", NULL);
            if (iid && *iid)
                acc_cfg.rfc5626_instance_id = pj_str((char*)iid);

            const char *rid = env_str("UP_REG_ID", "1");
            if (rid && *rid)
                acc_cfg.rfc5626_reg_id = pj_str((char*)rid);

            /* Optional extra Contact-URI params for REGISTER (inside <...>) */
            const char *uri_params = env_str("UP_REG_CONTACT_URI_PARAMS", "");
            if (uri_params && *uri_params)
                acc_cfg.reg_contact_uri_params = pj_str((char*)uri_params);

            /* Registration expires */
            acc_cfg.reg_timeout = (unsigned)env_int("UP_REG_EXPIRES", 86400);

            /* Keep TLS flow alive to favor flow reuse */
            acc_cfg.ka_interval = (unsigned)env_int("KEEPALIVE", 15);
            /* acc_cfg.ka_data left default (CRLF) */

            /* Prefer using the real connected TLS source port in Contact */
            acc_cfg.contact_use_src_port = PJ_TRUE;
            /* Aggressively update Contact on IP/port change */
            acc_cfg.allow_contact_rewrite = 2; /* always update */
            acc_cfg.allow_via_rewrite = PJ_TRUE;
        }

        acc_cfg.cred_count = 0;
        if (up_user && up_pass) {
            acc_cfg.cred_count = 1;
            acc_cfg.cred_info[0].scheme    = pj_str("Digest");
            acc_cfg.cred_info[0].realm     = pj_str((char*)up_realm);
            acc_cfg.cred_info[0].username  = pj_str((char*)up_user);
            acc_cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
            acc_cfg.cred_info[0].data      = pj_str((char*)up_pass);
        }

        st = pjsua_acc_add(&acc_cfg, PJ_TRUE, &g_acc_up);
        if (st != PJ_SUCCESS) {
            PJ_LOG(1, (THIS_APP, "Failed to add upstream account"));
            pjsua_destroy();
            return 1;
        }
    }

    PJ_LOG(3, (THIS_APP, "Ready. Waiting for calls; will bridge between local and upstream."));

    while (1) pj_thread_sleep(1000);
    /* not reached */
    /* pjsua_destroy(); */
    /* return 0; */
}
