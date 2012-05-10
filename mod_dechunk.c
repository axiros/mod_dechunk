#include <httpd.h>
#include <http_config.h>
#include <apr_strmatch.h>
#include <http_log.h>
#include <util_filter.h>
#include <apr_strings.h>

#define ITER_BRIGADE(b, bb) \
    for (b=APR_BRIGADE_FIRST(bb); b!=APR_BRIGADE_SENTINEL(bb); b=APR_BUCKET_NEXT(b))

typedef struct replay_kept_body_filter_ctx {
    apr_bucket_brigade *kept_body;
    apr_off_t offset;
    apr_off_t remaining;
} replay_ctx_t;

static apr_status_t
mod_dechunk_replay_kept_body(
        ap_filter_t *f,
        apr_bucket_brigade *b,
        ap_input_mode_t mode,
        apr_read_type_e block,
        apr_off_t readbytes)
{
    apr_bucket *ec, *e2;
    replay_ctx_t *ctx = f->ctx;

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE) {
        return ap_get_brigade(f->next, b, mode, block, readbytes);
    }

    /* mod_dechunk is finished, send next filter */
    if (ctx->remaining <= 0) {
        return ap_get_brigade(f->next, b, mode, block, readbytes);
    }

    if (readbytes > ctx->remaining) {
        readbytes = ctx->remaining;
    }

    /* TODO: Error checking would be good here */
    apr_brigade_partition(ctx->kept_body, ctx->offset, &ec);
    apr_brigade_partition(ctx->kept_body, ctx->offset + readbytes, &e2);

    do {
        apr_bucket *tmp;
        apr_bucket_copy(ec, &tmp);
        APR_BRIGADE_INSERT_TAIL(b, tmp);
        ec = APR_BUCKET_NEXT(ec);
    } while (ec != e2);

    ctx->remaining -= readbytes;
    ctx->offset += readbytes;
    return APR_SUCCESS;
}



static apr_status_t
read_complete_body(request_rec *r, apr_bucket_brigade *kept_body)
{
    apr_bucket_brigade *tmp_bb;
    apr_bucket *t_bucket1, *t_bucket2;
    unsigned short eos_seen = 0;
    apr_status_t status;

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    while (!eos_seen) {
        status = ap_get_brigade(
                        r->input_filters,
                        tmp_bb,
                        AP_MODE_READBYTES,
                        APR_BLOCK_READ,
                        HUGE_STRING_LEN);

        /* This means the filter discovered an error.
         * Furthermore input-filter already handeld the error and sends
         * something to the output chain.
         * For example ap_http_filter does this if LimitRequestBody is reached
         */
        if (status == AP_FILTER_ERROR) {
            apr_brigade_destroy(tmp_bb);
            return AP_FILTER_ERROR;
        }

        /* Cool no need to search for the eos bucket */
        if (APR_STATUS_IS_EOF(status)) {
            apr_brigade_destroy(tmp_bb);
            return APR_SUCCESS;
        }

        if (status != APR_SUCCESS) {
            apr_brigade_destroy(tmp_bb);
            return status;
        }

        ITER_BRIGADE(t_bucket1, tmp_bb) {

            apr_bucket_copy(t_bucket1, &t_bucket2);
            APR_BRIGADE_INSERT_TAIL(kept_body, t_bucket2);

            if (!eos_seen && APR_BUCKET_IS_EOS(t_bucket1)) {
                eos_seen = 1;
            }
        }
        apr_brigade_cleanup(tmp_bb);
    }
    apr_brigade_destroy(tmp_bb);
    return APR_SUCCESS;
}

static int
mod_dechunk_handler(request_rec *r)
{
    apr_bucket_brigade *kept_body;
    apr_off_t content_length;
    apr_status_t status;

    /* Only run if 'Transfer-Encoding' is chunked */
    const char *tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    if (tenc == NULL) {
        return DECLINED;
    }

    if (apr_strnatcasecmp(tenc, "chunked") != 0) {
        return DECLINED;
    }

    /* Buffer all incoming data into one brigade */
    kept_body = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    status = read_complete_body(r, kept_body);
    if (status == AP_FILTER_ERROR) {
        /* Log is already done by outputfilter */
        apr_brigade_destroy(kept_body);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "Cannot read body");
        apr_brigade_destroy(kept_body);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* No need for other modules to know about 'Transfer-Encoding' */
    apr_table_unset(r->headers_in, "Transfer-Encoding");

    /* Having all data allows to set a 'Content-Length' header */
    apr_brigade_length(kept_body, 1, &content_length);
    apr_table_setn(
            r->headers_in,
            "Content-Length",
            apr_off_t_toa(r->pool, content_length));

    replay_ctx_t *ctx = (replay_ctx_t*) apr_palloc(r->pool, sizeof(replay_ctx_t));

    ctx->kept_body = kept_body;
    ctx->offset = 0;
    ctx->remaining = content_length;

    /* Add the replay filter, so that other 'handlers' have the body too */
    ap_add_input_filter("mod_dechunk_replay_kept_body", ctx, r, r->connection);

    /* Allows other 'handlers' like mod_wsgi to run */
    return DECLINED;
}

static void
register_hooks(apr_pool_t *pool)
{
    static const char * const run_before[] = {"mod_wsgi.c", NULL};

    ap_hook_handler(
            mod_dechunk_handler,
            NULL,
            run_before,
            APR_HOOK_MIDDLE);

    ap_register_input_filter(
            "mod_dechunk_replay_kept_body",
            mod_dechunk_replay_kept_body,
            NULL,
            AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA mod_dechunk = {
    STANDARD20_MODULE_STUFF,
    NULL, /*Dir config*/
    NULL, /*Merge dir config*/
    NULL, /*Server config */
    NULL, /*Server merge */
    NULL, /*Commands*/
    register_hooks,
};
