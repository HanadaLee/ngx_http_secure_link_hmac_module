
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_CONDITION)
#include <ngx_http_condition_module.h>
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>


#define NGX_HTTP_AUTH_HMAC_TIMESTAMP     1
#define NGX_HTTP_AUTH_HMAC_MSTIMESTAMP   2
#define NGX_HTTP_AUTH_HMAC_HEXTIMESTAMP  3
#define NGX_HTTP_AUTH_HMAC_DATE          4

#define NGX_HTTP_AUTH_HMAC_HEX           1
#define NGX_HTTP_AUTH_HMAC_BASE64URL     2
#define NGX_HTTP_AUTH_HMAC_BASE64        3
#define NGX_HTTP_AUTH_HMAC_BIN           4

typedef struct {
    ngx_http_complex_value_t  *time;
    ngx_http_complex_value_t  *start;
    ngx_http_complex_value_t  *end;
    ngx_uint_t                 time_mode;
    ngx_str_t                  time_format;
    time_t                     time_offset;
} ngx_http_auth_hmac_time_conf_t;


typedef struct {
    ngx_http_complex_value_t  *token;
    ngx_uint_t                 token_digest;
} ngx_http_auth_hmac_token_conf_t;


typedef struct {
#if (NGX_CONDITION)
    ngx_array_t               *enable;
    ngx_array_t               *time;
    ngx_array_t               *token;
    ngx_array_t               *message;
    ngx_array_t               *secret;
    ngx_array_t               *algorithm;
#else
    ngx_flag_t                 enable;
    ngx_http_auth_hmac_time_conf_t   *time;
    ngx_http_auth_hmac_token_conf_t  *token;
    ngx_http_complex_value_t  *message;
    ngx_http_complex_value_t  *secret;
    ngx_str_t                  algorithm;
#endif
} ngx_http_auth_hmac_conf_t;


static ngx_int_t ngx_http_auth_hmac_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_auth_hmac_create_conf(ngx_conf_t *cf);
static char *ngx_http_auth_hmac_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_int_t ngx_http_auth_hmac_hex_decode(ngx_str_t *dst,
    ngx_str_t *src);
static ngx_int_t ngx_http_auth_hmac_is_valid_num(ngx_str_t *s);
static char *ngx_http_auth_hmac_check_time(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_hmac_check_token(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auth_hmac_add_variables(ngx_conf_t *cf);


static ngx_command_t  ngx_http_auth_hmac_commands[] = {

    { ngx_string("auth_hmac"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_flag_slot,
#else
      ngx_conf_set_flag_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_hmac_conf_t, enable),
      NULL },

    { ngx_string("auth_hmac_check_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_1MORE,
      ngx_http_auth_hmac_check_time,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_hmac_check_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE12,
      ngx_http_auth_hmac_check_token,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("auth_hmac_message"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_http_set_conditional_complex_value_slot,
#else
      ngx_http_set_complex_value_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_hmac_conf_t, message),
      NULL },

    { ngx_string("auth_hmac_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_http_set_conditional_complex_value_slot,
#else
      ngx_http_set_complex_value_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_hmac_conf_t, secret),
      NULL },

    { ngx_string("auth_hmac_algorithm"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_TAKE1,
#if (NGX_CONDITION)
      ngx_conf_set_conditional_str_slot,
#else
      ngx_conf_set_str_slot,
#endif
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_hmac_conf_t, algorithm),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_hmac_module_ctx = {
    ngx_http_auth_hmac_add_variables,           /* preconfiguration */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_auth_hmac_create_conf,             /* create location configuration */
    ngx_http_auth_hmac_merge_conf               /* merge location configuration */
};


ngx_module_t  ngx_http_auth_hmac_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_hmac_module_ctx,             /* module context */
    ngx_http_auth_hmac_commands,                /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t ngx_http_auth_hmac_vars[] = {

    { ngx_string("auth_hmac"), NULL,
      ngx_http_auth_hmac_variable,
      0, NGX_HTTP_VAR_CHANGEABLE, 0 },

      ngx_http_null_variable
};


static ngx_int_t
ngx_http_auth_hmac_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                            hash_buf[EVP_MAX_MD_SIZE];
    u_char                            hmac_buf[EVP_MAX_MD_SIZE];
    u_int                             hmac_len;
    time_t                            timestamp, now, start, end;
    ngx_int_t                         is_negative;
    ngx_int_t                         start_is_valid, end_is_valid;
    ngx_flag_t                        enable;
    ngx_str_t                         hash, key, value;
    ngx_str_t                        *algorithm;
    ngx_tm_t                          tm;
    const EVP_MD                     *evp_md;
    ngx_http_complex_value_t         *message, *secret;
    ngx_http_auth_hmac_conf_t        *conf;
    ngx_http_auth_hmac_time_conf_t   *time_conf;
    ngx_http_auth_hmac_token_conf_t  *token_conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_auth_hmac_module);

#if (NGX_CONDITION)
    enable = ngx_http_get_conditional_flag_value(r, conf->enable);
    time_conf = ngx_http_get_conditional_ptr_value(r, conf->time);
    token_conf = ngx_http_get_conditional_ptr_value(r, conf->token);
    message = ngx_http_get_conditional_ptr_value(r, conf->message);
    secret = ngx_http_get_conditional_ptr_value(r, conf->secret);
    algorithm = ngx_http_get_conditional_str_value(r, conf->algorithm);
#else
    enable = conf->enable;
    time_conf = conf->time;
    token_conf = conf->token;
    message = conf->message;
    secret = conf->secret;
    algorithm = &conf->algorithm;
#endif

    if (!enable
        || token_conf == NULL
        || message == NULL
        || secret == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth hmac: disabled");
        goto not_found;
    }

    /* no time range is set, no check for expiration */
    if (time_conf == NULL
        || (time_conf->start == NULL && time_conf->end == NULL))
    {
        goto token;
    }

    start = 0;
    if (time_conf->start == NULL) {
        start_is_valid = 0;

    } else {
        if (ngx_http_complex_value(r, time_conf->start, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (value.len > 0) {
            is_negative = 0;

            if (value.data[0] == '-') {
                is_negative = 1;
                value.data++;
                value.len--;
            }

            if (value.len >= 2
                && value.data[0] == '0' && value.data[1] == 'x')
            {
                start = ngx_hextoi(value.data + 2, value.len - 2);

            } else {
                start = ngx_atoi(value.data, value.len);
            }

            if (start == NGX_ERROR) {
                start_is_valid = 0;
            }

            if (is_negative) {
                start = -start;
            }

            start_is_valid = 1;
        } else {
            start_is_valid = 0;
        }
    }

    end = 0;
    if (time_conf->end == NULL) {
        end_is_valid = 0;

    } else {
        if (ngx_http_complex_value(r, time_conf->end, &value) != NGX_OK) {
            return NGX_ERROR;
        }

        if (value.len > 0) {
            is_negative = 0;

            if (value.data[0] == '-') {
                is_negative = 1;
                value.data++;
                value.len--;
            }

            if (value.len >= 2
                && value.data[0] == '0' && value.data[1] == 'x')
            {
                end = ngx_hextoi(value.data + 2, value.len - 2);

            } else {
                end = ngx_atoi(value.data, value.len);
            }

            if (end == NGX_ERROR) {
                end_is_valid = 0;
            }

            if (is_negative) {
                end = -end;
            }

            end_is_valid = 1;
        } else {
            end_is_valid = 0;
        }
    }

    /* invalid time range */
    if ((start_is_valid == 0 && end_is_valid == 0)
        || (start_is_valid == 1 && end_is_valid == 1 && start > end))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth hmac: invalid time range");
        goto not_found;
    }

    if (ngx_http_complex_value(r, time_conf->time, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    if (value.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth hmac: time is empty");
        goto not_found;
    }

    if (time_conf->time_mode == NGX_HTTP_AUTH_HMAC_TIMESTAMP) {
        timestamp = (time_t) ngx_atoi(value.data, value.len);

    } else if (time_conf->time_mode == NGX_HTTP_AUTH_HMAC_MSTIMESTAMP) {

        if (value.len < 4) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth hmac: time len too short");
            goto not_found;
        }

        /* cut off the milliseconds part */
        timestamp = (time_t) ngx_atoi(value.data , value.len - 3);

    } else if (time_conf->time_mode == NGX_HTTP_AUTH_HMAC_HEXTIMESTAMP) {
        timestamp = (time_t) ngx_hextoi(value.data, value.len);

    } else { /* NGX_HTTP_AUTH_HMAC_DATE */
        ngx_memzero(&tm, sizeof(ngx_tm_t));

        if (strptime((char *) value.data,
            (char *) time_conf->time_format.data, &tm) == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "failed to parse date string");
            return NGX_ERROR;
        }

        /* Convert to unix_time */
        timestamp = timegm(&tm);
        
        if (timestamp == (time_t) NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth hmac: date conversion failed");
            goto not_found;
        }

        timestamp -= time_conf->time_offset;
    }

    if (timestamp <= 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth hmac: timestamp must be positive num");
        goto not_found;
    }

    now = ngx_time();
    if ((start_is_valid && (now < timestamp + start))
        || (end_is_valid && (now > timestamp + end)))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth hmac: request not yet valid or expired");
        goto not_found;
    }

token:

    evp_md = EVP_get_digestbyname((const char*) algorithm->data);
    if (evp_md == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "auth hmac: unknown cryptographic "
                       "hash function \"%s\"", algorithm->data);

        return NGX_ERROR;
    }

    hash.len  = (u_int) EVP_MD_size(evp_md);
    hash.data = hash_buf;

    if (ngx_http_complex_value(r, token_conf->token, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    if (value.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth hmac: token is empty");
        goto not_found;
    }

    if (token_conf->token_digest == NGX_HTTP_AUTH_HMAC_HEX) {
        if (ngx_http_auth_hmac_hex_decode(&hash, &value) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth hmac: token hex decode fail");
            goto not_found;
        }

    } else if (token_conf->token_digest == NGX_HTTP_AUTH_HMAC_BASE64) {

        if (ngx_decode_base64(&hash, &value) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth hmac: token base64 decode fail");
            goto not_found;
        }

    } else if (token_conf->token_digest == NGX_HTTP_AUTH_HMAC_BASE64URL) {

        if (ngx_decode_base64url(&hash, &value) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "auth hmac: token base64url decode fail");
            goto not_found;
        }

    } else {
        hash = value;
    }

    if (hash.len != (u_int) EVP_MD_size(evp_md)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth hmac: token len mismatch");
        goto not_found;
    }

    if (ngx_http_complex_value(r, message, &value) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth hmac: message: \"%V\"", &value);

    if (ngx_http_complex_value(r, secret, &key) != NGX_OK) {
        return NGX_ERROR;
    }

    HMAC(evp_md, key.data, key.len, value.data, value.len, hmac_buf, &hmac_len);

    if (CRYPTO_memcmp(hash_buf, hmac_buf, EVP_MD_size(evp_md)) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth hmac: token value mismatch");
        goto not_found;
    }

    v->data = (u_char *) "1";
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_http_auth_hmac_create_conf(ngx_conf_t *cf)
{
    ngx_http_auth_hmac_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_hmac_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (NGX_CONDITION)
    conf->enable = NGX_CONF_UNSET_PTR;
    conf->time = NGX_CONF_UNSET_PTR;
    conf->token = NGX_CONF_UNSET_PTR;
    conf->message = NGX_CONF_UNSET_PTR;
    conf->secret = NGX_CONF_UNSET_PTR;
    conf->algorithm = NGX_CONF_UNSET_PTR;
#else
    conf->enable = NGX_CONF_UNSET;
#endif

    return conf;
}


static char *
ngx_http_auth_hmac_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_hmac_conf_t  *prev = parent;
    ngx_http_auth_hmac_conf_t  *conf = child;

#if (NGX_CONDITION)
    ngx_str_t  algorithm = ngx_string("sha256");

    if (ngx_conf_merge_conditional_flag_value(cf, &conf->enable, prev->enable,
                                              0)
        != NGX_OK
        || ngx_conf_merge_conditional_ptr_value(cf, &conf->time, prev->time,
                                                NULL)
           != NGX_OK
        || ngx_conf_merge_conditional_ptr_value(cf, &conf->token, prev->token,
                                                NULL)
           != NGX_OK
        || ngx_conf_merge_conditional_ptr_value(cf, &conf->message,
                                                prev->message, NULL)
           != NGX_OK
        || ngx_conf_merge_conditional_ptr_value(cf, &conf->secret,
                                                prev->secret, NULL)
           != NGX_OK
        || ngx_conf_merge_conditional_str_value(cf, &conf->algorithm,
                                                prev->algorithm, algorithm)
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
#else
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->time, prev->time, NULL);
    ngx_conf_merge_ptr_value(conf->token, prev->token, NULL);
    ngx_conf_merge_ptr_value(conf->message, prev->message, NULL);
    ngx_conf_merge_ptr_value(conf->secret, prev->secret, NULL);
    ngx_conf_merge_str_value(conf->algorithm, prev->algorithm, "sha256");
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_hmac_is_valid_num(ngx_str_t *s)
{
    u_char      *p;
    size_t       len;

    if (s == NULL || s->len == 0) {
        return 0;
    }

    p = s->data;
    len = s->len;

    if (*p == '-') {
        p++;
        len--;

        if (len == 0) {
            return 0;
        }
    }

    if (len > 2 && p[0] == '0' && (p[1] == 'x')) {
        p += 2;
        len -= 2;

        if (len == 0) {
            return 0;
        }

        while (len--) {
            if (!((*p >= '0' && *p <= '9')
                  || (*p >= 'a' && *p <= 'f')
                  || (*p >= 'A' && *p <= 'F')))
            {
                return 0;
            }
            p++;
        }

        return 1;
    }

    while (len--) {
        if (!(*p >= '0' && *p <= '9')) {
            return 0;
        }
        p++;
    }

    return 1;
}


static char *
ngx_http_auth_hmac_check_time(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_hmac_conf_t       *slcf = conf;
    ngx_http_auth_hmac_time_conf_t  *time_conf;

    time_t                            time_offset;
    ngx_str_t                         s;
    ngx_str_t                        *value;
    ngx_uint_t                        i, j;
    ngx_http_compile_complex_value_t  ccv;
#if (NGX_CONDITION)
    ngx_condition_expr_id_t           expr_id;
    ngx_conf_condition_ptr_ctx_t     *ctx;
#endif

#if (NGX_CONDITION)
    expr_id = ngx_condition_get_associated_expr_id(cf);

    if (slcf->time != NULL && slcf->time != NGX_CONF_UNSET_PTR
        && ngx_condition_find_expr_ctx(slcf->time, expr_id,
               sizeof(ngx_conf_condition_ptr_ctx_t),
               offsetof(ngx_conf_condition_ptr_ctx_t, expr_id))
           != NULL)
    {
        return "is duplicate";
    }
#else
    if (slcf->time != NGX_CONF_UNSET_PTR && slcf->time != NULL) {
        return "is duplicate";
    }
#endif

    time_conf = ngx_pcalloc(cf->pool,
                            sizeof(ngx_http_auth_hmac_time_conf_t));
    if (time_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    time_conf->time_mode = NGX_HTTP_AUTH_HMAC_TIMESTAMP;
    ngx_str_set(&time_conf->time_format, "%s");

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool,
                                sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    time_conf->time = ccv.complex_value;

    for (i = 2; i < cf->args->nelts; i++) {

        if (value[i].len > 7
            && ngx_strncmp(value[i].data, "format=", 7) == 0)
        {
            s.len = value[i].len - 7;
            s.data = value[i].data + 7;

            if (s.len == 2 && s.data[0] == '%' && s.data[1] == 's') {
                time_conf->time_mode = NGX_HTTP_AUTH_HMAC_TIMESTAMP;
                continue;
            }

            if (s.len == 3 && s.data[0] == '%'
                && s.data[1] == 'm' && s.data[2] == 's') {
                time_conf->time_mode = NGX_HTTP_AUTH_HMAC_MSTIMESTAMP;
                continue;
            }

            if (s.len == 2 && s.data[0] == '%' && s.data[1] == 'x') {
                time_conf->time_mode = NGX_HTTP_AUTH_HMAC_HEXTIMESTAMP;
                continue;
            }

            time_conf->time_mode = NGX_HTTP_AUTH_HMAC_DATE;
            time_conf->time_format = s;

            continue;
        }

        if (value[i].len > 9
            && ngx_strncmp(value[i].data, "timezone=", 9) == 0)
        {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            if (ngx_strncmp(s.data, "gmt", 3) != 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "invalid timezone format");
                return NGX_CONF_ERROR;
            }

            if (s.len == 3) {
                time_conf->time_offset = 0;
                continue;
            }

            if (s.len != 8
                || (s.data[3] != '+' && s.data[3] != '-'))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "invalid timezone format");
                return NGX_CONF_ERROR;
            }

            for (j = 4; j < 8; j++) {
                if (s.data[j] < '0' || s.data[j] > '9') {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid timezone value");
                    return NGX_CONF_ERROR;
                }
            }

            /* Parse timezone offset, e.g., +0800 or -0200 */
            time_offset = ((s.data[4] - '0') * 10
                            + (s.data[5] - '0')) * 3600;
            time_offset += ((s.data[6] - '0') * 10
                            + (s.data[7] - '0')) * 60;

            if (s.data[3] == '-') {
                time_offset = -time_offset;
            }

            time_conf->time_offset = time_offset;

            continue;
        }

        if (value[i].len > 12
            && ngx_strncmp(value[i].data, "range_start=", 12) == 0)
        {
            s.len = value[i].len - 12;
            s.data = value[i].data + 12;

            if (ngx_strlchr(s.data, s.data + s.len, '$') == NULL) {
                if (!ngx_http_auth_hmac_is_valid_num(&s)) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid numeric value in start parameter \"%V\"", &s);
                    return NGX_CONF_ERROR;
                }
            }

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                        sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            time_conf->start = ccv.complex_value;

            continue;
        }

        if (value[i].len >= 10
            && ngx_strncmp(value[i].data, "range_end=", 10) == 0)
        {
            s.len = value[i].len - 10;
            s.data = value[i].data + 10;

            if (ngx_strlchr(s.data, s.data + s.len, '$') == NULL) {
                if (!ngx_http_auth_hmac_is_valid_num(&s)) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "invalid numeric value in end parameter \"%V\"", &s);
                    return NGX_CONF_ERROR;
                }
            }

            ccv.cf = cf;
            ccv.value = &s;
            ccv.complex_value = ngx_palloc(cf->pool,
                                        sizeof(ngx_http_complex_value_t));
            if (ccv.complex_value == NULL) {
                return NGX_CONF_ERROR;
            }

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            time_conf->end = ccv.complex_value;
        }
    }

#if (NGX_CONDITION)
    if (slcf->time == NULL || slcf->time == NGX_CONF_UNSET_PTR) {
        slcf->time = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_conf_condition_ptr_ctx_t));
        if (slcf->time == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx = ngx_array_push(slcf->time);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->value = time_conf;
    ctx->expr_id = expr_id;
#else
    slcf->time = time_conf;
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_auth_hmac_check_token(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_hmac_conf_t        *slcf = conf;
    ngx_http_auth_hmac_token_conf_t  *token_conf;

    ngx_str_t                        *value;
    ngx_http_compile_complex_value_t  ccv;
#if (NGX_CONDITION)
    ngx_condition_expr_id_t           expr_id;
    ngx_conf_condition_ptr_ctx_t     *ctx;
#endif

#if (NGX_CONDITION)
    expr_id = ngx_condition_get_associated_expr_id(cf);

    if (slcf->token != NULL && slcf->token != NGX_CONF_UNSET_PTR
        && ngx_condition_find_expr_ctx(slcf->token, expr_id,
               sizeof(ngx_conf_condition_ptr_ctx_t),
               offsetof(ngx_conf_condition_ptr_ctx_t, expr_id))
           != NULL)
    {
        return "is duplicate";
    }
#else
    if (slcf->token != NGX_CONF_UNSET_PTR && slcf->token != NULL) {
        return "is duplicate";
    }
#endif

    token_conf = ngx_pcalloc(cf->pool,
                             sizeof(ngx_http_auth_hmac_token_conf_t));
    if (token_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    token_conf->token_digest = NGX_HTTP_AUTH_HMAC_HEX;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = ngx_palloc(cf->pool,
                                sizeof(ngx_http_complex_value_t));
    if (ccv.complex_value == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    token_conf->token = ccv.complex_value;

    if (cf->args->nelts == 3) {

        if (ngx_strncmp(value[2].data, "digest=hex", 10) == 0) {
            token_conf->token_digest = NGX_HTTP_AUTH_HMAC_HEX;

        } else if (ngx_strncmp(value[2].data, "digest=base64url", 16) == 0) {
            token_conf->token_digest = NGX_HTTP_AUTH_HMAC_BASE64URL;

        } else if (ngx_strncmp(value[2].data, "digest=base64", 13) == 0) {
            token_conf->token_digest = NGX_HTTP_AUTH_HMAC_BASE64;

        } else if (ngx_strncmp(value[2].data, "digest=bin", 10) == 0) {
            token_conf->token_digest = NGX_HTTP_AUTH_HMAC_BIN;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid token format: \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

    }

#if (NGX_CONDITION)
    if (slcf->token == NULL || slcf->token == NGX_CONF_UNSET_PTR) {
        slcf->token = ngx_array_create(cf->pool, 2,
                                       sizeof(ngx_conf_condition_ptr_ctx_t));
        if (slcf->token == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    ctx = ngx_array_push(slcf->token);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->value = token_conf;
    ctx->expr_id = expr_id;
#else
    slcf->token = token_conf;
#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_hmac_hex_decode(ngx_str_t *dst, ngx_str_t *src)
{
    size_t      i, half_len;
    u_char     *p;
    ngx_int_t   n;

    if (src->len % 2 != 0) {
        return NGX_ERROR;
    }

    half_len = src->len / 2;

    if (dst->len < half_len) {
        return NGX_ERROR;
    }

    p = src->data;
    for (i = 0; i < half_len; i++) {

        n = ngx_hextoi(p, 2);
        if (n == NGX_ERROR || n > 255) {
            return NGX_ERROR;
        }

        dst->data[i] = (u_char) n;
        p += 2;
    }

    dst->len = half_len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_hmac_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_auth_hmac_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
