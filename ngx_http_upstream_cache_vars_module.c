
/*
 * Copyright (C) Hanada
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_upstream_cache_vars_add_variable(ngx_conf_t *cf);

static ngx_int_t ngx_http_upstream_cache_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_key_crc32_variable(
	ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_key_hash_variable(
	ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_main_hash_variable(
	ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_variant_hash_variable(
	ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_file_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_age_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_create_time_variable(
	ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_expire_time_variable(
	ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_ttl_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_cache_max_age_variable(
	ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


static ngx_http_module_t  ngx_http_upstream_cache_vars_module_ctx = {
    ngx_http_upstream_cache_vars_add_variables,    /* preconfiguration */
    NULL,                                          /* postconfiguration */

    NULL,                                          /* create main configuration */
    NULL,                                          /* init main configuration */

    NULL,                                          /* create server configuration */
    NULL,                                          /* merge server configuration */

    NULL,                                          /* create location configuration */
    NULL                                           /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_cache_vars_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_cache_vars_module_ctx,      /* module context */
    NULL,                                          /* module directives */
    NGX_HTTP_MODULE,                               /* module type */
    NULL,                                          /* init master */
    NULL,                                          /* init module */
    NULL,                                          /* init process */
    NULL,                                          /* init thread */
    NULL,                                          /* exit thread */
    NULL,                                          /* exit process */
    NULL,                                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_upstream_cache_vars[] = {
    { ngx_string("upstream_cache_key"), NULL,
	  ngx_http_upstream_cache_key_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_key_crc32"), NULL,
	  ngx_http_upstream_cache_key_crc32_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_key_hash"), NULL,
	  ngx_http_upstream_cache_key_hash_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_main_hash"), NULL,
	  ngx_http_upstream_cache_main_hash_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_variant_hash"), NULL,
	  ngx_http_upstream_cache_variant_hash_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_file"), NULL,
	  ngx_http_upstream_cache_file_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_age"), NULL,
	  ngx_http_upstream_cache_age_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_create_time"), NULL,
	  ngx_http_upstream_cache_create_time_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_expire_time"), NULL,
	  ngx_http_upstream_cache_expire_time_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_ttl"), NULL,
	  ngx_http_upstream_cache_ttl_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_cache_max_age"), NULL,
	  ngx_http_upstream_cache_max_age_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_upstream_cache_vars_add_variable(ngx_conf_t *cf)
{
    ngx_http_variable_t  *v;
	ngx_http_variable_t  *var;

    for (v = ngx_http_upstream_cache_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char            *p;
    size_t             len;
    ngx_str_t         *key;
    ngx_uint_t         i;
    ngx_http_cache_t  *c;

    if (r->cache == NULL || r->cache->keys.nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    c = r->cache;

    len = 0;
    key = c->keys.elts;

    for (i = 0; i < c->keys.nelts; i++) {
        len += key[i].len;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    for (i = 0; i < c->keys.nelts; i++) {
        p = ngx_cpymem(p, key[i].data, key[i].len);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_key_crc32_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *crc32_str;

    if (r->cache == NULL || r->cache->crc32.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    crc32_str = ngx_pnalloc(r->pool, 8 + 1);
    if (crc32_str == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(crc32_str, "%08x", (uint32_t) r->cache->crc32);

    v->data = crc32_str;
    v->len = 8;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_key_hash_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *key_hash;

    if (r->cache == NULL || r->cache->key.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    key_hash = ngx_pnalloc(r->pool, r->cache->key.len * 2 + 1);
    if (key_hash == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(key_hash, r->cache->key.data, r->cache->key.len);


    key_hash[r->cache->key.len * 2] = '\0';

    v->data = key_hash;
    v->len = r->cache->key.len * 2;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_main_hash_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *main_hash;

    if (r->cache == NULL || r->cache->main.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    main_hash = ngx_pnalloc(r->pool, r->cache->main.len * 2 + 1);
    if (main_hash == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(main_hash, r->cache->main.data, r->cache->main.len);


    main_hash[r->cache->main.len * 2] = '\0';

    v->data = main_hash;
    v->len = r->cache->main.len * 2;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_variant_hash_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char *variant_hash;

    if (r->cache == NULL || r->cache->variant.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    variant_hash = ngx_pnalloc(r->pool, r->cache->variant.len * 2 + 1);
    if (variant_hash == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(variant_hash, r->cache->variant.data, r->cache->variant.len);


    variant_hash[r->cache->variant.len * 2] = '\0';

    v->data = variant_hash;
    v->len = r->cache->variant.len * 2;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_file_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cache_t  *c;

    c = r->cache;
    if (c == NULL || c->file.name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = c->file.name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = c->file.name.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_age_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;
    time_t   now, age;

    if (r->upstream == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!r->cached
        || r->cache == NULL
        || r->upstream->cache_status == NGX_HTTP_CACHE_REVALIDATED)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    now = ngx_time();
    age = now - r->cache->date;

    if (r->cache->date > now) {
        age = 0;
    }

    v->len = ngx_sprintf(p, "%T", age) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_create_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->upstream == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!r->cached
        || r->cache == NULL
        || r->upstream->cache_status == NGX_HTTP_CACHE_REVALIDATED)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", r->cache->date) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_expire_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->upstream == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!r->cached
        || r->cache == NULL
        || r->upstream->cache_status == NGX_HTTP_CACHE_REVALIDATED)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", r->cache->valid_sec) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_ttl_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;
    time_t   now, ttl;

    if (r->upstream == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!r->cached
        || r->cache == NULL
        || r->upstream->cache_status == NGX_HTTP_CACHE_REVALIDATED)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    now = ngx_time();
    ttl = r->cache->valid_sec - now;

    if (r->cache->valid_sec < now) {
        ttl = 0;
    }

    v->len = ngx_sprintf(p, "%T", ttl) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_cache_max_age_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;
    time_t   max_age;

    if (r->upstream == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (!r->cached
        || r->cache == NULL
        || r->upstream->cache_status == NGX_HTTP_CACHE_REVALIDATED)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    max_age = r->cache->valid_sec - r->cache->date;

    v->len = ngx_sprintf(p, "%T", max_age) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
}
