#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include <jwt.h>
#include <jansson.h>

#include "ngx_http_study_jwt.h"

typedef struct {
  ngx_str_t study_root;
  ngx_str_t study_rex_str;
  ngx_str_t study_jwt_key;
} ngx_http_study_loc_conf_t;

typedef struct {
  ngx_str_t username;
  ngx_str_t service_uri;
} ngx_http_study_ctx_t;

static ngx_int_t ngx_http_study_init(ngx_conf_t *cf);

static void *ngx_http_study_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_study_root(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_study_rex_str(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_study_jwt_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* variable function */
static ngx_int_t ngx_http_study_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_study_variable_username(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_study_variable_service_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_command_t ngx_http_study_commands[] = {
  {
    ngx_string("study_root"),
    NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
    ngx_http_study_root,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_study_loc_conf_t, study_root),
    NULL
  },
  {
    ngx_string("study_rex_str"),
    NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
    ngx_http_study_rex_str,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_study_loc_conf_t, study_rex_str),
    NULL
  },
  {
    ngx_string("study_jwt_key"),
    NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
    ngx_http_study_jwt_key,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_study_loc_conf_t, study_jwt_key),
    NULL
  },
  ngx_null_command
};

/* variable */
static ngx_http_variable_t ngx_http_study_variables[] = {
  {
    ngx_string("study_username"),
    NULL,
    ngx_http_study_variable_username, 0,
    NGX_HTTP_VAR_NOCACHEABLE, 0
  },
  {
    ngx_string("study_service_uri"),
    NULL,
    ngx_http_study_variable_service_uri, 0,
    NGX_HTTP_VAR_NOCACHEABLE, 0
  }
};

static ngx_http_module_t ngx_http_study_module_ctx = {
  ngx_http_study_add_variables,
  ngx_http_study_init,
  NULL,
  NULL,
  NULL,
  NULL,
  ngx_http_study_create_loc_conf,
  NULL
};

ngx_module_t ngx_http_study_module = {
  NGX_MODULE_V1,
  &ngx_http_study_module_ctx,
  ngx_http_study_commands,
  NGX_HTTP_MODULE,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_study_handler(ngx_http_request_t *r) {

  ngx_http_study_loc_conf_t *lconf;
  ngx_http_study_ctx_t      *geoctx;
  ngx_regex_t                  *re;
  ngx_regex_compile_t           rc;
  u_char                        errstr[NGX_MAX_CONF_ERRSTR];
  
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "study module is called!");

  /* create ctx */
  geoctx = ngx_pcalloc(r->pool,sizeof(ngx_http_study_ctx_t));
  if (geoctx == NULL) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "create ctx failed");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_http_set_ctx(r, geoctx, ngx_http_study_module);

  lconf = ngx_http_get_module_loc_conf(r, ngx_http_study_module);
  if (lconf->study_rex_str.len == 0) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "study string is empty!");
    return NGX_DECLINED;
  } else {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "study string: %V", &lconf->study_rex_str);
  }

  // check cookie header
  if (r->headers_in.cookie == NULL) {
    r->headers_out.status = NGX_HTTP_UNAUTHORIZED;

    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
      return NGX_ERROR;
    }
      
    r->headers_out.www_authenticate = h;
      
    h->hash = 1;
    h->next = NULL;
    return NGX_HTTP_UNAUTHORIZED;
  }

  ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

  rc.pattern = lconf->study_rex_str;
  rc.pool = r->pool;
  rc.err.len = NGX_MAX_CONF_ERRSTR;
  rc.err.data = errstr;

  if (ngx_regex_compile(&rc) != NGX_OK) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "regex error: %V", &rc.err.data);
    return NGX_ERROR;
  }

  re = rc.regex;

  // TODO
  /*
  ngx_table_elt_t *auth_header;

  auth_header = r->headers_in.authorization;
  if (auth_header == NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "no auth header");
  } else {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "has auth he\ader");
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "auth header: %s", auth_header->value.data);
  }

  if (auth_header->next != NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "auth header next is not null");
  } else {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "auth header next is null");
  }
  */

  // check cookie
  /*
  if (r->headers_in.cookie != NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "has cookie");

    ngx_table_elt_t* data = r->headers_in.cookie;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "cookie data: %V", &data->value);

    u_char* begin = (u_char*)ngx_strstr(data->value.data, "token=");
    if (begin != NULL) {
      ngx_str_t v;
      ngx_str_null(&v);

      v.data = begin + 6;
      v.len = data->value.len - (begin - data->value.data) - 6;

      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get token length: %d", v.len);

      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get token data: %V", &v);

      jwt_t *jwt = NULL;

      int size = lconf->study_jwt_key.len;
      u_char *decoded_data = base64_decode(r, lconf->study_jwt_key.data, lconf->study_jwt_key.len, (size_t*)&size);
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "decode size: %d", size);
      if (decoded_data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "decode key failed!");
      } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "decode key success!");
      }

      if (jwt_decode(&jwt, (char*)v.data, decoded_data, size)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: failed to parse jwt");
        return NGX_DECLINED;
      } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: parse ok");

        const char *sub = jwt_get_grant(jwt, "sub");
        geoctx->username.len = strlen(sub);
        geoctx->username.data = ngx_pcalloc(r->pool, geoctx->username.len);
        ngx_memcpy(geoctx->username.data, sub, geoctx->username.len);

        jwt_free(jwt);
        jwt = NULL;
      }
    }
  } else {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "nocookie");
  }
  */

  ngx_int_t  n;
  int        captures[(1 + rc.captures) * 3];

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "captures size: %d", rc.captures);
  
  n = ngx_regex_exec(re, &r->uri, captures, (1 + rc.captures) * 3);
  if (n >= 0) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "regex matched: %d", n);

    int uri_len = 0;

    // get service url length from last capture
    uri_len = captures[(n - 1) * 2 + 1];
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "service uri length: %d", uri_len);

    // compose service url
    geoctx->service_uri.len = uri_len + lconf->study_root.len + 1;
    geoctx->service_uri.data = ngx_pcalloc(r->pool, geoctx->service_uri.len);
    ngx_snprintf(geoctx->service_uri.data, lconf->study_root.len + 1, "/%s", lconf->study_root.data);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "service uri: %s", geoctx->service_uri.data);

    u_char *p_start = geoctx->service_uri.data + 1 + lconf->study_root.len;
    ngx_snprintf(p_start, uri_len, "%s", r->uri.data);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "has cookie");

    ngx_table_elt_t* data = r->headers_in.cookie;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "cookie data: %V", &data->value);

    // TODO: We should consider that if token is not tail of the header
    u_char* begin = (u_char*)ngx_strstr(data->value.data, "token=");
    if (begin != NULL) {
      u_char* token_cursor = begin + 6;
      u_char* token_end = data->value.data + data->value.len;

      while (token_cursor != token_end && *(char*)token_cursor != ';') {
        token_cursor++;
      }

      ngx_str_t vv;
      ngx_str_null(&vv);

      vv.len = token_cursor - (begin + 6);
      vv.data = ngx_pcalloc(r->pool, vv.len);
      ngx_memcpy(vv.data, begin + 6, vv.len);

      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get token length: %d", vv.len);

      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "get token data: %V", &vv);
        
      jwt_t *jwt = NULL;

      // decode seurity key
      int size = lconf->study_jwt_key.len;
      u_char *decoded_data = base64_decode(r, lconf->study_jwt_key.data, lconf->study_jwt_key.len, (size_t*)&size);
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "decode size: %d", size);
      if (decoded_data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "decode key failed!");
        return NGX_ERROR;
      } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "decode key success!");
      }

      // verify token
      if (jwt_decode(&jwt, (char*)vv.data, decoded_data, size)) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: failed to parse jwt");
        
        r->headers_out.status = NGX_HTTP_UNAUTHORIZED;

        ngx_table_elt_t *h;

        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
          return NGX_ERROR;
        }
        
        r->headers_out.www_authenticate = h;
        
        h->hash = 1;
        h->next = NULL;
        return NGX_HTTP_UNAUTHORIZED;
      } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: parse ok");

        // get subject (username) and save into the variable
        const char *sub = jwt_get_grant(jwt, "sub");
        geoctx->username.len = strlen(sub);
        geoctx->username.data = ngx_pcalloc(r->pool, geoctx->username.len);
        ngx_memcpy(geoctx->username.data, sub, geoctx->username.len);

        jwt_free(jwt);
        jwt = NULL;
      }
    } else {
      r->headers_out.status = NGX_HTTP_UNAUTHORIZED;

      ngx_table_elt_t *h;

      h = ngx_list_push(&r->headers_out.headers);
      if (h == NULL) {
        return NGX_ERROR;
      }
      
      r->headers_out.www_authenticate = h;
      
      h->hash = 1;
      h->next = NULL;
      return NGX_HTTP_UNAUTHORIZED;
    }
  } else if (n == NGX_REGEX_NO_MATCHED) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "regex no matched");

    r->headers_out.status = NGX_HTTP_UNAUTHORIZED;

    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
      return NGX_ERROR;
    }

    r->headers_out.www_authenticate = h;

    h->hash = 1;
    h->next = NULL;
    return NGX_HTTP_UNAUTHORIZED;

  } else {
    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "regex failed: %i", n);
  }
  
  return NGX_OK;
}

static void *
ngx_http_study_create_loc_conf(ngx_conf_t *cf) {

  ngx_http_study_loc_conf_t * lconf = NULL;
  lconf = ngx_pcalloc(cf->pool, sizeof(ngx_http_study_loc_conf_t));
  if (lconf == NULL) {
    return NULL;
  }

  ngx_str_null(&lconf->study_rex_str);

  return lconf;
}

static char *
ngx_http_study_root(ngx_conf_t *cf, ngx_command_t *cmd, void * conf) {

  ngx_http_study_loc_conf_t *lconf;

  lconf = conf;
  char *rv = ngx_conf_set_str_slot(cf, cmd, conf);

  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "study root: %s", lconf->study_root.data);

  return rv;
}

static char *
ngx_http_study_rex_str(ngx_conf_t *cf, ngx_command_t *cmd, void * conf) {

  ngx_http_study_loc_conf_t *lconf;

  lconf = conf;
  char *rv = ngx_conf_set_str_slot(cf, cmd, conf);

  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "study regex string: %s", lconf->study_rex_str.data);

  return rv;
}

static char *
ngx_http_study_jwt_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
  
  ngx_str_t                    *value = cf->args->elts;
  ngx_http_study_loc_conf_t *lconf = conf;
  ngx_str_t                    *key = &lconf->study_jwt_key;

  ngx_str_t *key_str = &value[1];
  if (key_str->len == 0 || key_str->data == NULL) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "study jwt: Invalid key");
    return NGX_CONF_ERROR;
  }
  
  key->data = key_str->data;
  key->len = key_str->len;

  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "jwt key: %s", key->data);
  
  return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_study_init(ngx_conf_t *cf) {

  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t * cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_study_handler;

  return NGX_OK;
}

static ngx_int_t
ngx_http_study_variable_username(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {

  ngx_http_study_ctx_t     *ctx;

  v->not_found = 1;

  ctx = ngx_http_get_module_ctx(r, ngx_http_study_module);
  if (ctx == NULL) {
    v->not_found = 1;
    return NGX_OK;
  }

  if (ctx->username.len == 0 || ctx->username.data == NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ctx username is null");
    return NGX_OK;
  }
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ctx username: %s", ctx->username.data);
  
  v->len = ctx->username.len;
  v->data = ctx->username.data;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  
  return NGX_OK;
}

static ngx_int_t
ngx_http_study_variable_service_uri(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {

  ngx_http_study_ctx_t     *ctx;

  v->not_found = 1;

  ctx = ngx_http_get_module_ctx(r, ngx_http_study_module);
  if (ctx == NULL) {
    v->not_found = 1;
    return NGX_OK;
  }

  if (ctx->service_uri.len == 0 || ctx->service_uri.data == NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ctx service uri is null");
    return NGX_OK;
  }
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ctx service uri: %s", ctx->service_uri.data);
  
  v->len = ctx->service_uri.len;
  v->data = ctx->service_uri.data;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  
  return NGX_OK;
}

static ngx_int_t
ngx_http_study_add_variables(ngx_conf_t *cf) {

  ngx_http_variable_t  *var, *v;

  for (v = ngx_http_study_variables; v->name.len; v++) {
    var = ngx_http_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
      return NGX_ERROR;
    }

    var->get_handler = v->get_handler;
    var->data = v->data;
  }

  return NGX_OK;
}
