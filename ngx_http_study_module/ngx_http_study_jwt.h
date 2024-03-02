#ifndef _NGX_HTTP_STUDY_JWT_H_
#define _NGX_HTTP_STUDY_JWT_H_ (1)

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

#include <stddef.h>

/**
 * Reference: https://www.mycplus.com/source-code/c-source-code/base64-encode-decode/
 */
unsigned char *
base64_decode(ngx_http_request_t *r, const u_char *data,
              size_t input_length,
              size_t *output_length);

#endif // _NGX_HTTP_STUDY_JWT_H_
