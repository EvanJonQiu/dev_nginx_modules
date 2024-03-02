#include "ngx_http_study_jwt.h"

#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

unsigned char *
base64_decode(ngx_http_request_t *r, const u_char *data,
              size_t input_length,
              size_t *output_length) {

  ngx_str_t decoding_table;
  ngx_str_t decoded_data;
  
  ngx_str_null(&decoding_table);
  ngx_str_null(&decoded_data);

  decoding_table.len = 256;
  decoding_table.data = ngx_pcalloc(r->pool, decoding_table.len);
  if (decoding_table.data == NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "alloc memeory for decoding_table failed!");
    return NULL;
  } else {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "alloc memeory for decoding_table success!");
  }
  for (int i = 0; i < 64; i++)
        decoding_table.data[(unsigned char) encoding_table[i]] = i;

  if (input_length % 4 != 0) return NULL;
 
  int buf_size = input_length / 4 * 3;
  if (data[input_length - 1] == '=') (buf_size)--;
  if (data[input_length - 2] == '=') (buf_size)--;

  *output_length = buf_size;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "output_length length: %d", buf_size);

  decoded_data.len = buf_size;
  decoded_data.data = ngx_pnalloc(r->pool, decoded_data.len);
  if (decoded_data.data == NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "alloc memeory for decoded_data failed!");
    return NULL;
  } else {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "alloc memeory for decoded_data success!");
  }
  for (int i = 0, j = 0; i < (int)input_length;) {
 
    uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table.data[(unsigned char)data[i++]];
    uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table.data[(unsigned char)data[i++]];
    uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table.data[(unsigned char)data[i++]];
    uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table.data[(unsigned char)data[i++]];
 
    uint32_t triple = (sextet_a << 3 * 6)
      + (sextet_b << 2 * 6)
      + (sextet_c << 1 * 6)
      + (sextet_d << 0 * 6);
 
    if (j < (int)*output_length) decoded_data.data[j++] = (triple >> 2 * 8) & 0xFF;
    if (j < (int)*output_length) decoded_data.data[j++] = (triple >> 1 * 8) & 0xFF;
    if (j < (int)*output_length) decoded_data.data[j++] = (triple >> 0 * 8) & 0xFF;
  }
  
  return decoded_data.data;
}

