/*
 * Copyright 2017 Imperial College London
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at   
 * 
 * 	http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ENCLAVESHIM_OCALLS_H_
#define ENCLAVESHIM_OCALLS_H_

#include <stddef.h>

#include "enclaveshim_config.h"

int my_fprintf(FILE *stream, const char *format, ...);
int my_printf(const char *format, ...);

void ocall_init_async_ocalls(void* oq, int tid, int appthreads, int sgxthreads, int lthreadtasks, int ncycles);

long execute_async_bio_ctrl(void* b, int cmd, long argl, void *arg, void* cb);
int execute_async_bio_write(void* b, char* buf, int len, void* cb);
int execute_async_bio_destroy(void* b, void* cb);
void* execute_async_ocall_malloc(size_t size);
void execute_async_ocall_free(void* ptr);
void* execute_bio_ocall_malloc(size_t size);
void execute_bio_ocall_free(void* ptr);
int execute_async_bio_read(void* b, char* buf, int len, void* cb);

DH* ocall_SSL_CTX_set_tmp_dh_cb_wrapper(SSL *ssl, int is_export, int keylength, void* cb);
int ocall_alpn_select_cb_async_wrapper(SSL* s, unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg, void* cb);
int ssl_ctx_set_next_proto_select_async_cb_wrapper(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg, void* cb);

#endif
