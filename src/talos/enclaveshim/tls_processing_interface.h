/*
 * Copyright 2017 Imperial College London
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TLS_PROCESSING_INTERFACE_H_
#define TLS_PROCESSING_INTERFACE_H_

#include "openssl/ossl_typ.h"

/***** public function: you need to use them to register your callbacks *****/

void tls_processing_register_ssl_read_processing_cb(void (*cb)(const SSL*, char*, unsigned int*));
void tls_processing_register_ssl_write_processing_cb(void (*cb)(const SSL*, char*, unsigned int*));
void tls_processing_register_set_ssl_type_cb(void (*cb)(const void*, const long));
void tls_processing_register_new_connection_cb(void (*cb)(const SSL*));
void tls_processing_register_free_connection_cb(void (*cb)(const SSL*));


/***** private functions: called by TaLoS *****/

// Called by TaLoS to initialize your TLS processing module.  It calls
// tls_processing_module_init(), which must be defined in your module.
void ecall_tls_processing_module_init(void);

// called by ssl3_read_bytes() in ssl/s3_pkt.c when data is read from the TLS connection socket
void tls_processing_ssl_read(const SSL* s, char* data, unsigned int* len);

// called by do_ssl3_write() in ssl/s3_pkt.c when data is read from the TLS connection socket
void tls_processing_ssl_write(const SSL* s, char* data, unsigned int* len);

// called by BIO_int_ctrl when the command is BIO_C_SET_FD. Originally used for Squid in SSL proxy mode
void tls_processing_set_ssl_type(const void* b, const long type);

// called from SSL_new() in ssl/ssl_lib.c
void tls_processing_new_connection(const SSL* s);

// called from SSL_free() in ssl/ssl_lib.c
void tls_processing_free_connection(const SSL* s);

#endif
