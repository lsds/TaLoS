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

#include <stdio.h>

#include "tls_processing_interface.h"

#define CHECK_AND_CALL_CB(cb, ...) {\
	if (cb) { \
		cb(__VA_ARGS__); \
	} \
}

// this function must be defined by your TLS processing module
extern void tls_processing_module_init(void);

static void (*ssl_read_processing_cb)(const SSL*, char*, unsigned int*) = NULL;
static void (*ssl_write_processing_cb)(const SSL*, char*, unsigned int*) = NULL;
static void (*set_ssl_type_cb)(const void*, const long) = NULL;
static void (*new_connection_cb)(const SSL*) = NULL;
static void (*free_connection_cb)(const SSL*) = NULL;

void tls_processing_register_ssl_read_processing_cb(void (*cb)(const SSL*, char*, unsigned int*)) {
	ssl_read_processing_cb = cb;
}

void tls_processing_register_ssl_write_processing_cb(void (*cb)(const SSL*, char*, unsigned int*)) {
	ssl_write_processing_cb = cb;
}

void tls_processing_register_set_ssl_type_cb(void (*cb)(const void*, const long)) {
	set_ssl_type_cb = cb;
}

void tls_processing_register_new_connection_cb(void (*cb)(const SSL*)) {
	new_connection_cb = cb;
}

void tls_processing_register_free_connection_cb(void (*cb)(const SSL*)) {
	free_connection_cb = cb;
}


/***** private functions: called by TaLoS *****/

// Called by TaLoS to initialize your TLS processing module.  It calls
// tls_processing_module_init(), which must be defined in your module.
void ecall_tls_processing_module_init(void) {
	tls_processing_module_init();
}

// called by ssl3_read_bytes() in ssl/s3_pkt.c when data is read from the TLS connection socket
void tls_processing_ssl_read(const SSL* s, char* data, unsigned int* len) {
	CHECK_AND_CALL_CB(ssl_read_processing_cb, s, data, len);
}

// called by do_ssl3_write() in ssl/s3_pkt.c when data is read from the TLS connection socket
void tls_processing_ssl_write(const SSL* s, char* data, unsigned int* len) {
	CHECK_AND_CALL_CB(ssl_write_processing_cb, s, data, len);
}

// called by BIO_int_ctrl when the command is BIO_C_SET_FD. Originally used for Squid in SSL proxy mode
void tls_processing_set_ssl_type(const void* b, const long type) {
	CHECK_AND_CALL_CB(set_ssl_type_cb, b, type);
}

// called from SSL_new() in ssl/ssl_lib.c
void tls_processing_new_connection(const SSL* s) {
	CHECK_AND_CALL_CB(new_connection_cb, s);
}

// called from SSL_free() in ssl/ssl_lib.c
void tls_processing_free_connection(const SSL* s) {
	CHECK_AND_CALL_CB(free_connection_cb, s);
}
