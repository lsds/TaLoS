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
#include <string.h>

#include "openssl/ossl_typ.h"
#include "tls_processing_interface.h"
#include "hashmap.h"
#include "enclaveshim_config.h"

// define this macro to activate this module
#undef DO_LOGGING

// define this macro if you are using this module with Squid
#undef LOG_FOR_SQUID

#ifdef COMPILE_WITH_INTEL_SGX
//#include "sgx_error.h"
extern int my_printf(const char *format, ...);
#else
#define my_printf(format, ...) printf(format, ##__VA_ARGS__)
#endif

#ifdef COMPILE_WITH_INTEL_SGX
	#include <sgx_spinlock.h>
  	#include "enclaveshim_ocalls.h"
	#include "enclave_t.h"
	#define THREAD_MUTEX_INITIALIZER SGX_SPINLOCK_INITIALIZER
	#define pthread_mutex_lock(m) sgx_spin_lock(m)
	#define pthread_mutex_unlock(m) sgx_spin_unlock(m)
	typedef sgx_spinlock_t thread_mutex_t;
#else
	#include <pthread.h>
	#include <unistd.h>
	#include "openssl_types.h"
	#define THREAD_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
	#define my_fprintf(fd, format, ...) printf(format, ##__VA_ARGS__)
	typedef pthread_mutex_t thread_mutex_t;
#endif

#ifdef LOG_FOR_SQUID
// from squid (bio.h)
#define BIO_TO_CLIENT 6000
#define BIO_TO_SERVER 6001

static hashmap* bio2type = NULL;
static thread_mutex_t bio2type_mutex = THREAD_MUTEX_INITIALIZER;
#endif


#ifdef DO_LOGGING

void log_https_request(const SSL* s, char* req, int* len) {
#ifdef LOG_FOR_SQUID
	long type;
	pthread_mutex_lock(&bio2type_mutex);
	type = (long)hashmapGet(bio2type, (unsigned long)s->rbio);
	pthread_mutex_unlock(&bio2type_mutex);
	if (type != BIO_TO_CLIENT) {
		my_printf("%s SSL %p, this is not BIO_TO_CLIENT so don't log\n", __func__, s);
		return; // Squid, this is not a message between the client and the proxy, so don't log
	}
#endif
	my_printf("%s SSL %p, there is a request of %d bytes\n", __func__, s, *len);
}
void log_https_reply(const SSL* s, char* rep, int* len) {
#ifdef LOG_FOR_SQUID
	long type;
	pthread_mutex_lock(&bio2type_mutex);
	type = (long)hashmapGet(bio2type, (unsigned long)s->wbio);
	pthread_mutex_unlock(&bio2type_mutex);
	if (type != BIO_TO_CLIENT) {
		my_fprintf(0, "%s SSL %p, this is not BIO_TO_CLIENT so don't log\n", __func__, s);
		return; // Squid, this is not a message between the client and the proxy, so don't log
	}
#endif
	my_printf("%s SSL %p, there is a reply of %d bytes\n", __func__, s, *len);
}

void log_set_ssl_type(const void* b, const long type) {
#ifdef LOG_FOR_SQUID
	pthread_mutex_lock(&bio2type_mutex);
	if (!bio2type) {
		bio2type = hashmapCreate(0);
	}
	hashmapInsert(bio2type, (void*)type, (unsigned long)b);
	pthread_mutex_unlock(&bio2type_mutex);

	//for log_req and log_rep we need to retrieve the bio on the ssl object and check the type
	//if BIO_TO_CLIENT then we can log, otherwise there is no need
#else
	(void)b;
	(void)type;
#endif
}

void log_new_connection(const SSL* s) {
	my_printf("%s new connection at %p\n", __func__, s);
}

void log_free_connection(const SSL* s) {
#ifdef LOG_FOR_SQUID
	pthread_mutex_lock(&bio2type_mutex);
	hashmapRemove(bio2type, (unsigned long)s->rbio);
	hashmapRemove(bio2type, (unsigned long)s->wbio);
	pthread_mutex_unlock(&bio2type_mutex);
#endif
	my_printf("%s connection at %p has been closed\n", __func__, s);
}

#endif // DO_LOGGING


void tls_processing_module_init() {
#ifdef DO_LOGGING
	tls_processing_register_ssl_read_processing_cb(log_https_request);
	tls_processing_register_ssl_write_processing_cb(log_https_reply);
	tls_processing_register_set_ssl_type_cb(log_set_ssl_type);
	tls_processing_register_new_connection_cb(log_new_connection);
	tls_processing_register_free_connection_cb(log_free_connection);
#endif
}
