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

#include "hashmap.h"
#include "enclaveshim_logpoint.h"

#ifdef DO_LOGGING
#include "logpoint.h"
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

static hashmap* connections = NULL;
static thread_mutex_t connections_mutex = THREAD_MUTEX_INITIALIZER;

#ifdef LOG_FOR_SQUID
static hashmap* bio2type = NULL;
static thread_mutex_t bio2type_mutex = THREAD_MUTEX_INITIALIZER;
#endif

#if defined(DO_LOGGING) && !defined(COMPILE_WITH_INTEL_SGX)
 static int initialized = 0;
#endif

struct log_connection* retrieve_log_connection(unsigned long s) {
	pthread_mutex_lock(&connections_mutex);
	struct log_connection* c = hashmapGet(connections, s);
	pthread_mutex_unlock(&connections_mutex);
	return c;
}

void ecall_logpoint_init() {
#ifdef DO_LOGGING
	logpoint_init();
#endif
}

void free_slot(struct log_entry* e) {
	//my_fprintf(0, "%s:%i free slot %p\n", __func__, __LINE__, e);
	if (e->req) {
		free(e->req);
	}
	e->req_len = 0;
	if (e->rep) {
		free(e->rep);
	}
	e->rep_len = 0;
	free(e);
}

void add_entry_to_list(struct log_entry* e) {
	// Remove 0x0100 that is being added by LibreSSL at the end of the reply
	// This is not being observed while we are within the enclave
#ifndef COMPILE_WITH_INTEL_SGX
	if (e->rep_len >= 2 && e->rep[e->rep_len-2] == 0x01 && e->rep[e->rep_len-1] == 0x00) {
		e->rep_len -= 2;
	}
#endif

#ifdef DO_LOGGING
#ifndef COMPILE_WITH_INTEL_SGX
	int init = __atomic_fetch_add(&initialized, 1, __ATOMIC_RELAXED);
	if (init == 0) {
		ecall_logpoint_init(0);
		initialized = -1;
	} else {
		while (__atomic_load_n(&initialized, __ATOMIC_RELAXED) != -1) {
			usleep(10);
		}
	}
#endif

	logpoint_log(e->req, e->rep, e->req_len, e->rep_len);
#endif

#if 0
	my_fprintf(0, "log entry %u %u\n", e->req_len, e->rep_len);
	if (e->req_len > 0) {
		my_fprintf(0, "req=[");
		unsigned int i;
		for (i=0; i<e->req_len; i++) {
			my_fprintf(0, "%c", e->req[i]);
		}
		my_fprintf(0, "]\n");
	}
	if (e->rep_len > 0) {
		my_fprintf(0, "rep=[");
		unsigned int i;
		for (i=0; i<e->rep_len; i++) {
			my_fprintf(0, "%c", e->rep[i]);
		}
		my_fprintf(0, "]\n");
	}
#endif
}

struct log_entry* new_slot(void) {
	struct log_entry* e = (struct log_entry*)malloc(sizeof(*e));
	if (!e) {
		my_fprintf(0, "%s:%i malloc(%lu) error!\n", __func__, __LINE__, sizeof(*e));
		return NULL;
	}
	e->req = NULL;
	e->req_len = 0;
	e->rep = NULL;
	e->rep_len = 0;
	//my_fprintf(0, "%s:%i new slot %p\n", __func__, __LINE__, e);
	return e;
}

void log_https_request(const SSL* s, const char* req, unsigned int len) {
#ifdef DO_LOGGING

	struct log_connection* c = retrieve_log_connection((unsigned long)s);
	if (!c) {
		my_fprintf(0, "In %s, unknown connection %lu\n", __func__, (unsigned long)s);
		return;
	}

#ifdef LOG_FOR_SQUID
	long type;
	pthread_mutex_lock(&bio2type_mutex);
	type = (long)hashmapGet(bio2type, (unsigned long)s->rbio);
	pthread_mutex_unlock(&bio2type_mutex);
	if (type != BIO_TO_CLIENT) {
		//my_fprintf(0, "%s SSL %p, this is not BIO_TO_CLIENT so don't log\n", __func__, s);
		return; // Squid, this is not a message between the client and the proxy, so don't log
	}
#endif

	if (!c->log_request) {
		if (c->slot) {
			if (c->ignore_slots > 0) {
				c->ignore_slots--;
			} else {
				add_entry_to_list(c->slot);
			}
			free_slot(c->slot);
			c->slot = NULL;
		}

		c->slot = new_slot();
	} // else we continue to log to the same slot

	c->slot->req = (char*)realloc(c->slot->req, c->slot->req_len+len);
	if (!c->slot->req) {
		my_fprintf(0, "%s:%i malloc(%d) error!\n", __func__, __LINE__,  c->slot->req_len+len);
		return;
	}
	memcpy(c->slot->req + c->slot->req_len, req, len);
	c->slot->req_len += len;
	c->log_request = 1;
#endif
}

void log_https_reply(const SSL* s, const char* rep, unsigned int len) {
#ifdef DO_LOGGING
	struct log_connection* c = retrieve_log_connection((unsigned long)s);
	if (!c) {
		my_fprintf(0, "In %s, unknown connection %lu\n", __func__, (unsigned long)s);
		return;
	}

#ifdef LOG_FOR_SQUID
	long type;
	pthread_mutex_lock(&bio2type_mutex);
	type = (long)hashmapGet(bio2type, (unsigned long)s->wbio);
	pthread_mutex_unlock(&bio2type_mutex);
	if (type != BIO_TO_CLIENT) {
		//my_fprintf(0, "%s SSL %p, this is not BIO_TO_CLIENT so don't log\n", __func__, s);
		return; // Squid, this is not a message between the client and the proxy, so don't log
	}
#endif

	// the SSL_read and SSL_write are execute by 2 different threads when we use the async ecalls,
	// so this case happens
	if (!c->slot) {
		my_fprintf(0, "%s:%i logging a reply without having a request first (ssl=%ld, slot==NULL, len=%d): [", __func__, __LINE__, (unsigned long)s, len);
		unsigned int i;
		for (i=0; i<len; i++) {
			my_fprintf(0, "%c", rep[i]);
		}
		my_fprintf(0, "]\n");
		return;
	}

	c->slot->rep = (char*)realloc(c->slot->rep, c->slot->rep_len+len);
	if (!c->slot->rep) {
		my_fprintf(0, "%s:%i malloc(%d) error!\n", __func__, __LINE__,  c->slot->rep_len+len);
		return;
	}
	memcpy(c->slot->rep + c->slot->rep_len, rep, len);
	c->slot->rep_len += len;
	c->log_request = 0;
#endif
}

void log_new_connection(const SSL* s) {
#ifdef DO_LOGGING
	struct log_connection* c = (struct log_connection*)malloc(sizeof(*c));
	if (!c) {
		my_fprintf(0, "In %s:%i, malloc(%lu) error\n", __func__, __LINE__, sizeof(*c));
		return;
	}
	c->id = (unsigned long)s;
	c->slot = NULL;
	c->log_request = 0;
#ifdef COMPILE_WITH_INTEL_SGX
	c->ignore_slots = 0;
#else
	c->ignore_slots = 2;
#endif

	pthread_mutex_lock(&connections_mutex);
	if (!connections) {
		connections = hashmapCreate(0);
	}
	hashmapInsert(connections, c, (unsigned long)s);
	pthread_mutex_unlock(&connections_mutex);
#endif
}

void log_free_connection(const SSL* s) {
#ifdef DO_LOGGING
	pthread_mutex_lock(&connections_mutex);
	struct log_connection* c = hashmapRemove(connections, (unsigned long)s);
	pthread_mutex_unlock(&connections_mutex);

	if (!c) {
		my_fprintf(0, "In %s, unknown connection %lu\n", __func__, (unsigned long)s);
		return;
	}

#ifdef LOG_FOR_SQUID
	pthread_mutex_lock(&bio2type_mutex);
	hashmapRemove(bio2type, (unsigned long)s->rbio);
	hashmapRemove(bio2type, (unsigned long)s->wbio);
	pthread_mutex_unlock(&bio2type_mutex);
#endif

	if (c->slot) {
		if (c->ignore_slots > 0) {
			c->ignore_slots--;
		} else {
			add_entry_to_list(c->slot);
		}
        free_slot(c->slot);
		c->slot = NULL;
	}
	free(c);
#endif
}

void log_set_ssl_type(const void* b, const long type) {
#ifdef DO_LOGGING
#ifdef LOG_FOR_SQUID
	pthread_mutex_lock(&bio2type_mutex);
	if (!bio2type) {
		bio2type = hashmapCreate(0);
	}
	hashmapInsert(bio2type, (void*)type, (unsigned long)b);
	pthread_mutex_unlock(&bio2type_mutex);

	//for log_req and log_rep we need to retrieve the bio on the ssl object and check the type
	//if BIO_TO_CLIENT then we can log, otherwise there is no need
#endif
#endif
}
