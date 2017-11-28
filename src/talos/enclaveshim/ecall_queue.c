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

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#ifndef COMPILE_WITH_INTEL_SGX
#include <sched.h>
#include <stdio.h>
#endif

#include "ecall_queue.h"

void mpmc_pause() {
	__asm__ __volatile__( "pause" : : : "memory" );
}

struct mpmcq* newmpmc(int nslots) {
	if (nslots <= 0) return NULL;

	// check that the messages can fit
#ifndef COMPILE_WITH_INTEL_SGX
	if (sizeof(struct cell_ssl_read) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_read", sizeof(struct cell_ssl_read), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_accept) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_accept", sizeof(struct cell_ssl_accept), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_new) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_new", sizeof(struct cell_ssl_new), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_free) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_free", sizeof(struct cell_ssl_free), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_write) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_write", sizeof(struct cell_ssl_write), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_ctrl) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_ctrl", sizeof(struct cell_ssl_ctrl), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_set_bio) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_set_bio", sizeof(struct cell_ssl_set_bio), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_shutdown) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_shutdown", sizeof(struct cell_ssl_shutdown), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_set_connect_state) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_set_connect_state", sizeof(struct cell_ssl_set_connect_state), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_get_certificate) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_get_certificate", sizeof(struct cell_ssl_get_certificate), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ssl_get_error) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ssl_get_error", sizeof(struct cell_ssl_get_error), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_bio_new) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_bio_new", sizeof(struct cell_bio_new), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_bio_ctrl) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_bio_ctrl", sizeof(struct cell_bio_ctrl), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_malloc) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_malloc", sizeof(struct cell_malloc), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_free) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_free", sizeof(struct cell_free), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_bio_read) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_bio_read", sizeof(struct cell_bio_read), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_bio_write) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_bio_write", sizeof(struct cell_bio_write), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_ocall_bio_ctrl) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_ocall_bio_ctrl", sizeof(struct cell_ocall_bio_ctrl), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_bio_destroy) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_bio_destroy", sizeof(struct cell_bio_destroy), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_alpn_select_cb) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_alpn_select_cb", sizeof(struct cell_alpn_select_cb), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
	if (sizeof(struct cell_set_tmp_dh_cb) > QUEUE_MAX_MESSAGE_SIZE) {
		printf("Async message %s is too big: %lu > %d\n", "cell_set_tmp_dh_cb", sizeof(struct cell_set_tmp_dh_cb), QUEUE_MAX_MESSAGE_SIZE);
		return NULL;
	}
#else
	// if not outside of the enclave then why do we call it?
	return NULL;
#endif

	struct mpmcq* q = (struct mpmcq*)malloc(sizeof(*q));
	if (!q) return NULL;

	q->nslots = nslots;

	q->buffer = (struct cell_t*)malloc(sizeof(*q->buffer)*nslots);
	memset(q->buffer, 0, sizeof(*q->buffer)*nslots);

	int i;
	for (i=0; i<nslots; i++) {
		q->buffer[i].status = QUEUE_SLOT_AVAILABLE;
	}

	return q;
}

void delmpmc(struct mpmcq* q) {
	free(q->buffer);
	free(q);
}

// Busy wait for ncycles or until the slot is available.
// Returns 1 if the slot is available, 0 otherwise (in this case you might want
// to sleep).
int mpmc_wait_for_enqueue(struct mpmcq *q, int tid, int ncycles) {
	int status = __atomic_load_n(&q->buffer[tid].status, __ATOMIC_RELAXED);
	int i = 0;
	while (status != QUEUE_SLOT_AVAILABLE && i<ncycles) {
		mpmc_pause();
		status = __atomic_load_n(&q->buffer[tid].status, __ATOMIC_RELAXED);
		i++;
	}

	return (status == QUEUE_SLOT_AVAILABLE);
}

char* mpmc_get_msg_at_slot(struct mpmcq *q, int tid) {
	return q->buffer[tid].data;
}

void mpmc_enqueue(struct mpmcq *q, enum transition_type type, int tid, size_t len) {
	q->buffer[tid].type = type;
	__atomic_store_n(&q->buffer[tid].status, QUEUE_SLOT_TAKEN, __ATOMIC_RELAXED);
}

int mpmc_slot_taken(struct mpmcq *q, int tid) {
	return __atomic_load_n(&q->buffer[tid].status, __ATOMIC_RELAXED) == QUEUE_SLOT_TAKEN;
}

enum transition_type mpmc_dequeue(struct mpmcq *q, int tid, void **data) {
	enum transition_type type = transition_undef_t;

	// we can change the status to QUEUE_SLOT_AVAILABLE because there is only 1 ecall/ocall at a time for a given thread
	int expected = QUEUE_SLOT_TAKEN;
	int desired = QUEUE_SLOT_AVAILABLE;
	if (__atomic_compare_exchange_n(&q->buffer[tid].status, &expected, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		type = q->buffer[tid].type;
		*data = q->buffer[tid].data;
	}

	return type;
}

void mpmc_enqueue_result(struct mpmcq *q, int tid, size_t len) {
	__atomic_store_n(&q->buffer[tid].status, QUEUE_SLOT_RESULT_AVAILABLE, __ATOMIC_RELAXED);
}

// wait for the result of an ecall.
// Busy wait for ncycles or until the result is available.
// Returns 1 if the result is available, 0 otherwise (in this case you might want
// to sleep).
int mpmc_wait_for_result(struct mpmcq *q, int tid, int ncycles) {
	int status = __atomic_load_n(&q->buffer[tid].status, __ATOMIC_RELAXED);
	int i=0;
	while (status != QUEUE_SLOT_RESULT_AVAILABLE && i<ncycles) {
#ifndef COMPILE_WITH_INTEL_SGX
		sched_yield();
#else
		mpmc_pause();
#endif
		status = __atomic_load_n(&q->buffer[tid].status, __ATOMIC_RELAXED);
		i++;
	}

	return (status == QUEUE_SLOT_RESULT_AVAILABLE);
}

void mpmc_dequeue_result(struct mpmcq *q, int tid, void **data) {
	if (data) {
		*data = q->buffer[tid].data;
	}
	__atomic_store_n(&q->buffer[tid].status, QUEUE_SLOT_AVAILABLE, __ATOMIC_RELAXED);
}
