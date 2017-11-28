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

#ifndef TRANSITION_QUEUE_H_
#define TRANSITION_QUEUE_H_

#include <stddef.h>

#define USE_OCALL_QUEUE

// even if all the machines do not necessarily have lines of 64B, we don't really care
#define CACHE_LINE_SIZE 64

#define RW_OUT_BUF_SIZE 65536

// // Used to define the size of the pad member
// // The last modulo is to prevent the padding to add CACHE_LINE_SIZE bytes to the structure
#define PADDING_SIZE(S) ((CACHE_LINE_SIZE - ((S) % CACHE_LINE_SIZE)) % CACHE_LINE_SIZE)

#define QUEUE_MAX_MESSAGE_SIZE 64 // the structure passed into the queue must be less or equal than this value

#define QUEUE_SLOT_AVAILABLE		0
#define QUEUE_SLOT_TAKEN			1
#define QUEUE_SLOT_RESULT_AVAILABLE	2

enum transition_type {
	ecall_ssl_read, ecall_ssl_accept,
	ecall_ssl_new, ecall_ssl_free, ecall_ssl_ctrl, ecall_ssl_set_bio, ecall_ssl_shutdown, ecall_ssl_write,
	ecall_ssl_set_connect_state, ecall_ssl_get_certificate, ecall_ssl_get_error,
	ecall_bio_new, ecall_bio_ctrl,
	ocall_malloc_t, ocall_free_t,
	ocall_bio_ctrl_t, ocall_bio_destroy_t, ocall_bio_read_t, ocall_bio_write_t,
	ocall_alpn_select_cb_t, ocall_set_tmp_dh_cb_t,
	transition_undef_t
};

// type ecall_ssl_read
struct cell_ssl_read {
	void* ssl;
	void* buf;
	int num;
	int ret;
};

// type ecall_ssl_accept
struct cell_ssl_accept {
	void* ssl;
	int ret;
};

// type ecall_ssl_new
struct cell_ssl_new {
	void* ctx;
	void* out_s;
	void* ret;
};

// type ecall_ssl_free
struct cell_ssl_free {
	void* out_s;
};

// type ecall_ssl_write
struct cell_ssl_write {
	void* ssl;
	void* buf;
	int num;
	int ret;
};

// type ecall_ssl_ctrl
struct cell_ssl_ctrl {
	void* ssl;
	int cmd;
	long larg;
	void* parg;
	long ret;
};

// type ecall_ssl_set_bio
struct cell_ssl_set_bio {
	void* ssl;
	void* rbio;
	void* wbio;
};

// type ecall_ssl_shutdown
struct cell_ssl_shutdown {
	void* ssl;
	int ret;
};

// type ecall_ssl_set_connect_state
struct cell_ssl_set_connect_state {
	void* ssl;
	int ret;
};

// type ecall_ssl_get_certificate
struct cell_ssl_get_certificate {
	void* ssl;
	void* ret;
};

// type ecall_ssl_get_error
struct cell_ssl_get_error {
	void* ssl;
	int ret_code;
	int ret;
};

// type ecall_bio_new
struct cell_bio_new {
	void* type;
	int method_in_enclave;
	void* ret;
};

// type ecall_bio_ctrl
struct cell_bio_ctrl {
	void* bio;
	int cmd;
	long larg;
	void* parg;
	long ret;
};

// type ocall_malloc_t
struct cell_malloc {
	size_t size;
	void* ret;
};

// type ocall_free_t
struct cell_free {
	void* ptr;
};

// type ocall_bio_read_t
struct cell_bio_read {
	void* bio;
	char* buf;
	int len;
	void* cb;
	int ret;
};

// type ocall_bio_write_t
struct cell_bio_write {
	void* bio;
	char* buf;
	int len;
	void* cb;
	int ret;
};

// type ocall_bio_ctrl_t
struct cell_ocall_bio_ctrl {
	void* bio;
	int cmd;
	long argl;
	void* arg;
	void* cb;
	long ret;
};

// type ocall_bio_destroy_t
struct cell_bio_destroy {
	void* bio;
	void* cb;
	int ret;
};

// type ocall_alpn_select_cb_t
struct cell_alpn_select_cb {
	void* s;
	unsigned char* out;
	unsigned char outlen;
	unsigned char* in;
	unsigned int inlen;
	void* arg;
	void* cb;
	int ret;
};

// type ocall_set_tmp_dh_cb_t
struct cell_set_tmp_dh_cb {
	void* ssl;
	int is_export;
	int keylength;
	void* cb;
	void* ret;
};

struct cell_t {
	enum transition_type type;
	char data[QUEUE_MAX_MESSAGE_SIZE];
	int status; // 0: available, 1: occupied (can dequeue), 2: result is there
	char padding[PADDING_SIZE(sizeof(enum transition_type)+sizeof(char)*QUEUE_MAX_MESSAGE_SIZE+sizeof(int))];
} __attribute__((__packed__, __aligned__(CACHE_LINE_SIZE)));

struct mpmcq {
	struct cell_t* buffer;
	int nslots;
}  __attribute__((aligned(CACHE_LINE_SIZE)));

struct lthread_args {
	char* msg;
	enum transition_type type;
	int slot;
	int do_ocall;
	size_t size;
	char* rw_out_buffer;
};

struct mpmcq* newmpmc(int nslots);
void delmpmc(struct mpmcq* q);

// Busy wait for ncycles or until the slot is available.
// Returns 1 if the slot is available, 0 otherwise (in this case you might want
// to sleep).
int mpmc_wait_for_enqueue(struct mpmcq *q, int tid, int ncycles);

char* mpmc_get_msg_at_slot(struct mpmcq *q, int tid);

void mpmc_enqueue(struct mpmcq *q, enum transition_type type, int tid, size_t len);

int mpmc_slot_taken(struct mpmcq *q, int tid);

enum transition_type mpmc_dequeue(struct mpmcq *q, int tid, void **data);

// call this method if the caller of mpmc_enqueue needs to wait for the end of the ecall. data can be null
void mpmc_enqueue_result(struct mpmcq *q, int tid, size_t len);

// wait for the result of an ecall.
// Busy wait for ncycles or until the result is available.
// Returns 1 if the result is available, 0 otherwise (in this case you might want
// to sleep).
int mpmc_wait_for_result(struct mpmcq *q, int tid, int ncycles);

// call this method if you need to wait for the end of the ecall and expect a result
void mpmc_dequeue_result(struct mpmcq *q, int tid, void **data);

void mpmc_pause();

#endif
