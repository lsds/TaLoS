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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <link.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <sys/stat.h>
#include <unistd.h>
#include <termios.h>
#include <sys/auxv.h>

#define NOT_DEFINED_LSTAT_TYPES

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_thread.h"
#include "sgx_spinlock.h"
#include "ecall_queue.h"
#include "lthread.h"
#include "mempool.h"
#include "hashmap.h"

#ifndef BUFSIZ
#define BUFSIZ 8192
#endif

#define USE_BIO_MEM_POOL

extern int sgx_is_within_enclave(const void*, size_t);

typedef struct _sgx_errlist_t {
	sgx_status_t err;
	const char *msg;
	const char *sug; /* Suggestion */
} sgx_errlist_t;

static sgx_errlist_t sgx_errlist[] = {
		{
				SGX_ERROR_UNEXPECTED,
				"Unexpected error occurred.",
				NULL
		},
		{
				SGX_ERROR_INVALID_PARAMETER,
				"Invalid parameter.",
				NULL
		},
		{
				SGX_ERROR_OUT_OF_MEMORY,
				"Out of memory.",
				NULL
		},
		{
				SGX_ERROR_ENCLAVE_LOST,
				"Power transition occurred.",
				"Please refer to the sample \"PowerTransition\" for details."
		},
		{
				SGX_ERROR_INVALID_ENCLAVE,
				"Invalid enclave image.",
				NULL
		},
		{
				SGX_ERROR_INVALID_ENCLAVE_ID,
				"Invalid enclave identification.",
				NULL
		},
		{
				SGX_ERROR_INVALID_SIGNATURE,
				"Invalid enclave signature.",
				NULL
		},
		{
				SGX_ERROR_OUT_OF_EPC,
				"Out of EPC memory.",
				NULL
		},
		{
				SGX_ERROR_NO_DEVICE,
				"Invalid SGX device.",
				"Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
		},
		{
				SGX_ERROR_MEMORY_MAP_CONFLICT,
				"Memory map conflicted.",
				NULL
		},
		{
				SGX_ERROR_INVALID_METADATA,
				"Invalid enclave metadata.",
				NULL
		},
		{
				SGX_ERROR_DEVICE_BUSY,
				"SGX device was busy.",
				NULL
		},
		{
				SGX_ERROR_INVALID_VERSION,
				"Enclave version was invalid.",
				NULL
		},
		{
				SGX_ERROR_INVALID_ATTRIBUTE,
				"Enclave was not authorized.",
				NULL
		},
		{
				SGX_ERROR_ENCLAVE_FILE_ACCESS,
				"Can't open enclave file.",
				NULL
		},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if(ret == sgx_errlist[idx].err) {
			if(NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		printf("Error: Unexpected error occurred: %d.\n", ret);
}

/******************** ASYNC OCALLS ********************/

static int app_threads = 0;
static int sgx_threads = 0;
static int lthread_tasks = 0;
static int busy_wait_cycles = 0;
static struct mpmcq* ocall_queue = NULL;

void ocall_init_async_ocalls(void* oq, int tid, int appthreads, int sgxthreads, int lthreadtasks, int ncycles) {
	ocall_queue = (struct mpmcq*)oq;
	app_threads = appthreads;
	sgx_threads = sgxthreads;
	lthread_tasks = lthreadtasks;
	busy_wait_cycles = ncycles;
}

char* make_asynchronous_ocall(char* msg, int tid, enum transition_type type, size_t size) {
	// as we use 1 slot per application thread we can safely assume
	// that the enqueue will always work. So no need to call
	//              mpmc_wait_for_enqueue(ocall_queue, tid, busy_wait_cycles)
	mpmc_enqueue(ocall_queue, type, tid, size);

	lthread_get_task_args()->size = 0;
	lthread_get_task_args()->do_ocall = 1;
	//printf("task %p msg %p type %d slot %d ocall\n", lthread_current(), msg, type, tid);
	lthread_yield();
	//printf("task %p slot %d ocall result is here!\n", lthread_current(), tid);
	lthread_get_task_args()->do_ocall = 0;

	char* ret;
	mpmc_dequeue_result(ocall_queue, tid, (void**)&ret);
	return ret;
}

void* execute_async_ocall_malloc(size_t size) {
	void* ptr = NULL;

	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_malloc(&ptr, size);
		if (ret != SGX_SUCCESS) {
			printf("%s:%s:%i ret = %i\n", __FILE__, __func__, __LINE__, ret);
			ptr = NULL;
		}
	} else {
		int slot = lthread_get_task_args()->slot;
		char *msg = mpmc_get_msg_at_slot(ocall_queue, slot);
		struct cell_malloc* cs = (struct cell_malloc*)msg;
		cs->size = size;

		msg = make_asynchronous_ocall(msg, slot, ocall_malloc_t, sizeof(*cs));
		ptr = cs->ret;

		if (!ptr) {
			printf("Allocation error for %lu bytes!\n", size);
			ocall_exit(0);
		}
	}

	return ptr;
}

void execute_async_ocall_free(void* ptr) {
	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_free(ptr);
		if (ret != SGX_SUCCESS) {
			printf("%s:%s:%i ret = %i\n", __FILE__, __func__, __LINE__, ret);
		}
	} else {
		int slot = lthread_get_task_args()->slot;
		char *msg = mpmc_get_msg_at_slot(ocall_queue, slot);
		struct cell_free* cs = (struct cell_free*)msg;
		cs->ptr = ptr;

		make_asynchronous_ocall(msg, slot, ocall_free_t, sizeof(*cs));
	}
}

#ifdef USE_BIO_MEM_POOL

static int bio_mempool_initialized = 0;
static hashmap* bio_mempool_map = NULL;
sgx_spinlock_t bio_mempool_map_lock = SGX_SPINLOCK_INITIALIZER;

static mempool* get_bio_mempool() {
	int expected = 0;
	int desired = 1;
	if (__atomic_compare_exchange_n(&bio_mempool_initialized, &expected, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		bio_mempool_map = hashmapCreate(23);
	}
	while (!bio_mempool_map) {
		// burn cycles
	}

	mempool* pool = (mempool*)hashmapGet(bio_mempool_map, (unsigned long)sgx_thread_self());
	if (!pool) {
		pool = (mempool*)malloc(sizeof(*pool));
		*pool = create_pool(sizeof(BIO), 250);
		sgx_spin_lock(&bio_mempool_map_lock);
		//	need a lock on the insert, just to be safe. However each thread will acquire the lock only once during its execution
		hashmapInsert(bio_mempool_map, (const void*)pool, (unsigned long)sgx_thread_self());
		sgx_spin_unlock(&bio_mempool_map_lock);
	}

	return pool;
}

void* bio_alloc_from_pool(size_t size) {
	mempool* pool = get_bio_mempool();
	void* ptr = pool_alloc(pool);
	return ptr;
}

int bio_dealloc_from_pool(void* ptr) {
	mempool* pool = get_bio_mempool();
	if (pool_address_is_valid(pool, ptr)) {
		pool_dealloc(pool, ptr);
		return 1;
	} else {
		return 0;
	}
}
#endif

void* execute_bio_ocall_malloc(size_t size) {
	void* ptr;

#ifdef USE_BIO_MEM_POOL
	ptr = bio_alloc_from_pool(size);
	if (!ptr) {
		printf("%s:%s:%i bio allocation error\n", __FILE__, __func__, __LINE__);
		ocall_exit(-1);
	}
#else
	ptr = execute_async_ocall_malloc(size);
#endif

	return ptr;
}

void execute_bio_ocall_free(void* ptr) {
#ifdef USE_BIO_MEM_POOL
	if (!bio_dealloc_from_pool(ptr)) {
		execute_async_ocall_free(ptr);
	}
#else
	execute_async_ocall_free(ptr);
#endif
}

long execute_async_bio_ctrl(void* b, int cmd, long argl, void *arg, void* cb) {
	long retval = 0;

	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_bio_ctrl(&retval, (BIO*)b, cmd, argl, arg, cb);
		if (ret != SGX_SUCCESS) {
			printf("%s:%s:%i ret = %i\n", __FILE__, __func__, __LINE__, ret);
		}
	} else {
		int slot = lthread_get_task_args()->slot;
		char *msg = mpmc_get_msg_at_slot(ocall_queue, slot);
		struct cell_ocall_bio_ctrl* cs = (struct cell_ocall_bio_ctrl*)msg;
		cs->bio = b;
		cs->cmd = cmd;
		cs->argl = argl;
		cs->arg = arg;
		cs->cb = cb;

		msg = make_asynchronous_ocall(msg, slot, ocall_bio_ctrl_t, sizeof(*cs));
		retval = cs->ret;
	}

	return retval;
}

int execute_async_bio_destroy(void* b, void* cb) {
	int retval = 0;

	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_bio_destroy(&retval, (BIO*)b, cb);
		if (ret != SGX_SUCCESS) {
			printf("%s:%s:%i ret = %i\n", __FILE__, __func__, __LINE__, ret);
		}
	} else {
		int slot = lthread_get_task_args()->slot;
		char *msg = mpmc_get_msg_at_slot(ocall_queue, slot);
		struct cell_bio_destroy* cs = (struct cell_bio_destroy*)msg;
		cs->bio = b;
		cs->cb = cb;

		msg = make_asynchronous_ocall(msg, slot, ocall_bio_destroy_t, sizeof(*cs));
		retval = cs->ret;
	}

	return retval;
}

int execute_async_bio_write(void* b, char* buf, int len, void* cb) {
	int retval = 0;

	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_bio_write(&retval, b, buf, len, cb);
		if (ret != SGX_SUCCESS) {
			printf("%s:%s:%i ret = %i\n", __FILE__, __func__, __LINE__, ret);
		}
	} else {
		int slot = lthread_get_task_args()->slot;
		char* out_buf = lthread_get_task_args()->rw_out_buffer;
		if (len > RW_OUT_BUF_SIZE) {
			printf("%s rw_out_buffer too small: %d > %d\n", __func__, len, RW_OUT_BUF_SIZE);
			ocall_exit(-1);
		}
		memcpy(out_buf, buf, len);

		char *msg = mpmc_get_msg_at_slot(ocall_queue, slot);
		struct cell_bio_write* cs = (struct cell_bio_write*)msg;
		cs->bio = b;
		cs->buf = out_buf;
		cs->len = len;
		cs->cb = cb;

		msg = make_asynchronous_ocall(msg, slot, ocall_bio_write_t, sizeof(*cs));
		retval = cs->ret;
	}

	return retval;
}

int execute_async_bio_read(void* b, char* buf, int len, void* cb) {
	int retval = 0;

	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_bio_read(&retval, b, buf, len, cb);
		if (ret != SGX_SUCCESS) {
			printf("%s:%s:%i ret = %i\n", __FILE__, __func__, __LINE__, ret);
		}
	} else {
		int slot = lthread_get_task_args()->slot;
		char* out_buf = lthread_get_task_args()->rw_out_buffer;
		if (len > RW_OUT_BUF_SIZE) {
			printf("%s rw_out_buffer too small: %d > %d\n", __func__, len, RW_OUT_BUF_SIZE);
			ocall_exit(-1);
		}

		char *msg = mpmc_get_msg_at_slot(ocall_queue, slot);
		struct cell_bio_read* cs = (struct cell_bio_read*)msg;
		cs->bio = b;
		cs->buf = out_buf;
		cs->len = len;
		cs->cb = cb;

		msg = make_asynchronous_ocall(msg, slot, ocall_bio_read_t, sizeof(*cs));
		retval = cs->ret;

		memcpy(buf, out_buf, len);
	}

	return retval;
}

DH* ocall_SSL_CTX_set_tmp_dh_cb_wrapper(SSL *ssl, int is_export, int keylength, void* cb) {
	DH* retval = NULL;

	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_SSL_CTX_set_tmp_dh_cb(&retval, ssl, is_export, keylength, cb);
		if (ret != SGX_SUCCESS) {
			printf("%s:%s:%i ret = %i\n", __FILE__, __func__, __LINE__, ret);
		}
	} else {
		int slot = lthread_get_task_args()->slot;

		char *msg = mpmc_get_msg_at_slot(ocall_queue, slot);
		struct cell_set_tmp_dh_cb* cs = (struct cell_set_tmp_dh_cb*)msg;
		cs->ssl = ssl;
		cs->is_export = is_export;
		cs->keylength = keylength;
		cs->cb = cb;

		msg = make_asynchronous_ocall(msg, slot, ocall_set_tmp_dh_cb_t, sizeof(*cs));
		retval = (DH*)cs->ret;
	}

	return retval;
}

int ocall_alpn_select_cb_async_wrapper(SSL* s, unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void* arg, void* cb) {
	int retval = 0;

	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_alpn_select_cb(&retval, s, out, outlen, in, inlen, arg,cb);
		if (ret != SGX_SUCCESS) {
			printf("%s ocall error: %d\n", __func__, ret);
			retval = 0;
		}
	} else {
		int slot = lthread_get_task_args()->slot;
		char* out_buf = lthread_get_task_args()->rw_out_buffer;
		if (inlen > RW_OUT_BUF_SIZE) {
			printf("%s rw_out_buffer too small: %d > %d\n", __func__, inlen, RW_OUT_BUF_SIZE);
			ocall_exit(-1);
		}
		memcpy(out_buf, in, inlen);

		char *msg = mpmc_get_msg_at_slot(ocall_queue, slot);
		struct cell_alpn_select_cb* cs = (struct cell_alpn_select_cb*)msg;
		cs->s = s;
		cs->out = NULL;
		cs->in = (unsigned char*)out_buf;
		cs->inlen = inlen;
		cs->arg = arg;
		cs->cb = cb;

		msg = make_asynchronous_ocall(msg, slot, ocall_alpn_select_cb_t, sizeof(*cs));
		*outlen = cs->outlen;
		*out = cs->out;
		retval = cs->ret;
	}

	return retval;
}

int ssl_ctx_set_next_proto_select_async_cb_wrapper(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg, void* cb) {
	int retval = 0;

	//printf("task %p %s ocall_queue %p\n", lthread_current(), __func__, ocall_queue);

	if (!ocall_queue || !lthread_current()) {
		sgx_status_t ret = ocall_ssl_ctx_set_next_proto_select_cb(&retval, s, out, outlen, in, inlen, arg, cb);
		if (ret != SGX_SUCCESS) {
			printf("%s ocall error: %d\n", __func__, ret);
			retval = -1;
		}
	} else {
		printf("%s need to implement async queue ocall\n", __func__);
		retval = -1;
	}

	return retval;
}

/******************** C FILE ********************/

ssize_t write(int fd, const void *buf, size_t count) {
	//printf("ocall %s\n", __func__);
	ssize_t retval;
	sgx_status_t status;
	status = ocall_write((int*)&retval, fd, buf, count);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		return -1;
	}
	return retval;
}

ssize_t read(int fd, void *buf, size_t count) {
	//printf("ocall %s\n", __func__);
	int retval;
	sgx_status_t status;
	status = ocall_read(&retval, fd, buf, count);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}
	return (ssize_t)retval;
}

/*
int stat64(const char *path, struct stat *buf) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}
*/

/*
int lstat64(const char *pathname, struct stat *buf) {
	int retval;
	sgx_status_t status;
	status = ocall_lstat64(&retval, pathname, buf);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}
	return retval;


}
*/

int __xstat(int ver, const char *path, struct stat *buf) {
	ocall_println_string(__func__);
	return stat(path, buf);
}

int access(const char *pathname, int mode) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int open(const char *filename, int flags, ...)
{
	mode_t mode = 0;

	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	int fd;
	sgx_status_t ret = ocall_open(&fd, filename, flags, mode);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		printf("ocall %s sgx error %d\n", __func__, ret);
		return -1;
	}

	return fd;
}

int open64(const char *filename, int flags, ...)
{
	mode_t mode = 0;

	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	int fd;
	sgx_status_t ret = ocall_open64(&fd, filename, flags, mode);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret);
		printf("ocall %s sgx error %d\n", __func__, ret);
		return -1;
	}

	return fd;
}

int utimes(const char *filename, const struct timeval times[2]) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fchmod(int fd, mode_t mode) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fchown(int fd, uid_t owner, gid_t group) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fsync(int fd) {
	int ret = 0;
        sgx_status_t status = ocall_fsync(&ret, fd);
        if (status != SGX_SUCCESS) {
                print_error_message(status);
                printf("ocall %s sgx error %d\n", __func__, status);
                return -1;
        }

        return ret;
}

int unlink(const char *pathname) {
	int ret = 0;
        sgx_status_t status = ocall_unlink(&ret, pathname);
        if (status != SGX_SUCCESS) {
                print_error_message(status);
                printf("ocall %s sgx error %d\n", __func__, status);
                return -1;
        }

        return ret;
}

int printf(const char* format, ...) {
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, format);
	int r = vsnprintf(buf, BUFSIZ, format, ap);
	va_end(ap);

	sgx_status_t status;
	status = ocall_print_string(buf);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		r = -1;
	}

	return r;
}

int puts(const char *s) {
	ocall_println_string(s);
	return 0;
}

int my_vasprintf(char **strp, const char *fmt, va_list ap) {
	va_list ap2;
	//va_copy(ap2, ap);
	__builtin_va_copy(ap2, ap);
	int l = vsnprintf(0, 0, fmt, ap2);
	va_end(ap2);

	if (l<0 || !(*strp=(char*)malloc(l+1U))) return -1;
	return vsnprintf(*strp, l+1U, fmt, ap);
}

int my_asprintf(char **strp, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	int r = my_vasprintf(strp, fmt, ap);
	va_end(ap);
	return r;
}

int asprintf(char **strp, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	int r = my_vasprintf(strp, fmt, ap);
	va_end(ap);
	return r;
}

int sprintf(char *str, const char *format, ...) {
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, format);
	vsnprintf(buf, BUFSIZ, format, ap);
	va_end(ap);
	int s = strlen(buf);
	memcpy(str, buf, s);
	str[s] = '\0';
	return s;
}

off_t lseek64(int fd, off_t offset, int whence) {
	return lseek(fd, offset, whence);
}

off_t lseek(int fd, off_t offset, int whence) {
	off_t ret;
	sgx_status_t status = ocall_lseek(&ret, fd, offset, whence);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}

	return ret;
}

int sscanf(const char *str, const char *format, ...) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int my_vprintf(const char *format, va_list ap) {
	char buf[BUFSIZ] = {'\0'};
	vsnprintf(buf, BUFSIZ, format, ap);
	ocall_println_string(buf);
	return 0;
}


/******************** NETWORK ********************/

int inet_pton(int af, const char* src, void* dst) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int getnameinfo(const struct sockaddr *__restrict __sa,
		socklen_t __salen, char *__restrict __host,
		socklen_t __hostlen, char *__restrict __serv,
		socklen_t __servlen, int __flags) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo **res) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void freeaddrinfo(struct addrinfo *res) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

struct hostent *gethostbyname(const char *name) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

int socket(int domain, int type, int protocol) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int listen(int sockfd, int backlog) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int shutdown(int sockfd, int how) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


/******************** FILE ********************/

FILE* stderr = 0;
FILE* stdin = 0;
FILE* stdout = 0;

FILE *fopen64(const char *path, const char *mode) {
	char* paf;
	if (sgx_is_within_enclave(path, sizeof(*path))) {
		size_t _len_path = path ? strlen(path) + 1 : 0;
		ocall_malloc((void**)&paf, _len_path);
		memcpy(paf, path, _len_path);
	} else {
		paf = (char*)path;
	}

	char* m;
	if (sgx_is_within_enclave(mode, sizeof(*mode))) {
		size_t _len_mode = mode ? strlen(mode) + 1 : 0;
		ocall_malloc((void**)&m, _len_mode);
		memcpy(m, mode, _len_mode);
	} else {
		m = (char*)mode;
	}

	FILE* ret;
	//printf("--> ocall fopen(%s, %s)\n", path, mode);
	sgx_status_t status = ocall_fopen((void**)&ret, (const char*)paf, m);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = 0;
	}

	if (sgx_is_within_enclave(path, sizeof(*path))) {
		ocall_free((void*)paf);
	}

	if (sgx_is_within_enclave(mode, sizeof(*mode))) {
		ocall_free((void*)m);
	}

	return ret;
}

FILE *fopen(const char *path, const char *mode) {
	return fopen64(path, mode);
}


int fclose(FILE *fp) {
	int ret;
	sgx_status_t status;
	status = ocall_fclose(&ret, fp);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = -1;
	}
	//printf("ocall fclose(%p) = %u\n", fp, ret);

	return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t ret;
	sgx_status_t status;
	if (sgx_is_within_enclave(ptr, size*nmemb)) {
		status = ocall_fwrite_copy(&ret, ptr, size, nmemb, stream);
	} else {
		status = ocall_fwrite(&ret, ptr, size, nmemb, stream);
	}
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = 0;
	}

	//printf("ocall fwrite(%zu, %p) = %zu\n", size*nmemb, stream, ret);
	return ret;
}

int feof(FILE *stream) { 
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ferror(FILE *stream) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fseek(FILE *stream, long offset, int whence) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int my_ftruncate(int fd, off_t length) {
	int ret = 0;
        sgx_status_t status = ocall_ftruncate(&ret, fd, length);
        if (status != SGX_SUCCESS) {
                print_error_message(status);
                printf("ocall %s sgx error %d\n", __func__, status);
                return -1;
        }

        return ret;
}

/*
int ftruncate64(int fd, off_t length) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}
*/
long ftell(FILE *stream) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fcntl(int fd, int cmd, ...) {

	va_list ap;
	va_start(ap, cmd);
	void* arg = va_arg(ap, void*);
	va_end(ap);
		
	int ret;
	sgx_status_t status= ocall_fcntl(&ret, fd, cmd, arg, sizeof(void*));
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}

	return ret;
}

int ioctl(int d, int request, ...) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int close(int fd) {
	int ret;
        sgx_status_t status;
        status = ocall_close(&ret, fd);
        if (status != SGX_SUCCESS) {
                print_error_message(status);
                ret = -1;
        }
        //printf("ocall close(%p) = %u\n", fd, ret);
        return ret;
}

int fflush(FILE *stream) {
	int ret;
	sgx_status_t status;
	status = ocall_fflush(&ret, stream);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = -1;
	}
	return ret;
}

char *fgets(char *s, int size, FILE *stream) {
	char* ret;
	sgx_status_t status;
	status = ocall_fgets(&ret, s, size, stream);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		ret = 0;
	}

	//too verbose printf("ocall fgets(%u, %p) = %p\n", size, stream, ret);
	return ret;
}

FILE *fdopen(int fd, const char *mode) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

int my_vfprintf(FILE *stream, const char *format, va_list ap) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int my_printf(const char *format, ...) {
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, format);
	int r = vsnprintf(buf, BUFSIZ, format, ap);
	va_end(ap);
	ocall_print_string(buf);
	return r;
}

int my_fprintf(FILE *stream, const char *format, ...) {
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, format);
	int r = vsnprintf(buf, BUFSIZ, format, ap);
	va_end(ap);
	ocall_print_string(buf);
	return r;
}

int fprintf(FILE *stream, const char *format, ...) {
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, format);
	int r = vsnprintf(buf, BUFSIZ, format, ap);
	va_end(ap);
	ocall_print_string(buf);
	return r;
}

int fputs(const char *s, FILE *stream) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fputc(int c, FILE *stream) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fileno(FILE *stream) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int my_fstat(int fd, struct stat *buf) {
	int retval;
	sgx_status_t status;
	status = ocall_fstat(&retval, fd, buf, sizeof(struct stat));
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}
	return retval;
}

int my_lstat(const char *pathname, struct stat *buf) {
	int retval;
	sgx_status_t status;
	status = ocall_lstat(&retval, pathname, buf, sizeof(struct stat));
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}
	return retval;
}

int my_stat(const char *path, struct stat *buf) {
	int retval;
	sgx_status_t status;
	status = ocall_stat(&retval, path, buf, sizeof(struct stat));
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		printf("ocall %s sgx error %d\n", __func__, status);
		return -1;
	}
	return retval;
}


/******************** TIME ********************/

int gettimeofday(struct timeval *tv, struct timezone *tz) {
	return 0;
	int ret = 0;
	sgx_status_t s = ocall_gettimeofday(&ret, tv, tz);
	if (s != SGX_SUCCESS) {
		my_printf("%s:%s:%i error %d\n", __FILE__, __func__, __LINE__, s);
	}
	return ret;
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

unsigned int sleep (unsigned int __seconds) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

struct tm *gmtime(const time_t *timep) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

struct tm *gmtime_r(const time_t *timep, struct tm *result) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

time_t timegm(struct tm *tm) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return (time_t)0;
}

struct tm *localtime(const time_t *timep) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return (time_t)0;
}

time_t time(time_t *t) {
	//printf("ocall %s\n", __func__);
	time_t retval;
	sgx_status_t status;
	status = ocall_time((long int*)&retval, (long int*)t);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		return 0;
	}
	return retval;
}


/******************** SYSLOG ********************/

void openlog(const char *ident, int option, int facility) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
}

void syslog(int priority, const char *format, ...) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
}

void closelog(void) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
}


/******************** SIGNAL ********************/

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

sighandler_t signal(int signum, sighandler_t handler) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

int raise(int sig) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int sigpending(sigset_t *set) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


/******************** TERMINAL ********************/

int tcgetattr(int fd, struct termios *termios_p) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


/******************** DIR ********************/

DIR *opendir(const char *name) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

struct dirent *readdir(DIR *dirp) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

int closedir(DIR *dirp) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *getcwd(char *buf, size_t size) {
	sgx_status_t status;
	status = ocall_getcwd(&buf, buf, size);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		buf = 0;
	}

	//too verbose printf("ocall fgets(%u, %p) = %p\n", size, stream, ret);
	return buf;
}

int mkdir(const char *pathname, mode_t mode) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int rmdir(const char *pathname) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


/******************** MMAP ********************/

void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	return mmap(addr, length, prot, flags, fd, offset);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
	sgx_status_t status;
	void* ret = NULL;
        status = ocall_mmap(&ret, addr, length, prot, flags, fd, offset);
        if (status != SGX_SUCCESS) {
                print_error_message(status);
        }
        return ret;
}

int munmap(void *addr, size_t length) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void *mremap (void *__addr, size_t __old_len, size_t __new_len,
                     int __flags, ...) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

/******************** VFS ********************/

int getrusage(int who, struct rusage *usage) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int statfs(const char *path, struct statfs *buf) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fstatfs(int fd, struct statfs *buf) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int statvfs(const char *path, struct statvfs *buf) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int fstatvfs(int fd, struct statvfs *buf) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


/******************** VARIOUS ********************/

char *my_strdup(const char *s) {
	size_t l = strlen(s);
	char *d = (char*)malloc(l+1);
	if (!d) return NULL;
	return (char*)memcpy(d, s, l+1);
}

char *my_strndup(const char *__string, size_t __n) {
  char *result;
  size_t len = strlen (__string);

  if (__n < len)
    len = __n;

  result = (char*)malloc(len+1);
  if (!result) return NULL;

  memcpy(result, __string, len);
  result[len] = '\0';
  return result;
}

unsigned long long get_cpuid_for_openssl() {
	unsigned long long ret;
	sgx_status_t status;
	status = ocall_get_cpuid_for_openssl(&ret);
	if (status != SGX_SUCCESS) {
		print_error_message(status);
		return 0;
	}
	return ret;
}

int dl_iterate_phdr(int (*callback) (struct dl_phdr_info *info, size_t size, void *data), void *data) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int getpid(void) {
	pid_t ret;
        sgx_status_t status;
        status = ocall_getpid(&ret);
        if (status != SGX_SUCCESS) {
                print_error_message(status);
                return 0;
        }
	//fprintf(stderr, "%s:%i pid = %d, status = %d\n", __FILE__, __LINE__, ret, status);
        return ret;
}

pid_t getsid(pid_t pid) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 7777;
}

pid_t getppid(void) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 7777;
}

pid_t getpgid(pid_t pid) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 7777;
}

uid_t geteuid(void) {
	uid_t ret;
        sgx_status_t status;
        status = ocall_getuid((int*)&ret);
        if (status != SGX_SUCCESS) {
                print_error_message(status);
                return 0;
        }
        //fprintf(stderr, "%s:%i uid = %d, status = %d\n", __FILE__, __LINE__, ret, status);
        return ret;
}

int getpriority(__priority_which_t __which, id_t __who) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

/*
int getpagesize(void) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}
*/

char *getenv(const char *name) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void perror(const char *s) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
}

long int syscall(long int number, ...) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void exit(int status) {
	ocall_println_string(__func__);
	ocall_exit(status);
	do { } while (1);
}

void __assert_fail (const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
	printf("assert file %s line %d function %s: [%s]\n", __file, __line, __function, __assertion);
	ocall_exit(1);
}

unsigned long getauxval(unsigned long type) {
	fprintf(stderr, "%s:%i need to implement ocall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}


/******************** __CTYPE_B_LOC ********************/

#define X(x) (((x)/256 | (x)*256) % 65536)
static const unsigned short table_1[] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
	X(0x200),X(0x320),X(0x220),X(0x220),X(0x220),X(0x220),X(0x200),X(0x200),
	X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
	X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),X(0x200),
	X(0x160),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
	X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
	X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),X(0x8d8),
	X(0x8d8),X(0x8d8),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
	X(0x4c0),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8d5),X(0x8c5),
	X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),
	X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),X(0x8c5),
	X(0x8c5),X(0x8c5),X(0x8c5),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),
	X(0x4c0),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8d6),X(0x8c6),
	X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),
	X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),X(0x8c6),
	X(0x8c6),X(0x8c6),X(0x8c6),X(0x4c0),X(0x4c0),X(0x4c0),X(0x4c0),X(0x200),
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};

static const unsigned short *const ptable_1 = table_1+128;

const unsigned short **__ctype_b_loc(void) {
	return (const unsigned short**)&ptable_1;
}

/******************** __CTYPE_TOLOWER_LOC ********************/

static const int32_t table_2[] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
	16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
	32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
	48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
	64,
	'a','b','c','d','e','f','g','h','i','j','k','l','m',
	'n','o','p','q','r','s','t','u','v','w','x','y','z',
	91,92,93,94,95,96,
	'a','b','c','d','e','f','g','h','i','j','k','l','m',
	'n','o','p','q','r','s','t','u','v','w','x','y','z',
	123,124,125,126,127,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};

static const int32_t *const ptable_2 = table_2+128;

const int32_t **__ctype_tolower_loc(void) {
	return (const int32_t**)&ptable_2;
}
