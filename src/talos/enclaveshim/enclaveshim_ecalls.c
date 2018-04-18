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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <pthread.h>
#include <dlfcn.h>

#include "sgx_urts.h"
#include "enclaveshim_ecalls.h"
#include "openssl_types.h"
#include "enclaveshim_log.h"
#include "ocalls.h"
#include "hashmap.h"
#include "ecall_queue.h"

#define MAX_PATH 256

/* Global EID shared by multiple threads */
static sgx_enclave_id_t global_eid = 0;

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
void print_error_message(sgx_status_t ret, const char* fn)
{
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if(ret == sgx_errlist[idx].err) {
			if(NULL != sgx_errlist[idx].sug)
				printf("Info: %s from %s\n", sgx_errlist[idx].sug, fn);
			printf("Error: %s from %s\n", sgx_errlist[idx].msg, fn);
			break;
		}
	}

	if (idx == ttl)
		printf("Error: Unexpected error occurred: %d from %s.\n", ret, fn);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
	char token_path[MAX_PATH] = {'\0'};
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	/* Step 1: try to retrieve the launch token saved by last transaction 
	 *		 *          *         if there is no token, then create a new one.
	 *			 *                   */
	/* try to get the token saved in $HOME */
	const char *home_dir = getpwuid(getuid())->pw_dir;

	if (home_dir != NULL && 
			(strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
		/* compose the token path */
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
	} else {
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	}

	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}
	if (fp != NULL) {
		/* read the token from saved file */
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}

	/* Step 2: call sgx_create_enclave to initialize an enclave instance */
	/* Debug Support: set 2nd parameter to 1 */
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		if (fp != NULL) fclose(fp);
		return 0;
	}
	/* Step 3: save the launch token if it is updated */
	if (updated == FALSE || fp == NULL) {
		/* if the token is not updated, or file handler is invalid, do not perform saving */
		if (fp != NULL) fclose(fp);
		return 0;
	}

	/* reopen the file with write capablity */
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL) return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
	return 0;
}

/**************************** INIT + ASYNC ECALLS ********************************/

#include "enclaveshim_config.h"

#define USE_ECALL_QUEUE // undef it to deactivate the asynchronous ecalls
#define USE_OCALL_QUEUE // undef it to deactivate the asynchronous ocalls

#define USE_BUSY_WAITING_THREAD // define it to use the busy waiting thread to wait for ecall results / ocall requests

static int app_threads = 0;
static int sgx_threads = 0;
static int lthread_tasks = 0;

static struct mpmcq* ecall_queue = NULL;
static struct mpmcq* ocall_queue = NULL;

static int pending_async_ecalls = 0;
#ifndef USE_BUSY_WAITING_THREAD
static int master_app_thread = -1;
#endif
static pthread_cond_t busy_waiter_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t busy_waiter_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t* app_threads_lock;
static pthread_cond_t* app_threads_cond;
static int busy_wait_cycles = 0;

static pthread_mutex_t sgx_thread_sleeping_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sgx_thread_sleeping_cond = PTHREAD_COND_INITIALIZER;

static uint64_t rdtsc_value = 0;

// per application thread
static int next_tid = 0;
static __thread int tid = -1;

int read_int_from_file(const char* filename) {
	int i, n;
	FILE* f = fopen(filename, "r");
	if (!f) {
		printf("%s:%i cannot open file %s!\n", __func__, __LINE__, filename);
		return -1;
	}

	n = fscanf(f, "%d", &i);
	fclose(f);
	if (n != 1) {
		printf("%s:%i fscanf error with file %s!\n", __func__, __LINE__, filename);
		return 0;
	}

	printf("%s:%i file %s value %d\n", __func__, __LINE__, filename, i);
	return i;
}

void write_int_to_file(const char* filename, int i) {
	FILE* f = fopen(filename, "w");
	if (!f) {
		printf("%s:%i cannot open file %s!\n", __func__, __LINE__, filename);
	}

	fprintf(f, "%d", i);
	fclose(f);
}

void* sgx_thread_handler(void* arg) {
	int stid = *(int*)arg;

	printf("starting sgx thread %d.\n", stid);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_start_sgx_thread(global_eid, (void*)ecall_queue, (void*)ocall_queue, stid, app_threads, sgx_threads, lthread_tasks, busy_wait_cycles, &rdtsc_value);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}

	printf("sgx thread %d has finished.\n", stid);
	return NULL;
}

void ocall_sgx_thread_sleep(void) {
	pthread_mutex_lock(&sgx_thread_sleeping_lock);
	pthread_cond_wait(&sgx_thread_sleeping_cond, &sgx_thread_sleeping_lock);
	pthread_mutex_unlock(&sgx_thread_sleeping_lock);
}

void ocall_sgx_thread_wake_up(void) {
	pthread_cond_signal(&sgx_thread_sleeping_cond);
}

void* async_ecall_busy_waiter(void* arg) {
	while (1) {
		// At this check we can have a deadlock, where the busy waiting thread waits
		// for an ecall and the application thread waits for the result of its ecall
		// or for an ocall. The problem frequently happened with 1 client. To fix it:
		//    -we check again if there is a pending ecall
		//    -the app threads use the busy_waiter_lock when issuing the broadcast signal
		pthread_mutex_lock(&busy_waiter_lock);
		if (__atomic_load_n(&pending_async_ecalls, __ATOMIC_RELAXED) <= 0) {
			pthread_cond_wait(&busy_waiter_cond, &busy_waiter_lock);
		}
		pthread_mutex_unlock(&busy_waiter_lock);

		while (__atomic_load_n(&pending_async_ecalls, __ATOMIC_RELAXED) > 0) {
			int i;
			for (i=0; i<app_threads; i++) {
#ifdef USE_ECALL_QUEUE
				if (mpmc_wait_for_result(ecall_queue, i, 0)) {
					pthread_cond_signal(&app_threads_cond[i]);
				}
#endif

#ifdef USE_OCALL_QUEUE
				if (mpmc_slot_taken(ocall_queue, i)) {
					pthread_cond_signal(&app_threads_cond[i]);
				}
#endif
			}

#ifdef SGX_THREAD_SLEEPING
			uint64_t r;
			rdtsc(r);
			__atomic_store_n(&rdtsc_value, r, __ATOMIC_RELAXED);
#endif
			sched_yield();
			//usleep(busy_wait_cycles);
		}
	}
}

#ifdef SGX_MODE_SIM
static void* ssllib_handler = NULL;

void* load_original_ssl_function(char *name) {
	if (!ssllib_handler) {	
		ssllib_handler = dlopen(OPENSSL_LIBRARY_PATH, RTLD_LAZY | RTLD_LOCAL | RTLD_DEEPBIND);
		if (!ssllib_handler) {
			printf("Cannot open shared library libssl.so: %s\n", dlerror());
			exit(1);
		}
	}

	dlerror(); // clear existing errors
	void* addr = dlsym(ssllib_handler, name);
	char* err = dlerror();
	if (err) {
		printf("dlsym error: %s\n", err);
		exit(1);
	}
	return addr;
}
#endif

void tls_processing_module_init() {
	// this is the only ecall that doesn't call initialize_library
	// as tls_processing_module_init is called from initialize_library
	log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	ret = ecall_tls_processing_module_init(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}

	log_exit_ecall(__func__);
}

void initialize_library(void) {
	// Apache loads the mod_ssl.so module twice, which causes pthread to segfault
	// so initialize the queue and threads only on the second load
#ifdef USE_ASYNC_ECALLS_OCALLS
	int modsslload = read_int_from_file("mod_ssl_load.txt");
	// mod_ssl_load.txt only exists for Apache; -1 is returned if
	// the files does not exist, in which case we can create the
	// async queues now
	if (modsslload == -1) {
		modsslload = 1;
	} else {
		int newmodsslload = (modsslload == 0 ? 1 : 0);
		write_int_to_file("mod_ssl_load.txt", newmodsslload);
	}

	if (modsslload == 1) {
		// read the busy wait duration and the number of threads from a file
		busy_wait_cycles = read_int_from_file("busy_wait_cycles.txt");
		app_threads = read_int_from_file("app_threads.txt");
		sgx_threads = read_int_from_file("sgx_threads.txt");
		lthread_tasks = read_int_from_file("lthread_tasks.txt");

#ifdef USE_ECALL_QUEUE
		ecall_queue = newmpmc(app_threads);
#endif
#ifdef USE_OCALL_QUEUE
		ocall_queue = newmpmc(app_threads);
#endif

		int i;
		for (i=0; i<sgx_threads; i++) {
			pthread_t t;
			int *arg = malloc(sizeof(*arg));
			*arg = i;
			pthread_create(&t, NULL, sgx_thread_handler, arg);
		}

		app_threads_lock = malloc(sizeof(*app_threads_lock)*app_threads);
		app_threads_cond = malloc(sizeof(*app_threads_cond)*app_threads);

		for (i=0; i<app_threads; i++) {
			pthread_mutex_init(&app_threads_lock[i], NULL);
			pthread_cond_init(&app_threads_cond[i], NULL);
		}

		pthread_t t;
		pthread_create(&t, NULL, async_ecall_busy_waiter, NULL);
	}
	if (modsslload == 1)
	{
#endif
		if (initialize_enclave() < 0) {
			printf("Enclave initialization error!\n");
			exit(-1);
		}

#ifdef SGX_MODE_SIM
		// not needed anymore
		if (ssllib_handler != NULL) {
			dlclose(ssllib_handler);
			ssllib_handler = NULL;
		}
#endif

		init_clock_mhz();

		tls_processing_module_init();
#ifdef USE_ASYNC_ECALLS_OCALLS
	}
#endif
}

void destroy_enclave(void) {
	if (global_eid != 0) {
		printf("Destroying enclave %lu!\n", global_eid);
		sgx_destroy_enclave(global_eid);
	} else {
		printf("Cannot destroy a non-initialized enclave!\n");
	}
}

/**************************** ECALLS ********************************/

char* make_asynchronous_ecall(char* msg, enum transition_type type, size_t size) {
	// as we use 1 slot per application thread we can safely assume
	// that the enqueue will always work. So no need to call
	//              mpmc_wait_for_enqueue(ecall_queue, tid, busy_wait_cycles)
	mpmc_enqueue(ecall_queue, type, tid, size);

#ifdef USE_BUSY_WAITING_THREAD
	// we need to use the lock to ensure that the broadcast happens before the wait
	pthread_mutex_lock(&busy_waiter_lock);
	if (__atomic_add_fetch(&pending_async_ecalls, 1, __ATOMIC_RELAXED) == 1) {
		pthread_cond_broadcast(&busy_waiter_cond);
	}
	pthread_mutex_unlock(&busy_waiter_lock);
#endif

	int spins = 0;
	while (1) {
#ifndef USE_BUSY_WAITING_THREAD
		// if there is no master thread then become the master
		int expected = -1;
		int desired = tid;
		/*
		 * if (master_app_thread == expected) master_app_thread = desired; return true;
		 * else expected = master_app_thread; return false;
		 */
		__atomic_compare_exchange_n(&master_app_thread, &expected, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
#endif

		if (mpmc_wait_for_result(ecall_queue, tid, 0)) {
			break;
		}

#ifdef USE_OCALL_QUEUE
		char* msg;
		size_t size = 0;
		enum transition_type type = mpmc_dequeue(ocall_queue, tid, (void**)&msg);
		if (type == ocall_malloc_t) {
			struct cell_malloc* s = (struct cell_malloc*)msg;
			size = sizeof(*s);
			s->ret = malloc(s->size);
			//printf("malloc(%lu): %p\n", s->size, s->ret);
			//printf("App thread %d ocall_malloc(%lu) -> %p\n", tid, s->size, s->ret);
		} else if (type == ocall_free_t) {
			struct cell_free* s = (struct cell_free*)msg;
			size = sizeof(*s);
			//printf("App thread %d ocall_free(%p)\n", tid, s->ptr);
			//printf("free(%p)\n", s->ptr);
			free(s->ptr);
		} else if (type == ocall_bio_ctrl_t) {
			struct cell_ocall_bio_ctrl* s = (struct cell_ocall_bio_ctrl*)msg;
			size = sizeof(*s);
			//printf("App thread %d ocall_bio_ctrl(%p, %d, %ld, %p, %p)\n", tid, s->bio, s->cmd, s->argl, s->arg, s->cb);
			s->ret = ocall_bio_ctrl(s->bio, s->cmd, s->argl, s->arg, s->cb);
		} else if (type == ocall_bio_destroy_t) {
			struct cell_bio_destroy* s = (struct cell_bio_destroy*)msg;
			size = sizeof(*s);
			//printf("App thread %d ocall_bio_destroy(%p, %p)\n", tid, s->bio, s->cb);
			s->ret = ocall_bio_destroy(s->bio, s->cb);
		} else if (type == ocall_bio_read_t) {
			struct cell_bio_read* s = (struct cell_bio_read*)msg;
			size = sizeof(*s);
			//printf("App thread %d ocall_bio_read(%p, %p, %d, %p)\n", tid, s->bio, s->buf, s->len, s->cb);
			s->ret = ocall_bio_read(s->bio, s->buf, s->len, s->cb);
		} else if (type == ocall_bio_write_t) {
			struct cell_bio_write* s = (struct cell_bio_write*)msg;
			size = sizeof(*s);
			//printf("App thread %d ocall_bio_write(%p, %p, %d, %p)\n", tid, s->bio, s->buf, s->len, s->cb);
			s->ret = ocall_bio_write(s->bio, s->buf, s->len, s->cb);
		} else if (type == ocall_alpn_select_cb_t) {
			struct cell_alpn_select_cb* s = (struct cell_alpn_select_cb*)msg;
			size = sizeof(*s);
			//printf("App thread %d ocall_alpn_select_cb(...)\n", tid);
			s->ret = ocall_alpn_select_cb(s->s, (const unsigned char**)&(s->out), &(s->outlen), s->in, s->inlen, s->arg, s->cb);
		} else if (type == ocall_set_tmp_dh_cb_t) {
			struct cell_set_tmp_dh_cb* s = (struct cell_set_tmp_dh_cb*)msg;
			size = sizeof(*s);
			//printf("App thread %d ocall_set_tmp_dh(...)\n", tid);
			s->ret = ocall_SSL_CTX_set_tmp_dh_cb(s->ssl, s->is_export, s->keylength, s->cb);
		} else {
			//unknown type
		}

		if (size > 0) {
			mpmc_enqueue_result(ocall_queue, tid, size);
			spins = 0;
		}
#endif

#ifndef USE_BUSY_WAITING_THREAD
		/*
		 * if I am the master thread then
		 * 	check every ecall and ocall slots (but mine :))
		 * 	if there is something then wake up the corresponding thread
		 */
		if ((__atomic_load_n(&master_app_thread, __ATOMIC_RELAXED) == tid)) {
			int i;
			for (i=0; i<app_threads; i++) {
				if (i != tid && (mpmc_wait_for_result(ecall_queue, i, 0)
#ifdef USE_OCALL_QUEUE
							|| mpmc_slot_taken(ocall_queue, i)
#endif
					)) {
					pthread_cond_signal(&app_threads_cond[i]);
				}
			}
		}
#endif

		if (
#ifndef USE_BUSY_WAITING_THREAD
				__atomic_load_n(&master_app_thread, __ATOMIC_RELAXED) != tid &&
#endif
				++spins > busy_wait_cycles) { // apparently the best value is 0
			pthread_mutex_lock(&app_threads_lock[tid]);
			pthread_cond_wait(&app_threads_cond[tid], &app_threads_lock[tid]);
			pthread_mutex_unlock(&app_threads_lock[tid]);
			spins = 0;
		} else {
			sched_yield();
		}
	}

#ifndef USE_BUSY_WAITING_THREAD
	int expected = tid;
	int desired = -1;
	/*
	 * if (master_app_thread == expected) master_app_thread = desired; return true;
	 * else expected = master_app_thread; return false;
	 */
	int i_am_master = __atomic_compare_exchange_n(&master_app_thread, &expected, desired, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
	// if I am the master thread then set master thread to 0 and wake up another thread
	if (i_am_master) {
		int i;
		for (i=0; i<app_threads; i++) {
			if (i != tid && (mpmc_wait_for_result(ecall_queue, i, 0)
#ifdef USE_OCALL_QUEUE
						|| mpmc_slot_taken(ocall_queue, i)
#endif
				)) {
				pthread_cond_signal(&app_threads_cond[i]);
				break;
			}
		}
	}
#else
	pthread_mutex_lock(&busy_waiter_lock);
	__atomic_sub_fetch(&pending_async_ecalls, 1, __ATOMIC_RELAXED);
	pthread_mutex_unlock(&busy_waiter_lock);
#endif

	char* ret;
	mpmc_dequeue_result(ecall_queue, tid, (void**)&ret);
	return ret;
}

int SSL_read(SSL *ssl, void *buf, int num) {
	int retval = 0;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;
		ret = ecall_SSL_read(global_eid, &retval, ssl, buf, num);
		if (ret != SGX_SUCCESS) {
			print_error_message(ret, __func__);
			return 0;
		}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_read* cs = (struct cell_ssl_read*)msg;
		cs->ssl = ssl;
		cs->buf = buf;
		cs->num = num;

		msg = make_asynchronous_ecall(msg, ecall_ssl_read, sizeof(*cs));
		cs = (struct cell_ssl_read*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);
	return retval;
}

int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

unsigned char * ASN1_STRING_data(ASN1_STRING *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_STRING_length(const ASN1_STRING *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

long	BIO_ctrl(BIO *bp,int cmd,long larg,void *parg) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	long retval;

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BIO_ctrl(global_eid, &retval, bp, cmd, larg, parg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_bio_ctrl* cs = (struct cell_bio_ctrl*)msg;
		cs->bio = bp;
		cs->cmd = cmd;
		cs->larg = larg;
		cs->parg = parg;

		msg = make_asynchronous_ecall(msg, ecall_bio_ctrl, sizeof(*cs));
		cs = (struct cell_bio_ctrl*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);
	return retval;
}

int	BIO_free(BIO *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BIO_free(global_eid, &retval, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

long	BIO_int_ctrl(BIO *bp,int cmd,long larg,int iarg) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	long retval = 0;
	ret = ecall_BIO_int_ctrl(global_eid, &retval, bp, cmd, larg, iarg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

BIO *	BIO_new(BIO_METHOD *type) {
	BIO* retval = NULL;
	int method_in_enclave;

   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BIO_new(global_eid, &retval, type, &method_in_enclave);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_bio_new* cs = (struct cell_bio_new*)msg;
		cs->type = type;

		msg = make_asynchronous_ecall(msg, ecall_bio_new, sizeof(*cs));
		cs = (struct cell_bio_new*)msg;
		method_in_enclave = cs->method_in_enclave;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);

	if (type && retval && !method_in_enclave) {
		if (!type->create(retval)) {
			BIO_free(retval);
		}
	}

	return retval;
}

BIO *BIO_new_file(const char *filename, const char *mode) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	BIO* retval = 0;
	ret = ecall_BIO_new_file(global_eid, &retval, filename, mode);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int	BIO_read(BIO *b, void *data, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO_METHOD *BIO_s_mem(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	BIO_write(BIO *b, const void *data, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void BIO_set_flags(BIO *b, int flags) {
	// the BIO is allocated in untrusted memory, so we don't need an ecall
	b->flags |= flags;
}

int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file, int line) {
	int retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_CRYPTO_add_lock(global_eid, &retval, pointer, amount, type, file, line);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void CRYPTO_free(void *ptr) {
	free(ptr);
}

void *CRYPTO_malloc(int num, const char *file, int line) {
	if (num <= 0)
		return NULL;
	return malloc(num);
}

void	DH_free(DH *dh) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_DH_free(global_eid, dh);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void EC_KEY_free(EC_KEY *key) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EC_KEY_free(global_eid, key);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

EC_KEY *EC_KEY_new_by_curve_name(int nid) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	EC_KEY* retval = 0;
	ret = ecall_EC_KEY_new_by_curve_name(global_eid, &retval, nid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

const char *ENGINE_get_id(const ENGINE *e) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	char* retval = 0;
	ret = ecall_ENGINE_get_id(global_eid, &retval, e);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

const char *ENGINE_get_name(const ENGINE *e) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	char* retval = 0;
	ret = ecall_ENGINE_get_name(global_eid, &retval, e);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void ENGINE_load_builtin_engines(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ENGINE_load_builtin_engines(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

ENGINE *ENGINE_get_first(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ENGINE *ENGINE_get_next(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ENGINE *ENGINE_by_id(const char *id) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ENGINE_cleanup(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int ENGINE_free(ENGINE *e) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ENGINE_set_default(ENGINE *e, unsigned int flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ERR_remove_thread_state(const CRYPTO_THREADID *tid) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void ERR_clear_error(void ) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_clear_error(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_error_string_n(global_eid, e, buf, len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}else{
		printf("ERR_error_string_n: %lu %.*s\n", e, (int)len, buf);
	}
	log_exit_ecall(__func__);
}

unsigned long ERR_peek_error(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	unsigned long retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_peek_error(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

unsigned long ERR_peek_error_line_data(const char **file,int *line, const char **data,int *flags) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	unsigned long retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_peek_error_line_data(global_eid, &retval, file, line, data, flags);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

unsigned long ERR_peek_last_error(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	unsigned long retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_peek_last_error(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

const EVP_CIPHER *EVP_aes_128_cbc(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void EVP_cleanup(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_cleanup(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int	EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	EVP_DigestFinal_ex(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s) {
   if (global_eid == 0) {
#ifdef SGX_MODE_SIM
		//SDK >v1.9, sim mode, this call is made by the SGX SDK while it creates the enclave and must
		//call the original OpenSSL function
		int (*EVP_DigestFinal_ex_original)(EVP_MD_CTX*, unsigned char*, unsigned int*) = load_original_ssl_function("EVP_DigestFinal_ex");
		return EVP_DigestFinal_ex_original(ctx, md, s);
#else
		initialize_library();
#endif
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_DigestFinal_ex(global_eid, &retval, ctx, md, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int	EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
   if (global_eid == 0) {
#ifdef SGX_MODE_SIM
		//SDK >v1.9, sim mode, this call is made by the SGX SDK while it creates the enclave and must
		//call the original OpenSSL function
		int (*EVP_DigestInit_ex_original)(EVP_MD_CTX*, const EVP_MD*, ENGINE*) = load_original_ssl_function("EVP_DigestInit_ex");
		return EVP_DigestInit_ex_original(ctx, type, impl);
#else
		initialize_library();
#endif
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_DigestInit_ex(global_eid, &retval, ctx, type, impl);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int	EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *d, size_t cnt) {
   if (global_eid == 0) {
#ifdef SGX_MODE_SIM
		//SDK >v1.9, sim mode, this call is made by the SGX SDK while it creates the enclave and must
		//call the original OpenSSL function
		int (*EVP_DigestUpdate_original)(EVP_MD_CTX*, const void*, size_t) = load_original_ssl_function("EVP_DigestUpdate");
		return EVP_DigestUpdate_original(ctx, d, cnt);
#else
		initialize_library();
#endif
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_DigestUpdate(global_eid, &retval, ctx, d, cnt);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int	EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_MD_CTX *EVP_MD_CTX_create(void) {
   if (global_eid == 0) {
#ifdef SGX_MODE_SIM
		//SDK >v1.9, sim mode, this call is made by the SGX SDK while it creates the enclave and must
		//call the original OpenSSL function
		EVP_MD_CTX* (*EVP_MD_CTX_create_original)(void) = load_original_ssl_function("EVP_MD_CTX_create");
		return EVP_MD_CTX_create_original();
#else
		initialize_library();
#endif
	}

   log_enter_ecall(__func__);
	EVP_MD_CTX* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_MD_CTX_create(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void	EVP_MD_CTX_destroy(EVP_MD_CTX *ctx) {
   if (global_eid == 0) {
#ifdef SGX_MODE_SIM
		//SDK >v1.9, sim mode, this call is made by the SGX SDK while it creates the enclave and must
		//call the original OpenSSL function
		void (*EVP_MD_CTX_destroy_original)(EVP_MD_CTX*) = load_original_ssl_function("EVP_MD_CTX_destroy");
		return EVP_MD_CTX_destroy_original(ctx);
#else
		initialize_library();
#endif
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_MD_CTX_destroy(global_eid, ctx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void EVP_PKEY_free(EVP_PKEY *pkey) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_PKEY_free(global_eid, pkey);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);

}

const EVP_MD *EVP_sha1(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	EVP_MD* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_sha1(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return (const EVP_MD*)retval;
}

const EVP_MD *EVP_sha256(void) {
#ifdef SGX_MODE_SIM
	if (global_eid == 0) {
		//SDK >v1.9, sim mode, this call is made by the SGX SDK while it creates the enclave and must
		//call the original OpenSSL function
		const EVP_MD* (*EVP_sha256_original)(void) = load_original_ssl_function("EVP_sha256");
		return EVP_sha256_original();
	}
#endif

	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int i2d_SSL_SESSION(SSL_SESSION *in,unsigned char **pp) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_i2d_SSL_SESSION(global_eid, &retval, (void*)in, pp);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int MD5_Init(MD5_CTX *c) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_MD5_Init(global_eid, &retval, c);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int MD5_Update(MD5_CTX *c, const void *data, size_t len) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_MD5_Update(global_eid, &retval, c, data, len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int MD5_Final(unsigned char *md, MD5_CTX *c) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_MD5_Final(global_eid, &retval, md, c);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long sec, long maxsec) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_ONEREQ *OCSP_request_add0_id(OCSP_REQUEST *req, OCSP_CERTID *cid) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status, int *reason, ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME **nextupd) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void OPENSSL_config(const char *config_name) {
   if (global_eid == 0) {
   	initialize_library();
   }

	log_enter_ecall(__func__);
	sgx_status_t ret;
	char* str = (char*)malloc(sizeof(*str)*4);
	ret = ecall_OPENSSL_config(global_eid, config_name);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

RSA *	RSA_generate_key(int bits, unsigned long e,void (*callback)(int,int,void *),void *cb_arg) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SHA1_Init(SHA_CTX *c) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SHA1_Final(unsigned char *md, SHA_CTX *c) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int sk_num(const _STACK *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_sk_num(global_eid, &retval, (const void*)s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void *sk_value(const _STACK *s, int v) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	void* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_sk_value(global_eid, &retval, (const void*)s, v);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

char *SSL_CIPHER_description(const SSL_CIPHER *c, char *buf, int size) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	char* retval;
	ret = ecall_SSL_CIPHER_description(global_eid, &retval, c, buf, size);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

const char *	SSL_CIPHER_get_name(const SSL_CIPHER *c) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	char* retval;
	ret = ecall_SSL_CIPHER_get_name(global_eid, &retval, c);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return (const char*) retval;
}

long	SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg) {
	long retval = 0;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_ctrl(global_eid, &retval, ssl, cmd, larg, parg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_ctrl* cs = (struct cell_ssl_ctrl*)msg;
		cs->ssl = ssl;
		cs->cmd = cmd;
		cs->larg = larg;
		cs->parg = parg;

		msg = make_asynchronous_ecall(msg, ecall_ssl_ctrl, sizeof(*cs));
		cs = (struct cell_ssl_ctrl*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);
	return retval;
}

long	SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	long retval = 0;
	ret = ecall_SSL_CTX_ctrl(global_eid, &retval, ctx, cmd, larg, parg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

long SSL_CTX_callback_ctrl(SSL_CTX *c, int i, void (*cb)(void)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	long retval;
	ret = ecall_SSL_CTX_callback_ctrl(global_eid, &retval, c, i, (void*)cb);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void	SSL_CTX_free(SSL_CTX *c) {
   if (global_eid == 0) {
   	initialize_library();
   }

	log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_free(global_eid, c);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *c) {
	X509_STORE* retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_get_cert_store(global_eid, &retval, c);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	STACK_OF(X509_NAME)* retval;
	ret = ecall_SSL_CTX_get_client_CA_list(global_eid, (void**)&retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void *SSL_CTX_get_ex_data(const SSL_CTX *ssl,int idx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	void* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_get_ex_data(global_eid, &retval, ssl, idx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
	if (new_func || dup_func || free_func) {
		printf("ecall %s, callbacks are not null, beware!\n",  __func__);
	} else {
		//printf("ecall %s\n", __func__);
	}
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_SSL_CTX_get_ex_new_index(global_eid, &retval, argl, argp, new_func, dup_func, free_func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

long SSL_CTX_get_timeout(const SSL_CTX *ctx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	long retval = 0;
	ret = ecall_SSL_CTX_get_timeout(global_eid, &retval, ctx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int,X509_STORE_CTX *) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int (*retval)(int, X509_STORE_CTX *);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_get_verify_callback(global_eid, (void**)&retval, ctx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int SSL_CTX_get_verify_depth(const SSL_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_get_verify_mode(global_eid, &retval, ctx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	SSL_CTX* retval = 0;
	ret = ecall_SSL_CTX_new(global_eid, &retval, meth);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int	SSL_CTX_remove_session(SSL_CTX *s, SSL_SESSION *c) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl, unsigned char *data,int len,int *copy)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_sess_set_get_cb(global_eid, ctx, (void*)get_session_cb);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_sess_set_new_cb(global_eid, ctx, (void*)new_session_cb);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_sess_set_remove_cb(global_eid, ctx, (void*)remove_session_cb);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_default_passwd_cb(global_eid, ctx, (void*)cb);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*cb)(const SSL *ssl,int type,int val)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_info_callback(global_eid, ctx, (void*)cb);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s, int (*cb) (SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg), void *arg) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_next_protos_advertised_cb(global_eid, s, (void*)cb, arg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int	SSL_CTX_set_session_id_context(SSL_CTX *ctx,const unsigned char *sid_ctx, unsigned int sid_ctx_len) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_session_id_context(global_eid, &retval, ctx, sid_ctx, sid_ctx_len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void SSL_CTX_set_verify(SSL_CTX *ctx,int mode, int (*callback)(int, X509_STORE_CTX *)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_tmp_rsa_callback(global_eid, ctx, mode, (void*)callback);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_verify_depth(global_eid, ctx, depth);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_use_certificate(global_eid, &retval, ctx, x);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_use_PrivateKey(global_eid, &retval, ctx, pkey);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int	SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_use_PrivateKey_file(global_eid, &retval, ctx, file, type);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

static __thread hashmap* ssl_ex_data = NULL;

SSL *	SSL_new(SSL_CTX *ctx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

	SSL* retval;
	SSL* out_s = (SSL*)malloc(sizeof(*out_s));
	struct ssl3_state_st *s3 = malloc(sizeof(*s3));
	bzero(s3, sizeof(*s3));
	out_s->s3 = s3;

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;
		ret = ecall_SSL_new(global_eid, &retval, ctx, out_s);
		if (ret != SGX_SUCCESS) {
			print_error_message(ret, __func__);
			return 0;
		}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {

		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_new* cs = (struct cell_ssl_new*)msg;
		cs->ctx = ctx;
		cs->out_s = out_s;

		msg = make_asynchronous_ecall(msg, ecall_ssl_new, sizeof(*cs));
		cs = (struct cell_ssl_new*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);

	struct ssl_ex_data* ed = (struct ssl_ex_data*)malloc(sizeof(*ed));
	ed->s = 5;
	ed->a = (void**)calloc(sizeof(*(ed->a)), ed->s);

	if (!ssl_ex_data) {
		ssl_ex_data = hashmapCreate(0);
	}
	hashmapInsert(ssl_ex_data, ed, (unsigned long)retval);

	return retval;
}

void	SSL_free(SSL *ssl) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_free(global_eid, ssl);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_free* cs = (struct cell_ssl_free*)msg;
		cs->out_s = ssl;

		make_asynchronous_ecall(msg, ecall_ssl_free, sizeof(*cs));
	}
#endif

	if (!ssl || ssl->references <= 0) {
		if (ssl) {
			if (ssl->s3) {
				free(ssl->s3);
			}
			free(ssl);
		}
		log_exit_ecall(__func__);

		struct ssl_ex_data* ed = hashmapRemove(ssl_ex_data, (unsigned long)ssl);
		free(ed->a);
		free(ed);
	}
}

int SSL_set_ex_data(SSL *ssl,int idx,void *data) {
	struct ssl_ex_data* ed = NULL;
	ed = hashmapGet(ssl_ex_data, (unsigned long)ssl);

	if (!ed) {
		printf("%s No ssl_ex_data for %p. Abort!\n", __func__, ssl);
		exit(-1);
	}

	if (idx >= ed->s) {
		ed->a = realloc(ed->a, 2*idx);
		ed->s = 2*idx;
	}
	ed->a[idx] = data;
	return 1;
}

void *SSL_get_ex_data(const SSL *ssl,int idx) {
	struct ssl_ex_data* ed = hashmapGet(ssl_ex_data, (unsigned long)ssl);
	if (!ed) {
		printf("%s No ssl_ex_data for %p. Abort!\n", __func__, ssl);
		exit(-1);
	}
	return (idx < ed->s ? ed->a[idx] : NULL);
}

int	SSL_write(SSL *ssl,const void *buf,int num) {
	int retval = 0;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_write(global_eid, &retval, ssl, buf, num);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_write* cs = (struct cell_ssl_write*)msg;
		cs->ssl = ssl;
		cs->buf = (void*)buf;
		cs->num = num;

		msg = make_asynchronous_ecall(msg, ecall_ssl_write, sizeof(*cs));
		cs = (struct cell_ssl_write*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);
	return retval;
}

int SSL_do_handshake(SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_do_handshake(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

const char *SSLeay_version(int type) {
   if (global_eid == 0) {
   	initialize_library();
   }

	log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	char* retval;
	ret = ecall_SSLeay_version(global_eid, &retval, type);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return (const char*)retval;
}

SSL_SESSION *SSL_get1_session(SSL *ssl) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

X509 *SSL_get_certificate(const SSL *ssl) {
	X509* retval = NULL;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;
		ret = ecall_SSL_get_certificate(global_eid, &retval, ssl);
		if (ret != SGX_SUCCESS) {
			print_error_message(ret, __func__);
			return 0;
		}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_get_certificate* cs = (struct cell_ssl_get_certificate*)msg;
		cs->ssl = (SSL*)ssl;

		msg = make_asynchronous_ecall(msg, ecall_ssl_get_certificate, sizeof(*cs));
		cs = (struct cell_ssl_get_certificate*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);
	return retval;
}

const SSL_CIPHER *SSL_get_current_cipher(const SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	SSL_CIPHER* retval;
	ret = ecall_SSL_get_current_cipher(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return (const SSL_CIPHER*)retval;
}

int	SSL_get_error(const SSL *s,int ret_code) {
	int retval = 0;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;
		ret = ecall_SSL_get_error(global_eid, &retval, s, ret_code);
		if (ret != SGX_SUCCESS) {
			print_error_message(ret, __func__);
			return 0;
		}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_get_error* cs = (struct cell_ssl_get_error*)msg;
		cs->ssl = (SSL*)s;
		cs->ret_code = ret_code;

		msg = make_asynchronous_ecall(msg, ecall_ssl_get_error, sizeof(*cs));
		cs = (struct cell_ssl_get_error*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);
	return retval;
}

int SSL_get_ex_data_X509_STORE_CTX_idx(void ) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_SSL_get_ex_new_index(global_eid, &retval, argl, argp, new_func, dup_func, free_func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509 *	SSL_get_peer_certificate(const SSL *s) {
	//avoid an ecall
	X509 *r;
	if ((s == NULL) || (s->session == NULL)) {
		r = NULL;
	} else {
		r = (X509*)s->session;
	}
	return r;

	/*
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	X509* retval;
	ret = ecall_SSL_get_peer_certificate(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = NULL;
	}
	log_exit_ecall(__func__);
	return retval;
	*/
}

BIO *	SSL_get_rbio(const SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	BIO* retval = 0;
	ret = ecall_SSL_get_rbio(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

char servername[256] = {0};
const char *SSL_get_servername(const SSL *s, const int type) {
	//return '\0' as we don't need to support SNI
	//and the value returned by the ecall is '\0' anyway
	return servername;

	/*
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int len;
	ret = ecall_SSL_get_servername(global_eid, s, type, servername, &len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		len = 0;
	}
	servername[len] = '\0';
	log_exit_ecall(__func__);
	return (const char*)(len ? servername : NULL);
	*/
}

SSL_SESSION *SSL_get_session(const SSL *ssl) {
	return (ssl->session);
}

int SSL_get_shutdown(const SSL *ssl) {
	return (ssl->shutdown);
}

long SSL_get_verify_result(const SSL *ssl) {
	return (ssl->verify_result);
}

const char *SSL_get_version(const SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval;
	ret = ecall_SSL_get_version_as_int(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);

	switch (retval) {
		case DTLS1_VERSION:
			return (SSL_TXT_DTLS1);
		case TLS1_VERSION:
			return (SSL_TXT_TLSV1);
		case TLS1_1_VERSION:
			return (SSL_TXT_TLSV1_1);
		case TLS1_2_VERSION:
			return (SSL_TXT_TLSV1_2);
		default:
			return ("unknown");
	}
}

BIO *	SSL_get_wbio(const SSL *s) {
	return (s->wbio);
}

int SSL_library_init(void ) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

	if (global_eid == 0) {
		initialize_library();
	}

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_SSL_library_init(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void	SSL_load_error_strings(void ) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_load_error_strings(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int SSL_select_next_proto(unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, const unsigned char *client, unsigned int client_len) {
	int retval = -1;

   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_select_next_proto(global_eid, &retval, out, outlen, in, inlen, client, client_len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = -1;
	}
	log_exit_ecall(__func__);

	return retval;
}

void	SSL_SESSION_free(SSL_SESSION *ses) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

unsigned char ssl_session_id[32];
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_SESSION_get_id(global_eid, (void*)s, ssl_session_id, len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return (const unsigned char*)0;
	}
	log_exit_ecall(__func__);
	return (const unsigned char*)ssl_session_id;
}

void SSL_set_accept_state(SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_set_accept_state(global_eid, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void SSL_set_connect_state(SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;
		ret = ecall_SSL_set_connect_state(global_eid, s);
		if (ret != SGX_SUCCESS) {
			print_error_message(ret, __func__);
		}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_set_connect_state* cs = (struct cell_ssl_set_connect_state*)msg;
		cs->ssl = s;

		msg = make_asynchronous_ecall(msg, ecall_ssl_set_connect_state, sizeof(*cs));
		cs = (struct cell_ssl_set_connect_state*)msg;
		int retval = cs->ret;
		if (retval != 1) {
			fprintf(stderr, "%s:%i:%s error during asynchronous ecall!\n", __FILE__, __LINE__, __func__);
		}
	}
#endif

	log_exit_ecall(__func__);
}

int	SSL_set_fd(SSL *s, int fd) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_set_fd(global_eid, &retval, s, fd);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void SSL_set_quiet_shutdown(SSL *ssl,int mode) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_set_quiet_shutdown(global_eid, ssl, mode);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int	SSL_set_session(SSL *to, SSL_SESSION *session) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_set_shutdown(SSL *ssl,int mode) {
	ssl->shutdown = mode;
}

SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	SSL_CTX* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_set_SSL_CTX(global_eid, &retval, ssl,ctx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void	SSL_set_verify(SSL *s, int mode, int (*callback)(int ok,X509_STORE_CTX *ctx)) {
	s->verify_mode = mode;
	if (callback != NULL) s->verify_callback = callback;
}

void	SSL_set_verify_depth(SSL *s, int depth) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int SSL_shutdown(SSL *s) {
	int retval = 0;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_shutdown(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_shutdown* cs = (struct cell_ssl_shutdown*)msg;
		cs->ssl = s;

		msg = make_asynchronous_ecall(msg, ecall_ssl_shutdown, sizeof(*cs));
		cs = (struct cell_ssl_shutdown*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);
	return retval;
}

int SSL_state(const SSL *ssl) {
	return (ssl->state);
}

const SSL_METHOD *SSLv23_method(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	SSL_METHOD* retval = 0;
	ret = ecall_SSLv23_method(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return (const SSL_METHOD*)retval;
}

int X509_check_issued(X509 *issuer, X509 *subject) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_check_issued(global_eid, &retval, issuer, subject);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_digest(const X509 *data,const EVP_MD *type, unsigned char *md, unsigned int *len) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_X509_digest(global_eid, &retval, data, type, md, len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void X509_email_free(STACK_OF(OPENSSL_STRING) *sk) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void *X509_get_ex_data(X509 *r, int idx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	void* retval = 0;
	ret = ecall_X509_get_ex_data(global_eid, &retval, r, idx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
	if (new_func || dup_func || free_func) {
		printf("ecall %s, callbacks are not null, beware!\n",  __func__);
	} else {
		//printf("ecall %s\n", __func__);
	}
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_X509_get_ex_new_index(global_eid, &retval, argl, argp, new_func, dup_func, free_func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void	*	X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	void* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_ext_d2i(global_eid, &retval, x, nid, crit, idx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509_NAME *	X509_get_issuer_name(X509 *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_INTEGER *	X509_get_serialNumber(X509 *x) {
	ASN1_INTEGER* retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_serialNumber(global_eid, &retval, x);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509_NAME *	X509_get_subject_name(X509 *a) {
	X509_NAME* retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_subject_name(global_eid, &retval, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

X509_LOOKUP_METHOD *X509_LOOKUP_file(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_NAME_digest(const X509_NAME *data,const EVP_MD *type, unsigned char *md, unsigned int *len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_STRING *X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	ASN1_STRING* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_NAME_ENTRY_get_data(global_eid, &retval, ne);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	X509_NAME_ENTRY* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_NAME_get_entry(global_eid, &retval, name, loc);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int	X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_NAME_get_index_by_NID(global_eid, &retval, name, nid, lastpos);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

char* X509_NAME_oneline(X509_NAME *a,char *buf,int size) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	char* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_NAME_oneline(global_eid, &retval, a, buf, size);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_set_ex_data(X509 *r, int idx, void *arg) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_set_ex_data(global_eid, &retval, r, idx, arg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_STORE_CTX_free(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

X509 *	X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	X509_STORE_CTX_get_error(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void *	X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx,int idx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) *chain) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

X509_STORE_CTX *X509_STORE_CTX_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *X509_verify_cert_error_string(long n) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

unsigned long ERR_get_error(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	unsigned long retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_get_error(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int OBJ_sn2nid(const char *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_OBJ_sn2nid(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *OCSP_cert_status_str(long s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *OCSP_response_status_str(long s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_RESPONSE * d2i_OCSP_RESPONSE(OCSP_RESPONSE **a, const unsigned char **in, long len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void OPENSSL_add_all_algorithms_noconf(void) {
   if (global_eid == 0) {
#ifdef SGX_MODE_SIM
		//SDK >v1.9, sim mode, do not initialize the library as this call is made by the SGX SDK
		//while it is loading and would fail to create the enclave.
		void (*OPENSSL_add_all_algorithms_noconf_original)(void) = load_original_ssl_function("OPENSSL_add_all_algorithms_noconf");
		OPENSSL_add_all_algorithms_noconf_original();
		return;
#else
		initialize_library();
#endif
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_OPENSSL_add_all_algorithms_noconf(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int  RAND_bytes(unsigned char *buf,int num) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_CTX_set_ex_data(SSL_CTX *ssl,int idx,void *data) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_SSL_CTX_set_ex_data(global_eid, &retval, ssl, idx, data);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

long SSL_CTX_set_timeout(SSL_CTX *ctx,long t) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	long retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_timeout(global_eid, &retval, ctx, t);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

SSL_SESSION * d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	SSL_SESSION* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_d2i_SSL_SESSION(global_eid, (void*)&retval, (void**)a, pp, length);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

void GENERAL_NAMES_free(GENERAL_NAMES *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	i2d_OCSP_REQUEST(OCSP_REQUEST *a, unsigned char **out) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	i2d_OCSP_RESPONSE(OCSP_RESPONSE *a, unsigned char **out) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void OCSP_BASICRESP_free(OCSP_BASICRESP *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void OCSP_CERTID_free(OCSP_CERTID *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void OCSP_REQUEST_free(OCSP_REQUEST *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

OCSP_REQUEST * OCSP_REQUEST_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void OCSP_RESPONSE_free(OCSP_RESPONSE *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

OCSP_BASICRESP * OCSP_response_get1_basic(OCSP_RESPONSE *resp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_RESPONSE * OCSP_RESPONSE_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_response_status(OCSP_RESPONSE *resp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx, int (*cb) (SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg), void *arg) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_alpn_select_cb(global_eid, ctx, (void*)cb, arg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_cipher_list(global_eid, &retval, ctx, str);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void X509_free(X509 *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_free(global_eid, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	DH* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_PEM_read_bio_DHparams(global_eid, &retval, bp, x, (void*)cb, u);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
	if (cb) {
		printf("ecall %s, callback is not null, beware!\n",  __func__);
	} else {
		//printf("ecall %s\n", __func__);
	}
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

	X509* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_PEM_read_bio_X509(global_eid, &retval, bp, x, (void*)cb, u);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u) {
	if (cb) {
		printf("ecall %s, callback is not null, beware!\n",  __func__);
	} else {
		//printf("ecall %s\n", __func__);
	}
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

	X509* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_PEM_read_bio_X509_AUX(global_eid, &retval, bp, x, (void*)cb, u);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int PEM_write_bio_X509(BIO *bp, X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ASN1_STRING_free(ASN1_STRING *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

ASN1_STRING* ASN1_STRING_type_new(int type) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void BIO_clear_flags(BIO *b, int flags) {
	// the BIO is allocated in untrusted memory, so we don't need an ecall
	b->flags &= ~flags;
}

int BIO_puts(BIO *b, const char *in) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO_METHOD* BIO_s_file(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	BIO_METHOD* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BIO_s_file(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}


BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	BIGNUM* retval;
	sgx_status_t rets = SGX_ERROR_UNEXPECTED;
	rets = ecall_BN_bin2bn(global_eid, &retval, s, len, ret);
	if (rets != SGX_SUCCESS) {
		print_error_message(rets, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int BN_clear_bit(BIGNUM *a, int n) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_clear_bit(global_eid, &retval, a, n);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

BIGNUM *BN_dup(const BIGNUM *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	BIGNUM* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_dup(global_eid, &retval, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int BN_is_zero(BIGNUM* a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_is_zero(global_eid, &retval, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void BN_free(BIGNUM *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_free(global_eid, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int BN_is_bit_set(const BIGNUM *a, int n) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_is_bit_set(global_eid, &retval, a, n);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

BIGNUM *BN_new(void) {
	BIGNUM* retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_new(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int BN_num_bits(const BIGNUM *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_num_bits(global_eid, &retval, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int BN_set_word(BIGNUM *a, BN_ULONG w) {
	int retval;	
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_set_word(global_eid, &retval, a, w);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	ASN1_INTEGER* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_to_ASN1_INTEGER(global_eid, &retval, bn, ai);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int DH_check(const DH *dh, int *ret) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *ERR_error_string(unsigned long e, char *ret) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	char* retval;
	sgx_status_t retsgx = SGX_ERROR_UNEXPECTED;
	retsgx = ecall_ERR_error_string(global_eid, &retval, e, ret);
	if (retsgx != SGX_SUCCESS) {
		print_error_message(retsgx, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

void GENERAL_NAME_free(GENERAL_NAME *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t retsgx = SGX_ERROR_UNEXPECTED;
	retsgx = ecall_GENERAL_NAME_free(global_eid, a);
	if (retsgx != SGX_SUCCESS) {
		print_error_message(retsgx, __func__);
	}
	log_exit_ecall(__func__);
}

const EVP_MD *EVP_get_digestbyname(const char *name) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	EVP_MD* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_get_digestbyname(global_eid, (void**)&retval, name);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return (const EVP_MD*)retval;
}

int EVP_MD_type(const EVP_MD *md) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_MD_type(global_eid, &retval, md);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_PKEY *EVP_PKEY_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
}

int OBJ_create(const char *oid, const char *sn, const char *ln) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_OBJ_create(global_eid, &retval, oid, sn, ln);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

const char *OBJ_nid2sn(int n) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	char* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_OBJ_nid2sn(global_eid, &retval, n);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

ASN1_OBJECT* X509_get_algorithm(X509* ptr) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	ASN1_OBJECT *retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_algorithm(global_eid, &retval, ptr);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int OBJ_obj2nid(const ASN1_OBJECT *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_OBJ_obj2nid(global_eid, &retval, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int OBJ_txt2nid(const char *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_OBJ_txt2nid(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp, void *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *callback, void *u) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_PEM_ASN1_write(global_eid, &retval, i2d, name, fp, x, enc, kstr, klen, (void*)callback, u);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	EVP_PKEY* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_PEM_read_bio_PrivateKey(global_eid, &retval, bp, x, (void*)cb, u);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509_CRL *PEM_read_bio_X509_CRL(BIO *bp, X509_CRL **x, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
	//	return PEM_ASN1_read_bio((d2i_of_void *)d2i_X509_CRL, "X509 CRL",bp,(void **)x,cb,u);
}


DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return NULL;
	//	return PEM_ASN1_read((d2i_of_void *)d2i_DHparams, "DH PARAMETERS",fp,(void **)x,cb,u);
}

int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
	//	return PEM_ASN1_write((i2d_of_void *)i2d_RSAPrivateKey,"RSA PRIVATE KEY",fp,x,enc,kstr,klen,cb,u);
}

void RSA_free(RSA *r) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int SSL_accept(SSL *s) {
	int retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;
		ret = ecall_SSL_accept(global_eid, &retval, s);
		if (ret != SGX_SUCCESS) {
			print_error_message(ret, __func__);
			return 0;
		}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_accept* cs = (struct cell_ssl_accept*)msg;
		cs->ssl = s;

		msg = make_asynchronous_ecall(msg, ecall_ssl_accept, sizeof(*cs));
		cs = (struct cell_ssl_accept*)msg;
		retval = cs->ret;
	}
#endif

	log_exit_ecall(__func__);
	return retval;
}

int SSL_connect(SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_connect(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int SSL_version(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

__thread SSL_CIPHER* cipher_copy_outside = NULL;
__thread char cipher_name_copy_outside[8192];

const SSL_CIPHER *fake_ssl3_get_cipher_by_char(const unsigned char *p) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

	if (!cipher_copy_outside) {
		cipher_copy_outside = malloc(sizeof(*cipher_copy_outside));
		cipher_copy_outside->name = cipher_name_copy_outside;
	}

	SSL_CIPHER* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ssl3_get_cipher_name_by_char(global_eid, (void**)&retval, p, cipher_name_copy_outside);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}

	log_exit_ecall(__func__);
	return (retval?cipher_copy_outside:NULL);
}

const SSL_METHOD fake_TLS_method_data = {
	.version = TLS1_2_VERSION,
	.get_cipher_by_char = fake_ssl3_get_cipher_by_char,
	/*
	.ssl_new = fake_tls1_new,
	.ssl_clear = fake_tls1_clear,
	.ssl_free = fake_tls1_free,
	.ssl_accept = fake_ssl23_accept,
	.ssl_connect = fake_ssl23_connect,
	.ssl_read = fake_ssl23_read,
	.ssl_peek = fake_ssl23_peek,
	.ssl_write = fake_ssl23_write,
	.ssl_shutdown = fake_ssl_undefined_function,
	.ssl_renegotiate = fake_ssl_undefined_function,
	.ssl_renegotiate_check = fake_ssl_ok,
	.ssl_get_message = fake_ssl3_get_message,
	.ssl_read_bytes = fake_ssl3_read_bytes,
	.ssl_write_bytes = fake_ssl3_write_bytes,
	.ssl_dispatch_alert = fake_ssl3_dispatch_alert,
	.ssl_ctrl = fake_ssl3_ctrl,
	.ssl_ctx_ctrl = fake_ssl3_ctx_ctrl,
	.put_cipher_by_char = fake_ssl3_put_cipher_by_char,
	.ssl_pending = fake_ssl_undefined_const_function,
	.num_ciphers = fake_ssl3_num_ciphers,
	.get_cipher = fake_ssl3_get_cipher,
	.get_ssl_method = fake_tls1_get_method,
	.get_timeout = fake_ssl23_default_timeout,
	.ssl3_enc = &fake_ssl3_undef_enc_method,
	.ssl_version = fake_ssl_undefined_void_function,
	.ssl_callback_ctrl = fake_ssl3_callback_ctrl,
	.ssl_ctx_callback_ctrl = fake_ssl3_ctx_callback_ctrl,
	*/
};

const SSL_METHOD *TLS_method(void) {
	return &fake_TLS_method_data;
}

_STACK *sk_dup(_STACK *sk) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int sk_find(_STACK *st, void *data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void sk_free(_STACK *st) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

_STACK *sk_new_null(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	_STACK* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_sk_new_null(global_eid, (void**)&retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

void sk_pop_free(_STACK *st, void (*func)(void *)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_sk_pop_free(global_eid, st, (void*)func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int sk_push(_STACK *st, void *data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_CTX_check_private_key(const SSL_CTX *ctx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_check_private_key(global_eid, &retval, ctx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *, void *), void *arg) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_cert_verify_callback(global_eid, ctx, (void*)cb, arg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_default_verify_paths(global_eid, &retval, ctx);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	return retval;
	log_exit_ecall(__func__);
}

void SSL_CTX_set_next_proto_select_cb(SSL_CTX *ctx, int (*cb) (SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg), void *arg) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_next_proto_select_cb(global_eid, ctx, (void*)cb, arg);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx, RSA *(*cb)(SSL *ssl, int is_export, int keylength)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_tmp_rsa_callback(global_eid, ctx, (void*)cb);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file) {
	int retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_use_certificate_chain_file(global_eid, &retval, ctx, file);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	STACK_OF(SSL_CIPHER)* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_get_ciphers(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl) {
	return (ssl->ctx);
}

int SSL_pending(const SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_pending(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

long SSL_SESSION_set_timeout(SSL_SESSION *s, long t) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	long retval = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_SESSION_set_timeout(global_eid, &retval, s, t);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
	return retval;
}

int SSL_set_alpn_protos(SSL *ssl, const unsigned char* protos, unsigned int protos_len) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_set_alpn_protos(global_eid, &retval, ssl, protos, protos_len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
	return retval;
}

void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);

#ifdef USE_ASYNC_ECALLS_OCALLS
	if (!ecall_queue) {
#endif
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_set_bio(global_eid, s, rbio, wbio);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
#ifdef USE_ASYNC_ECALLS_OCALLS
	} else {
		if (tid == -1) {
			tid = __sync_fetch_and_add(&next_tid, 1);
		}

		char* msg = mpmc_get_msg_at_slot(ecall_queue, tid);
		struct cell_ssl_set_bio* cs = (struct cell_ssl_set_bio*)msg;
		cs->ssl = s;
		cs->rbio = rbio;
		cs->wbio = wbio;

		msg = make_asynchronous_ecall(msg, ecall_ssl_set_bio, sizeof(*cs));
	}
#endif

	log_exit_ecall(__func__);
}

int SSL_set_cipher_list(SSL *s, const char *str) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_set_cipher_list(global_eid, &retval, s, str);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void SSL_set_info_callback(SSL *ssl, void (*cb)(const SSL *ssl, int type, int val)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_set_info_callback(global_eid, ssl, (void*)cb);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

const char *SSL_state_string(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *SSL_state_string_long(const SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	char* retval = NULL;
	ret = ecall_SSL_state_string_long(global_eid, &retval, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return (const char*)retval;
}

int SSL_use_certificate(SSL *ssl, X509 *x) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_SSL_use_certificate(global_eid, &retval, ssl, x);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int retval = 0;
	ret = ecall_SSL_use_PrivateKey(global_eid, &retval, ssl, pkey);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		retval = 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

const SSL_METHOD *SSLv23_client_method(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	SSL_METHOD* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSLv23_client_method(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return (const SSL_METHOD*)retval;
}

const SSL_METHOD *SSLv23_server_method(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	SSL_METHOD* retval = NULL;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSLv23_server_method(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return (const SSL_METHOD*)retval;
}

const SSL_METHOD *TLSv1_1_client_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_1_server_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_2_client_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_2_server_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_client_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const SSL_METHOD *TLSv1_server_method(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval = 0;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_add_ext(global_eid, &retval, x, ex, loc);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

unsigned char *X509_alias_get0(X509 *x, int *len) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	unsigned char* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_alias_get0(global_eid, &retval, x, len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_alias_set1(X509 *x, unsigned char *name, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_check_private_key(X509 *x, EVP_PKEY *k) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_check_private_key(global_eid, &retval, x, k);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_cmp(const X509 *a, const X509 *b) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_cmp_current_time(const ASN1_TIME *ctm) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_CRL_free(X509_CRL *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_get_ext_by_NID(X509 *x, int nid, int lastpos) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_ext_by_NID(global_eid, &retval, x, nid, lastpos);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509_EXTENSION *X509_get_ext(X509 *x, int loc) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	X509_EXTENSION* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_ext(global_eid, &retval, x, loc);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type, unsigned char *bytes, int len, int loc, int set) {
//printf("ecall %s\n", __func__);
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_NAME_add_entry_by_NID(global_eid, &retval, name, nid, type, bytes, len, loc, set);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	X509_NAME_ENTRY* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_NAME_delete_entry(global_eid, &retval, name, loc);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

void X509_NAME_ENTRY_free(X509_NAME_ENTRY *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_NAME_ENTRY_free(global_eid, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void X509_NAME_free(X509_NAME *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf, int len) {
	int retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_NAME_get_text_by_NID(global_eid, &retval, name, nid, buf, len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

X509 *X509_new(void) {
	X509* retval;	
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_new(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_pubkey_digest(const X509 *data, const EVP_MD *type, unsigned char *md, unsigned int *len) {
	int retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_pubkey_digest(global_eid, &retval, data, type, md, len);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;

}

ASN1_OBJECT* X509_get_cert_key_algor_algorithm(X509* x) {
	log_enter_ecall(__func__);
	ASN1_OBJECT* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_cert_key_algor_algorithm(global_eid, &retval, x);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_set_issuer_name(X509 *x, X509_NAME *name) {
   if (global_eid == 0) {
   	initialize_library();
   }

	log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_set_issuer_name(global_eid, &retval, x, name);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_set_notAfter(X509 *x, const ASN1_TIME *tm) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_set_notAfter(global_eid, &retval, x, tm);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_set_notBefore(X509 *x, const ASN1_TIME *tm) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_set_notBefore(global_eid, &retval, x, tm);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

ASN1_TIME* X509_get_notBefore(X509* x) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	ASN1_TIME* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_notBefore(global_eid, &retval, x);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

ASN1_TIME* X509_get_notAfter(X509* x) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	ASN1_TIME* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_get_notAfter(global_eid, &retval, x);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_set_pubkey(X509 *x, EVP_PKEY *pkey) {
	int retval;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_set_pubkey(global_eid, &retval, x, pkey);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_set_subject_name(X509 *x, X509_NAME *name) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_set_subject_name(global_eid, &retval, x, name);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_set_version(X509 *x, long version) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_set_version(global_eid, &retval, x, version);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_sign(global_eid, &retval, x, pkey, md);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

STACK_OF(X509) *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_STORE_CTX_set_chain(X509_STORE_CTX *ctx, STACK_OF(X509) *sk) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void *X509V3_EXT_d2i(X509_EXTENSION *ext) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_verify_cert(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

long ASN1_INTEGER_get(const ASN1_INTEGER *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_UTCTIME_print(BIO *bp, const ASN1_UTCTIME *tm) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int BIO_dump(BIO *bp, const char *s, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *BIO_get_callback_arg(const BIO *b) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO *BIO_new_fp(FILE *stream, int close_flag) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO *BIO_new_socket(int fd, int close_flag) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int BIO_printf(BIO *bio, const char *format, ...) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void BIO_set_callback(BIO *b, long (*cb)(struct bio_st *, int, const char *, int,
    long, long)) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void BIO_set_callback_arg(BIO *b, char *arg) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void ERR_print_errors(BIO *bp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void ERR_print_errors_fp(FILE *fp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int EVP_PKEY_bits(EVP_PKEY *pkey) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_PKEY_bits(global_eid, &retval, pkey);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void RAND_seed(const void *buf, int num) {
	return; // we use the sgx specific system to generate random value
}

const char *SSL_alert_desc_string_long(int value) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *SSL_alert_type_string_long(int value) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *SSL_CIPHER_get_version(const SSL_CIPHER *c) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_SESSION_print(BIO *bp, const SSL_SESSION *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_get_ext_count(X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_PKEY *X509_get_pubkey(X509 *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_INFO_free(X509_INFO *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void *sk_shift(_STACK *st) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_get_verify_depth(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int BN_dec2bn(BIGNUM **bn, const char *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BN_dec2bn(global_eid, &retval, bn, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

int RAND_status(void) {
	return 1;
}

ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void BIO_vfree(BIO *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

OCSP_CERTID *OCSP_CERTID_dup(OCSP_CERTID *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void EC_GROUP_free(EC_GROUP * group) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EC_GROUP_free(global_eid, group);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void ERR_remove_state(unsigned long pid) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_remove_state(global_eid, pid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int X509_STORE_load_locations(X509_STORE *ctx, const char *file, const char *path) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

char *BN_bn2dec(const BIGNUM *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIO *BIO_push(BIO *b, BIO *bio) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, unsigned char *x) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	BIGNUM* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ASN1_INTEGER_to_BN(global_eid, &retval, ai, bn);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

void ASN1_OBJECT_free(ASN1_OBJECT *a) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

ASN1_STRING *ASN1_STRING_new(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int ASN1_TIME_check(ASN1_TIME *t) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_BASIC_CONSTRAINTS_free(global_eid, a);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

BIO_METHOD *BIO_f_base64(void) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void BIO_free_all(BIO *bio) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void CONF_modules_unload(int all) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_CONF_modules_unload(global_eid, all);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int CRYPTO_num_locks(void) {
	return CRYPTO_NUM_LOCKS;
}

void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(*func)(const char *file, int line)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_CRYPTO_set_dynlock_create_callback(global_eid, (void*)func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void CRYPTO_set_dynlock_lock_callback(void (*func)(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_CRYPTO_set_dynlock_lock_callback(global_eid, (void*)func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void CRYPTO_set_dynlock_destroy_callback(void (*func)(struct CRYPTO_dynlock_value *l, const char *file, int line)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_CRYPTO_set_dynlock_destroy_callback(global_eid, (void*)func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void CRYPTO_set_id_callback(unsigned long (*func)(void)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_CRYPTO_set_id_callback(global_eid, (void*)func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void CRYPTO_set_locking_callback(void (*func)(int mode, int type, const char *file, int line)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_CRYPTO_set_locking_callback(global_eid, (void*)func);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, const unsigned char **in, long len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

DH *DH_new(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	DH* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_DH_new(global_eid, &retval);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);
	return retval;
}

int EC_GROUP_get_curve_name(const EC_GROUP * group) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ERR_free_strings(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_free_strings(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

void ERR_load_crypto_strings(void) {
   if (global_eid == 0) {
#ifdef SGX_MODE_SIM
		//SDK >v1.9, sim mode, do not initialize the library as this call is made by the SGX SDK
		//while it is loading and would fail to create the enclave.
		void (*ERR_load_crypto_strings_original)(void) = load_original_ssl_function("ERR_load_crypto_strings");
		ERR_load_crypto_strings_original();
		return;
#else
		initialize_library();
#endif
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_ERR_load_crypto_strings(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int EVP_PKEY_type(int type) {
	int retval = 0;
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_EVP_PKEY_type(global_eid, &retval, type);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
	return retval;
}

int EVP_read_pw_string(char *buf, int len, const char *prompt, int verify) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *OBJ_nid2ln(int n) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

const char *OCSP_crl_reason_str(long s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void OPENSSL_load_builtin_modules(void) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_OPENSSL_load_builtin_modules(global_eid);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

EC_GROUP *PEM_read_bio_ECPKParameters(BIO *bp, EC_GROUP **x, pem_password_cb *cb, void *u) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	EC_GROUP* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_PEM_read_bio_ECPKParameters(global_eid, &retval, bp, x, (void*)cb, u);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb, void *u) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int	RAND_pseudo_bytes(unsigned char *buf, int num) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

_STACK *sk_new(int (*c)(const void *, const void *)) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int (*sk_set_cmp_func(_STACK *sk, int (*c)(const void *, const void *)))(const void *, const void *) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey)) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx, DH *(*dh)(SSL *ssl, int is_export, int keylength)) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_set_tmp_dh_callback(global_eid, ctx, (void*)dh);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
	}
	log_exit_ecall(__func__);
}

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	int retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_CTX_use_certificate_file(global_eid, &retval, ctx, file, type);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

unsigned long SSLeay(void) {
	return SSLEAY_VERSION_NUMBER;
}

STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

static __thread EVP_PKEY my_evp_pkey;

EVP_PKEY *SSL_get_privatekey(SSL *s) {
   if (global_eid == 0) {
   	initialize_library();
   }

   log_enter_ecall(__func__);
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_SSL_get_privatekey(global_eid, &my_evp_pkey, s);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return NULL;
	}
	log_exit_ecall(__func__);

	return &my_evp_pkey;
}

int SSL_get_verify_mode(const SSL *s) {
	return (s->verify_mode);
}

int SSL_renegotiate(SSL *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

long SSL_SESSION_get_time(const SSL_SESSION *s) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx, unsigned int sid_ctx_len) {
	if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH) {
		return 0;
	}

	ssl->sid_ctx_length = sid_ctx_len;
	memcpy(ssl->sid_ctx, sid_ctx, sid_ctx_len);
	return 1;
}

void SSL_set_state(SSL *ssl, int state) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void SSL_set_verify_result(SSL *ssl, long arg) {
	ssl->verify_result = arg;
}

ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ex) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

ASN1_OBJECT *X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int err) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
	return 0;
}

void ERR_put_error(int lib, int func, int reason, const char *file, int line) {
	fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
}

ASN1_INTEGER* X509_BC_get_pathlen(BASIC_CONSTRAINTS* bc) {
	log_enter_ecall(__func__);
	ASN1_INTEGER* retval;
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	ret = ecall_X509_BC_get_pathlen(global_eid, &retval, bc);
	if (ret != SGX_SUCCESS) {
		print_error_message(ret, __func__);
		return 0;
	}
	log_exit_ecall(__func__);
	return retval;
}

BIGNUM *
get_rfc2409_prime_768(BIGNUM *bn)
{
	static const unsigned char RFC2409_PRIME_768[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
		0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
		0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
		0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
		0xA6, 0x3A, 0x36, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	};
	return BN_bin2bn(RFC2409_PRIME_768, sizeof(RFC2409_PRIME_768), bn);
}

/* "Second Oakley Default Group" from RFC2409, section 6.2.
 *
 * The prime is: 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
 *
 * RFC2409 specifies a generator of 2.
 * RFC2412 specifies a generator of 22.
 */

BIGNUM *
get_rfc2409_prime_1024(BIGNUM *bn)
{
	static const unsigned char RFC2409_PRIME_1024[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
		0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
		0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
		0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
		0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
		0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	};
	return BN_bin2bn(RFC2409_PRIME_1024, sizeof(RFC2409_PRIME_1024), bn);
}

/* "1536-bit MODP Group" from RFC3526, Section 2.
 *
 * The prime is: 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }
 *
 * RFC3526 specifies a generator of 2.
 * RFC2312 specifies a generator of 22.
 */

BIGNUM *
get_rfc3526_prime_1536(BIGNUM *bn)
{
	static const unsigned char RFC3526_PRIME_1536[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
		0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
		0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
		0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
		0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
		0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
		0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
		0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
		0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	};
	return BN_bin2bn(RFC3526_PRIME_1536, sizeof(RFC3526_PRIME_1536), bn);
}

/* "2048-bit MODP Group" from RFC3526, Section 3.
 *
 * The prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *
get_rfc3526_prime_2048(BIGNUM *bn)
{
	static const unsigned char RFC3526_PRIME_2048[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
		0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
		0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
		0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
		0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
		0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
		0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
		0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
		0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
		0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
		0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
		0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	};
	return BN_bin2bn(RFC3526_PRIME_2048, sizeof(RFC3526_PRIME_2048), bn);
}

/* "3072-bit MODP Group" from RFC3526, Section 4.
 *
 * The prime is: 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *
get_rfc3526_prime_3072(BIGNUM *bn)
{
	static const unsigned char RFC3526_PRIME_3072[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
		0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
		0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
		0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
		0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
		0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
		0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
		0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
		0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
		0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
		0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
		0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
		0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
		0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
		0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
		0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
		0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
		0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
		0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
		0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
		0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
		0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
		0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	};
	return BN_bin2bn(RFC3526_PRIME_3072, sizeof(RFC3526_PRIME_3072), bn);
}

/* "4096-bit MODP Group" from RFC3526, Section 5.
 *
 * The prime is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *
get_rfc3526_prime_4096(BIGNUM *bn)
{
	static const unsigned char RFC3526_PRIME_4096[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
		0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
		0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
		0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
		0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
		0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
		0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
		0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
		0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
		0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
		0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
		0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
		0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
		0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
		0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
		0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
		0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
		0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
		0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
		0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
		0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
		0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
		0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
		0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
		0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
		0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
		0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
		0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
		0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
		0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
		0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
		0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
		0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	};
	return BN_bin2bn(RFC3526_PRIME_4096, sizeof(RFC3526_PRIME_4096), bn);
}

/* "6144-bit MODP Group" from RFC3526, Section 6.
 *
 * The prime is: 2^6144 - 2^6080 - 1 + 2^64 * { [2^6014 pi] + 929484 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *
get_rfc3526_prime_6144(BIGNUM *bn)
{
	static const unsigned char RFC3526_PRIME_6144[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
		0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
		0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
		0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
		0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
		0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
		0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
		0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
		0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
		0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
		0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
		0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
		0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
		0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
		0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
		0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
		0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
		0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
		0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
		0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
		0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
		0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
		0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
		0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
		0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
		0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
		0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
		0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
		0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
		0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
		0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
		0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
		0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92,
		0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26, 0xC1, 0xD4, 0xDC, 0xB2,
		0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
		0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F,
		0x41, 0x30, 0x01, 0xAE, 0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31,
		0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18, 0xDA, 0x3E, 0xDB, 0xEB,
		0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
		0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33, 0x20, 0x51, 0x51,
		0x2B, 0xD7, 0xAF, 0x42, 0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
		0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC, 0xF0, 0x32, 0xEA, 0x15,
		0xD1, 0x72, 0x1D, 0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
		0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31,
		0x90, 0x0B, 0x1C, 0x9E, 0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3,
		0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE, 0x0F, 0x1D, 0x45, 0xB7,
		0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
		0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2,
		0x0F, 0x80, 0x37, 0xE0, 0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28,
		0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76, 0xF5, 0x50, 0xAA, 0x3D,
		0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
		0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7,
		0x6E, 0x3C, 0x04, 0x68, 0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE,
		0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6, 0xE6, 0x94, 0xF9, 0x1E,
		0x6D, 0xCC, 0x40, 0x24, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	};
	return BN_bin2bn(RFC3526_PRIME_6144, sizeof(RFC3526_PRIME_6144), bn);
}

/* "8192-bit MODP Group" from RFC3526, Section 7.
 *
 * The prime is: 2^8192 - 2^8128 - 1 + 2^64 * { [2^8062 pi] + 4743158 }
 *
 * RFC3526 specifies a generator of 2.
 */

BIGNUM *
get_rfc3526_prime_8192(BIGNUM *bn)
{
	static const unsigned char RFC3526_PRIME_8192[] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
		0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
		0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
		0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
		0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
		0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
		0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
		0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
		0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
		0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
		0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
		0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
		0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
		0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
		0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
		0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
		0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
		0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
		0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
		0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
		0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
		0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
		0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
		0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
		0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
		0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
		0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
		0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
		0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
		0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
		0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
		0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
		0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92,
		0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26, 0xC1, 0xD4, 0xDC, 0xB2,
		0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
		0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F,
		0x41, 0x30, 0x01, 0xAE, 0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31,
		0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18, 0xDA, 0x3E, 0xDB, 0xEB,
		0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
		0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33, 0x20, 0x51, 0x51,
		0x2B, 0xD7, 0xAF, 0x42, 0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
		0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC, 0xF0, 0x32, 0xEA, 0x15,
		0xD1, 0x72, 0x1D, 0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
		0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31,
		0x90, 0x0B, 0x1C, 0x9E, 0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3,
		0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE, 0x0F, 0x1D, 0x45, 0xB7,
		0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
		0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2,
		0x0F, 0x80, 0x37, 0xE0, 0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28,
		0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76, 0xF5, 0x50, 0xAA, 0x3D,
		0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
		0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7,
		0x6E, 0x3C, 0x04, 0x68, 0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE,
		0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6, 0xE6, 0x94, 0xF9, 0x1E,
		0x6D, 0xBE, 0x11, 0x59, 0x74, 0xA3, 0x92, 0x6F, 0x12, 0xFE, 0xE5, 0xE4,
		0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C, 0xD8, 0xBE, 0xC4, 0xD0,
		0x73, 0xB9, 0x31, 0xBA, 0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00,
		0x74, 0x1F, 0xA7, 0xBF, 0x8A, 0xFC, 0x47, 0xED, 0x25, 0x76, 0xF6, 0x93,
		0x6B, 0xA4, 0x24, 0x66, 0x3A, 0xAB, 0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68,
		0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78, 0x23, 0x8F, 0x16, 0xCB,
		0xE3, 0x9D, 0x65, 0x2D, 0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9,
		0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07, 0x13, 0xEB, 0x57, 0xA8,
		0x1A, 0x23, 0xF0, 0xC7, 0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B,
		0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83, 0x85, 0xDD, 0xFA, 0x9D, 0x4B, 0x7F,
		0xA2, 0xC0, 0x87, 0xE8, 0x79, 0x68, 0x33, 0x03, 0xED, 0x5B, 0xDD, 0x3A,
		0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6, 0x6D, 0x2A, 0x13, 0xF8,
		0x3F, 0x44, 0xF8, 0x2D, 0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36,
		0x45, 0x97, 0xE8, 0x99, 0xA0, 0x25, 0x5D, 0xC1, 0x64, 0xF3, 0x1C, 0xC5,
		0x08, 0x46, 0x85, 0x1D, 0xF9, 0xAB, 0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1,
		0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73, 0xFA, 0xF3, 0x6B, 0xC3,
		0x1E, 0xCF, 0xA2, 0x68, 0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92,
		0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7, 0x88, 0x9A, 0x00, 0x2E,
		0xD5, 0xEE, 0x38, 0x2B, 0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47,
		0x95, 0x58, 0xE4, 0x47, 0x56, 0x77, 0xE9, 0xAA, 0x9E, 0x30, 0x50, 0xE2,
		0x76, 0x56, 0x94, 0xDF, 0xC8, 0x1F, 0x56, 0xE8, 0x80, 0xB9, 0x6E, 0x71,
		0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	};
	return BN_bin2bn(RFC3526_PRIME_8192, sizeof(RFC3526_PRIME_8192), bn);
}
