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
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>
#include <semaphore.h>

#include "enclaveshim_log.h"
#include "openssl/ssl.h"

#ifndef O_TMPFILE
/* a horrid kludge trying to make sure that this will fail on old kernels */
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

/******************** OCALLS ********************/
off_t ocall_lseek(int fd, off_t offset, int whence) {
	log_enter_ocall(__func__);
	off_t ret = lseek(fd, offset, whence);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_fsync(int fd){
        log_enter_ocall(__func__);
        int ret = fsync(fd);
        log_exit_ocall(__func__);
        return ret;
}

int ocall_unlink(const char* pathname){
	log_enter_ocall(__func__);
        int ret = unlink(pathname);
        log_exit_ocall(__func__);
        return ret;
}

int ocall_fcntl(int fd, int cmd, void* arg, size_t size) {
	log_enter_ocall(__func__);
	int ret = fcntl(fd, cmd, arg);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_fstat(int fd, struct stat *buf, size_t size) {
	log_enter_ocall(__func__);
	int ret = fstat(fd, buf);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_lstat(const char *pathname, struct stat *buf, size_t size) {
	log_enter_ocall(__func__);
	int ret = lstat(pathname, buf);
	log_exit_ocall(__func__);
	return ret;
}

void* ocall_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
	log_enter_ocall(__func__);
        void* ret = mmap(addr, length, prot, flags, fd, offset);
        log_exit_ocall(__func__);
        return NULL;

}

int ocall_stat(const char *pathname, struct stat *buf, size_t size) {
	log_enter_ocall(__func__);
	int ret = stat(pathname, buf);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_ftruncate(int fd, off_t length) {
	log_enter_ocall(__func__);
        int ret = ftruncate(fd, length);
        log_exit_ocall(__func__);
        return ret;
}

char *ocall_getcwd(char *buf, size_t size) {
	log_enter_ocall(__func__);
	char* ret = getcwd(buf, size);
	log_exit_ocall(__func__);
	return ret;
}

void ocall_print_string(const char* str) {
	printf("%s", str);
	fflush(NULL);
}

void ocall_println_string(const char* str) {
	printf("%s\n", str);
	fflush(NULL);
}

void ocall_exit(int s) {
	exit(s);
}

void* ocall_malloc(size_t size) {
	log_enter_ocall(__func__);
	void* ret = malloc(size);
	log_exit_ocall(__func__);
	return ret;
}

void* ocall_realloc(void* ptr, size_t size) {
	log_enter_ocall(__func__);
	void* ret = realloc(ptr, size);
	log_exit_ocall(__func__);
	return ret;
}

void* ocall_calloc(size_t nmemb, size_t size) {
	log_enter_ocall(__func__);
	void* ret = calloc(nmemb, size);
	log_exit_ocall(__func__);
	return ret;
}

void ocall_free(void* ptr) {
	log_enter_ocall(__func__);
	free(ptr);
	log_exit_ocall(__func__);
}

void* ocall_fopen(const char *path, const char *mode) {
	log_enter_ocall(__func__);
	FILE* f = fopen(path, mode);
	log_exit_ocall(__func__);
	return (void*)f;
}

size_t _ocall_fwrite(const void *ptr, size_t size, size_t nmemb, void *stream) {
	log_enter_ocall(__func__);
	size_t ret;
	if (!stream) {
		size_t i;
		for (i=0; i<size*nmemb; i++) {
			printf("%c", *((char*)ptr+i));
		}
		fflush(NULL);
		ret = size*nmemb;
	} else {
		ret = fwrite(ptr, size, nmemb, (FILE*)stream);
	}
	return ret;
	log_exit_ocall(__func__);
}

size_t ocall_fwrite(const void *ptr, size_t size, size_t nmemb, void *stream) {
	return _ocall_fwrite(ptr, size, nmemb, stream);
}

size_t ocall_fwrite_copy(const void *ptr, size_t size, size_t nmemb, void *stream) {
	return _ocall_fwrite(ptr, size, nmemb, stream);
}

int ocall_fflush(void* stream) {
	return fflush((FILE*)stream);
}

int ocall_close(int fd) {
        log_enter_ocall(__func__);
        int ret = close(fd);
        log_exit_ocall(__func__);
        return ret;
}

int ocall_fclose(void* fp) {
	log_enter_ocall(__func__);
	int ret = fclose((FILE*)fp);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_open(const char *filename, int flags, mode_t mode) {
	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		return open(filename, flags, mode);	
	} else {
		return open(filename, flags);
	}
}

int ocall_open64(const char *filename, int flags, mode_t mode) {
	/*
	if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
		return open64(filename, flags, mode);	
	} else {
		return open64(filename, flags);
	}
	*/
	return ocall_open(filename, flags, mode);
}

char *ocall_fgets(char *s, int size, void *stream) {
	log_enter_ocall(__func__);
	char* ret = fgets(s, size, (FILE*)stream);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_read(int fd, void *buf, size_t count) {
	log_enter_ocall(__func__);
	int ret = (int)read(fd, buf, count);
	//printf("%s %d bytes\n", __func__, ret);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_write(int fd, void *buf, size_t count) {
	log_enter_ocall(__func__);
	int ret = (int)write(fd, buf, count);
	//printf("%s %d bytes\n", __func__, ret);
	log_exit_ocall(__func__);
	return ret;
}

long int ocall_time(long int *t) {
	log_enter_ocall(__func__);
	long int ret = (long int)time((time_t*)t);
	log_exit_ocall(__func__);
	return ret;
}

unsigned long long ocall_get_cpuid_for_openssl(void) {
	unsigned long long OPENSSL_ia32_cpuid(void);
	unsigned long long vec;

	vec = OPENSSL_ia32_cpuid();
	return vec;
}

int ocall__getpagesize() {
	return getpagesize();
}


uid_t ocall_getuid(){
	log_enter_ocall(__func__);
	uid_t ret = getuid();
	log_exit_ocall(__func__);
        return ret;
}

pid_t ocall_getpid(){
	log_enter_ocall(__func__);
	pid_t ret = getpid();
	log_exit_ocall(__func__);
	return ret;
	
}

int ocall_gettimeofday(struct timeval* tv, struct timezone* tz) {
	int ret = gettimeofday(tv, tz);
	return ret;
}

void ocall_nanosleep(unsigned long sec, unsigned long nanosec) {
	struct timespec ts;
	ts.tv_sec = sec;
	ts.tv_nsec = nanosec;
	nanosleep(&ts, NULL);
}

/******************** CALLBACKS ********************/

void ocall_execute_ssl_ctx_info_callback(const SSL *ssl, int type, int val, void *cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	void (*callback)(const SSL *ssl,int type,int val) = (void (*)(const SSL *ssl,int type,int val))cb;
	callback(ssl, type, val);
	log_exit_ocall(__func__);
}

int ocall_alpn_select_cb(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg, void *cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) = (int (*)(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg))cb;
	int ret = callback(s, out, outlen, in, inlen, arg);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_next_protos_advertised_cb(SSL *s, unsigned char **buf, unsigned int *len, void *arg, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(SSL *s, const unsigned char **buf, unsigned int *len, void *arg) = (int (*)(SSL *s, const unsigned char **buf, unsigned int *len, void *arg))cb;
	int ret = callback(s, (const unsigned char**)buf, len, arg);
	log_exit_ocall(__func__);
	return ret;
}

void ocall_crypto_ex_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	CRYPTO_EX_free *callback = (CRYPTO_EX_free *)cb;
	callback(parent, ptr, ad, idx, argl, argp);
	log_exit_ocall(__func__);
}

void ocall_sk_pop_free_cb(void* data, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	void (*callback)(void*) = (void (*)(void*))cb;
	callback(data);
	log_exit_ocall(__func__);
}

int ocall_pem_password_cb(char *buf, int size, int rwflag, void *userdata, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(char *buf, int size, int rwflag, void *userdata) = (int (*)(char *buf, int size, int rwflag, void *userdata))cb;
	int ret = callback(buf, size, rwflag, userdata);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_new_session_callback(struct ssl_st *ssl, void *sess, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(struct ssl_st *ssl, SSL_SESSION *sess) = (int (*)(struct ssl_st *ssl, SSL_SESSION *sess))cb;
	int ret = callback(ssl, (SSL_SESSION*)sess);
	log_exit_ocall(__func__);
	return ret;
}

void ocall_remove_session_cb(SSL_CTX *ctx, void* sess, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	void (*callback)(SSL_CTX *ctx, SSL_SESSION *sess) = (void (*)(SSL_CTX *ctx, SSL_SESSION *sess))cb;
	callback(ctx, (SSL_SESSION*)sess);
	log_exit_ocall(__func__);
}

void* ocall_get_session_cb(struct ssl_st *ssl, unsigned char *data, int len, int *copy, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	SSL_SESSION *(*callback)(struct ssl_st *ssl, unsigned char *data, int len, int *copy) = (SSL_SESSION *(*)(struct ssl_st *ssl, unsigned char *data, int len, int *copy))cb;
	void* ret = callback(ssl, data, len, copy);
	log_exit_ocall(__func__);
	return ret;
}

int ocall_ssl_ctx_callback_ctrl(SSL* ssl, int* ad, void* arg, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(SSL* ssl, int* ad, void* arg) = (int (*)(SSL* ssl, int* ad, void* arg))cb;
	int ret = callback(ssl, ad, arg);
	log_exit_ocall(__func__);
	return ret;
}

void ocall_crypto_set_locking_cb(void* cb, int mode, int type, const char* file, int line) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	void (*callback)(int, int,const char *, int) = (void (*)(int, int,const char *, int))cb;
	callback(mode, type, file, line);
	log_exit_ocall(__func__);
}

unsigned long ocall_crypto_set_id_cb(void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	unsigned long (*callback)(void) = (unsigned long (*)(void))cb;
	unsigned long retval = callback();
	log_exit_ocall(__func__);
	return retval;
}

int ocall_bio_create(BIO* b, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(BIO *) = (int (*)(BIO *))cb;
	int retval = callback(b);
	log_exit_ocall(__func__);
	return retval;
}

int ocall_bio_destroy(BIO* b, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(BIO *) = (int (*)(BIO *))cb;
	int retval = callback(b);
	log_exit_ocall(__func__);
	return retval;
}

int ocall_bio_read(BIO *b, char *buf, int len, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(BIO *, char *, int) = (int (*)(BIO *, char *, int))cb;
	int retval = callback(b, buf, len);
	log_exit_ocall(__func__);
	return retval;
}

int ocall_bio_write(BIO *b, char *buf, int len, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(BIO *, char *, int) = (int (*)(BIO *, char *, int))cb;
	int retval = callback(b, buf, len);
	log_exit_ocall(__func__);
	return retval;
}

long ocall_bio_ctrl(BIO *b, int cmd, long argl, void *arg, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	long (*callback)(BIO *, int, long, void*) = (long (*)(BIO *, int, long, void*))cb;
	long retval = callback(b, cmd, argl, arg);
	log_exit_ocall(__func__);
	return retval;
}

DH* ocall_SSL_CTX_set_tmp_dh_cb(SSL *ssl, int is_export, int keylength, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	DH* (*callback)(SSL *, int, int) = (DH* (*)(SSL *, int, int))cb;
	DH* retval = callback(ssl, is_export, keylength);
	log_exit_ocall(__func__);
	return retval;
}

int ocall_ssl_ctx_set_next_proto_select_cb(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg, void* cb) {
	//ocall_println_string(__func__);
	log_enter_ocall(__func__);
	int (*callback)(SSL*, unsigned char **, unsigned char *, const unsigned char *, unsigned int, void *) =
		(int (*)(SSL*, unsigned char **, unsigned char *, const unsigned char *, unsigned int, void *))cb;
	int retval = callback(s, out, outlen, in, inlen, arg);
	log_exit_ocall(__func__);
	return retval;
}
