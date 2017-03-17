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

#ifndef OCALLS_H_
#define OCALLS_H_

#include <stddef.h>

#include "openssl/ossl_typ.h"

void ocall_print_string(const char* str);
void ocall_println_string(const char* str);
void ocall_exit(int s);
void* ocall_malloc(size_t size);
void* ocall_realloc(void* ptr, size_t size);
void* ocall_calloc(size_t nmemb, size_t size);
void ocall_free(void* ptr);
void* ocall_fopen(const char *path, const char *mode);
size_t ocall_fwrite(const void *ptr, size_t size, size_t nmemb, void *stream);
size_t ocall_fwrite_copy(const void *ptr, size_t size, size_t nmemb, void *stream);
int ocall_fflush(void* stream);
int ocall_fclose(void* fp);
int ocall_close(int fd);
char* ocall_fgets(char *s, int size, void *stream);
void* ocall_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int ocall_open(const char *pathname, int flags, mode_t mode);
int ocall_open64(const char *pathname, int flags, mode_t mode);
int ocall_stat(const char *path, struct stat *buf, size_t size);
int ocall_ftruncate(int fd, off_t length);
int ocall_fstat(int fd, struct stat *buf, size_t size);
int ocall_lstat(const char *path, struct stat *buf, size_t size);
int ocall_read(int fd, void *buf, size_t count);
int ocall_write(int fd, const void *buf, size_t count);
long int ocall_time(long int *t);
unsigned long long ocall_get_cpuid_for_openssl(void);
int ocall__getpagesize();
void ocall__gettimeofday(char* tv, char* tz, int tvs, int tzs);
pid_t ocall_getpid();
uid_t ocall_getuid();
int ocall_unlink(const char* pathname);
int ocall_fsync(int fd);

void ocall_execute_ssl_ctx_info_callback(const SSL *ssl, int type, int val, void *cb);
int ocall_alpn_select_cb(SSL *s, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg, void *cb);
int ocall_next_protos_advertised_cb(SSL *s, const unsigned char **buf, unsigned int *len, void *arg, void* cb);
void ocall_crypto_ex_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp, void* cb);
void ocall_sk_pop_free_cb(void* data, void* cb);
int ocall_pem_password_cb(char *buf, int size, int rwflag, void *userdata, void* cb);
int ocall_new_session_callback(struct ssl_st *ssl, void *sess, void* cb);
void ocall_remove_session_cb(SSL_CTX *ctx, void* sess, void* cb);
void* ocall_get_session_cb(struct ssl_st *ssl, unsigned char *data, int len, int *copy, void* cb);
int ocall_ssl_ctx_callback_ctrl(SSL* ssl, int* ad, void* arg, void* cb);
void ocall_crypto_set_locking_cb(void* cb, int mode, int type, const char* file, int line);
unsigned long ocall_crypto_set_id_cb(void* cb);
int ocall_bio_create(BIO* b, void* cb);
int ocall_bio_destroy(BIO* b, void* cb);
int ocall_bio_read(BIO *b, char *buf, int len, void* cb);
int ocall_bio_write(BIO *b, char *buf, int len, void* cb);
long ocall_bio_ctrl(BIO *b, int cmd, long argl, void *arg, void* cb);
DH* ocall_SSL_CTX_set_tmp_dh_cb(SSL *ssl, int is_export, int keylength, void* cb);
int ocall_ssl_ctx_set_next_proto_select_cb(SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg, void* cb);
#endif
