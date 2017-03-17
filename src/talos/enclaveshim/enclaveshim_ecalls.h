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

#ifndef ENCLAVE_SHIM_H_
#define ENCLAVE_SHIM_H_

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

void print_error_message(sgx_status_t ret, const char* fn);
int initialize_enclave(void);
void destroy_enclave(void);

/********** SSL specific *********/

#include "openssl_types.h"

/********** to have the SSL CRYPTO_EX_DATA struct in untrusted memory *********/

struct ssl_ex_data {
	void** a; // array of size s
	int s;
};

/********** enclave interface *********/

int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a);
unsigned char * ASN1_STRING_data(ASN1_STRING *x);
int ASN1_STRING_length(const ASN1_STRING *x);
long	BIO_ctrl(BIO *bp,int cmd,long larg,void *parg); 
int	BIO_free(BIO *a); 
long	BIO_int_ctrl(BIO *bp,int cmd,long larg,int iarg); 
BIO *	BIO_new(BIO_METHOD *type); 
BIO *BIO_new_file(const char *filename, const char *mode); 
int	BIO_read(BIO *b, void *data, int len); 
BIO_METHOD *BIO_s_mem(void); 
int	BIO_write(BIO *b, const void *data, int len);

void BIO_set_flags(BIO *b, int flags);

int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file, int line); 
void CRYPTO_free(void *ptr); 
void *CRYPTO_malloc(int num, const char *file, int line); 

void	DH_free(DH *dh); 
void EC_KEY_free(EC_KEY *key); 
EC_KEY *EC_KEY_new_by_curve_name(int nid); 

ENGINE *ENGINE_by_id(const char *id); 
void ENGINE_cleanup(void); 
int ENGINE_free(ENGINE *e); 
EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data); 
int ENGINE_set_default(ENGINE *e, unsigned int flags); 

void ERR_remove_thread_state(const CRYPTO_THREADID *tid);
void ERR_clear_error(void ); 
void ERR_error_string_n(unsigned long e, char *buf, size_t len); 
unsigned long ERR_peek_error(void); 
unsigned long ERR_peek_error_line_data(const char **file,int *line, const char **data,int *flags); 
unsigned long ERR_peek_last_error(void); 

const EVP_CIPHER *EVP_aes_128_cbc(void); 
void EVP_cleanup(void); 
int	EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv); 
int	EVP_DigestFinal_ex(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s); 
int	EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl); 
int	EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *d, size_t cnt); 
int	EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv); 
EVP_MD_CTX *EVP_MD_CTX_create(void); 
void	EVP_MD_CTX_destroy(EVP_MD_CTX *ctx); 
void		EVP_PKEY_free(EVP_PKEY *pkey); 
const EVP_MD *EVP_sha1(void); 
const EVP_MD *EVP_sha256(void); 

int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a); 
int i2d_SSL_SESSION(SSL_SESSION *in,unsigned char **pp);

int MD5_Init(MD5_CTX *c);
int MD5_Update(MD5_CTX *c, const void *data, size_t len);
int MD5_Final(unsigned char *md, MD5_CTX *c);

OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer); 
int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long sec, long maxsec); 
OCSP_ONEREQ *OCSP_request_add0_id(OCSP_REQUEST *req, OCSP_CERTID *cid); 

int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status, int *reason, ASN1_GENERALIZEDTIME **revtime, ASN1_GENERALIZEDTIME **thisupd, ASN1_GENERALIZEDTIME **nextupd); 

void OPENSSL_config(const char *config_name);

RSA *	RSA_generate_key(int bits, unsigned long e,void (*callback)(int,int,void *),void *cb_arg);

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);

int sk_num(const _STACK *); 
void *sk_value(const _STACK *, int); 
char *SSL_CIPHER_description(const SSL_CIPHER *,char *buf,int size); 
const char *	SSL_CIPHER_get_name(const SSL_CIPHER *c); 

long	SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg); 
long	SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg);
long	SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));

void	SSL_CTX_free(SSL_CTX *);
X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);
STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *s);
void *SSL_CTX_get_ex_data(const SSL_CTX *ssl,int idx);
int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func); 

long SSL_CTX_get_timeout(const SSL_CTX *ctx); 
int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int,X509_STORE_CTX *); 
int SSL_CTX_get_verify_depth(const SSL_CTX *ctx); 
int SSL_CTX_get_verify_mode(const SSL_CTX *ctx); 
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath); 
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth); 
int	SSL_CTX_remove_session(SSL_CTX *,SSL_SESSION *c); 
void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl, unsigned char *data,int len,int *copy)); 
void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess)); 
void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess)); 

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list);
void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*cb)(const SSL *ssl,int type,int val));

void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s, int (*cb) (SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg), void *arg); 
int	SSL_CTX_set_session_id_context(SSL_CTX *ctx,const unsigned char *sid_ctx, unsigned int sid_ctx_len);
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode, int (*callback)(int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x); 
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey); 
int	SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type); 

void	SSL_free(SSL *ssl);
int	SSL_read(SSL *ssl,void *buf,int num);
int	SSL_write(SSL *ssl,const void *buf,int num);
int SSL_do_handshake(SSL *s); 
const char *SSLeay_version(int type); 
SSL_SESSION *SSL_get1_session(SSL *ssl); /* obtain a reference count */ 
X509 *SSL_get_certificate(const SSL *ssl); 
const SSL_CIPHER *SSL_get_current_cipher(const SSL *s); 
int	SSL_get_error(const SSL *s,int ret_code); 
void *SSL_get_ex_data(const SSL *ssl,int idx); 
int SSL_get_ex_data_X509_STORE_CTX_idx(void ); 
int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func); 
X509 *	SSL_get_peer_certificate(const SSL *s); 
BIO *	SSL_get_rbio(const SSL *s); 
const char *SSL_get_servername(const SSL *s, const int type); 
SSL_SESSION *SSL_get_session(const SSL *ssl); 
int SSL_get_shutdown(const SSL *ssl); 
long SSL_get_verify_result(const SSL *ssl); 
const char *SSL_get_version(const SSL *s); 
BIO *	SSL_get_wbio(const SSL *s); 
int SSL_library_init(void ); 
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file); 
void	SSL_load_error_strings(void ); 
SSL *	SSL_new(SSL_CTX *ctx); 
int SSL_select_next_proto(unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, const unsigned char *client, unsigned int client_len); 
void	SSL_SESSION_free(SSL_SESSION *ses); 
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len); 
void SSL_set_accept_state(SSL *s); 
void SSL_set_connect_state(SSL *s); 
int SSL_set_ex_data(SSL *ssl,int idx,void *data); 
int	SSL_set_fd(SSL *s, int fd); 
void SSL_set_quiet_shutdown(SSL *ssl,int mode); 
int	SSL_set_session(SSL *to, SSL_SESSION *session); 
void SSL_set_shutdown(SSL *ssl,int mode); 
SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx); 
void	SSL_set_verify(SSL *s, int mode, int (*callback)(int ok,X509_STORE_CTX *ctx)); 
void	SSL_set_verify_depth(SSL *s, int depth); 
int SSL_shutdown(SSL *s); 
int SSL_state(const SSL *ssl); 
const SSL_METHOD *SSLv23_method(void);	/* SSLv3 but can rollback to v2 */ 

int X509_check_issued(X509 *issuer, X509 *subject); 
int X509_digest(const X509 *data,const EVP_MD *type, unsigned char *md, unsigned int *len); 
void X509_email_free(STACK_OF(OPENSSL_STRING) *sk); 

void *X509_get_ex_data(X509 *r, int idx); 
int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func); 
void	*	X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx); 
X509_NAME *	X509_get_issuer_name(X509 *a); 
ASN1_INTEGER *	X509_get_serialNumber(X509 *x); 
X509_NAME *	X509_get_subject_name(X509 *a); 
int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret); 
X509_LOOKUP_METHOD *X509_LOOKUP_file(void); 
int X509_NAME_digest(const X509_NAME *data,const EVP_MD *type, unsigned char *md, unsigned int *len); 
ASN1_STRING *	X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne); 
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc); 
int		X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos); 
char *		X509_NAME_oneline(X509_NAME *a,char *buf,int size);
int X509_set_ex_data(X509 *r, int idx, void *arg); 
X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m); 
void X509_STORE_CTX_free(X509_STORE_CTX *ctx); 
int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x); 
X509 *	X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx); 
int	X509_STORE_CTX_get_error(X509_STORE_CTX *ctx); 
int	X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx); 
void *	X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx,int idx); 
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509, STACK_OF(X509) *chain); 
X509_STORE_CTX *X509_STORE_CTX_new(void); 
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags); 
const char *X509_verify_cert_error_string(long n);

OCSP_RESPONSE * d2i_OCSP_RESPONSE(OCSP_RESPONSE **a, const unsigned char **in, long len);
void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x); 
unsigned long ERR_get_error(void); 
int		OBJ_sn2nid(const char *s); 
int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags); 
const char *OCSP_cert_status_str(long s); 
const char *OCSP_response_status_str(long s); 
void OPENSSL_add_all_algorithms_noconf(void); 
int  RAND_bytes(unsigned char *buf,int num); 
int SSL_CTX_set_ex_data(SSL_CTX *ssl,int idx,void *data); 
long SSL_CTX_set_timeout(SSL_CTX *ctx,long t); 

SSL_SESSION * d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length); 
void GENERAL_NAMES_free(GENERAL_NAMES *a);
int	HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
int	i2d_OCSP_REQUEST(OCSP_REQUEST *a, unsigned char **out); 
int	i2d_OCSP_RESPONSE(OCSP_RESPONSE *a, unsigned char **out);
void OCSP_BASICRESP_free(OCSP_BASICRESP *a);
void OCSP_CERTID_free(OCSP_CERTID *a);
void OCSP_REQUEST_free(OCSP_REQUEST *a); 
OCSP_REQUEST * OCSP_REQUEST_new(void);
void OCSP_RESPONSE_free(OCSP_RESPONSE *a);
OCSP_BASICRESP * OCSP_response_get1_basic(OCSP_RESPONSE *resp);
OCSP_RESPONSE * OCSP_RESPONSE_new(void);
int OCSP_response_status(OCSP_RESPONSE *resp);
void SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx, int (*cb) (SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg), void *arg);
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
void X509_free(X509 *a);
STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(X509 *x);

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);
X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
int PEM_write_bio_X509(BIO *bp, X509 *x);


/* up to here it was for nginx. Now it is the ones missing in squid */

void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a);
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
void ASN1_STRING_free(ASN1_STRING *a);
ASN1_STRING* ASN1_STRING_type_new(int type);
int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm);

void BIO_clear_flags(BIO *b, int flags);
int BIO_puts(BIO *b, const char *in);
BIO_METHOD* BIO_s_file(void);

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_clear_bit(BIGNUM *a, int n);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_is_zero(BIGNUM* a);
void BN_free(BIGNUM *a);
int BN_is_bit_set(const BIGNUM *a, int n);
BIGNUM *BN_new(void);
int BN_num_bits(const BIGNUM *a);
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_set_word(BIGNUM *a, BN_ULONG w);
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);

int DH_check(const DH *dh, int *ret);
char *ERR_error_string(unsigned long e, char *ret);
void GENERAL_NAME_free(GENERAL_NAME *a);

const EVP_MD *EVP_get_digestbyname(const char *name);
int EVP_MD_type(const EVP_MD *md);
int EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key);
EVP_PKEY *EVP_PKEY_new(void);

int OBJ_create(const char *oid, const char *sn, const char *ln);
const char *OBJ_nid2sn(int n);
ASN1_OBJECT* X509_get_algorithm(X509* ptr); //PL: added for squid
int OBJ_obj2nid(const ASN1_OBJECT *a);
int OBJ_txt2nid(const char *s);

int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp, void *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *callback, void *u);
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
X509_CRL *PEM_read_bio_X509_CRL(BIO *bp, X509_CRL **x, pem_password_cb *cb, void *u);
DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u);
int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

void RSA_free(RSA *r);
int SSL_accept(SSL *s);
int SSL_connect(SSL *s);
int SSL_version(const SSL *s);
const SSL_METHOD *TLS_method(void);

_STACK *sk_dup(_STACK *sk);
int sk_find(_STACK *st, void *data);
void sk_free(_STACK *st);
_STACK *sk_new_null(void);
void sk_pop_free(_STACK *st, void (*func)(void *));
int sk_push(_STACK *st, void *data);

int SSL_CTX_check_private_key(const SSL_CTX *ctx);
void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *, void *), void *arg);
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
void SSL_CTX_set_next_proto_select_cb(SSL_CTX *ctx, int (*cb) (SSL *s, unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg), void *arg);
void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode);
void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx, RSA *(*cb)(SSL *ssl, int is_export, int keylength));
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);

STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk);
STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s);
STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s);
SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl);
int SSL_pending(const SSL *s);
long SSL_SESSION_set_timeout(SSL_SESSION *s, long t);

int SSL_set_alpn_protos(SSL *ssl, const unsigned char* protos, unsigned int protos_len);
void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);
int SSL_set_cipher_list(SSL *s, const char *str);
void SSL_set_info_callback(SSL *ssl, void (*cb)(const SSL *ssl, int type, int val));
const char *SSL_state_string(const SSL *s);
const char *SSL_state_string_long(const SSL *s);
int SSL_use_certificate(SSL *ssl, X509 *x);
int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);

const SSL_METHOD *SSLv23_client_method(void);
const SSL_METHOD *SSLv23_server_method(void);
const SSL_METHOD *TLSv1_1_client_method(void);
const SSL_METHOD *TLSv1_1_server_method(void);
const SSL_METHOD *TLSv1_2_client_method(void);
const SSL_METHOD *TLSv1_2_server_method(void);
const SSL_METHOD *TLSv1_client_method(void);
const SSL_METHOD *TLSv1_server_method(void);

int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
unsigned char *X509_alias_get0(X509 *x, int *len);
int X509_alias_set1(X509 *x, unsigned char *name, int len);
int X509_check_private_key(X509 *x, EVP_PKEY *k);
int X509_cmp(const X509 *a, const X509 *b);
int X509_cmp_current_time(const ASN1_TIME *ctm);
void X509_CRL_free(X509_CRL *a);
int X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data);
int X509_get_ext_by_NID(X509 *x, int nid, int lastpos);
X509_EXTENSION *X509_get_ext(X509 *x, int loc);
ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj);

int	X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type, unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
void X509_NAME_ENTRY_free(X509_NAME_ENTRY *a);
void X509_NAME_free(X509_NAME *a);
int X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf, int len);

X509 *X509_new(void);
int X509_pubkey_digest(const X509 *data, const EVP_MD *type, unsigned char *md, unsigned int *len);
ASN1_OBJECT* X509_get_cert_key_algor_algorithm(X509* x);
int X509_set_issuer_name(X509 *x, X509_NAME *name);
int X509_set_notAfter(X509 *x, const ASN1_TIME *tm);
int X509_set_notBefore(X509 *x, const ASN1_TIME *tm);
ASN1_TIME* X509_get_notBefore(X509* x);
ASN1_TIME* X509_get_notAfter(X509* x);
int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
int X509_set_subject_name(X509 *x, X509_NAME *name);
int X509_set_version(X509 *x, long version);
int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);

int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x);
STACK_OF(X509) *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_chain(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);

void *X509V3_EXT_d2i(X509_EXTENSION *ext);
const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext);
int X509_verify_cert(X509_STORE_CTX *ctx);

long ASN1_INTEGER_get(const ASN1_INTEGER *a);
int ASN1_UTCTIME_print(BIO *bp, const ASN1_UTCTIME *tm);
int BIO_dump(BIO *bp, const char *s, int len);
char *BIO_get_callback_arg(const BIO *b);
BIO *BIO_new_fp(FILE *stream, int close_flag);
BIO *BIO_new_socket(int fd, int close_flag);
int BIO_printf(BIO *bio, const char *format, ...);
void BIO_set_callback(BIO *b, long (*cb)(struct bio_st *, int, const char *, int,
    long, long));
void BIO_set_callback_arg(BIO *b, char *arg);
void ERR_print_errors(BIO *bp);
void ERR_print_errors_fp(FILE *fp);
int EVP_PKEY_bits(EVP_PKEY *pkey);
void RAND_seed(const void *buf, int num);
const char *SSL_alert_desc_string_long(int value);
const char *SSL_alert_type_string_long(int value);
int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits);
char *SSL_CIPHER_get_version(const SSL_CIPHER *c);
int SSL_SESSION_print(BIO *bp, const SSL_SESSION *x);
int X509_get_ext_count(X509 *x);
EVP_PKEY *X509_get_pubkey(X509 *x);
void X509_INFO_free(X509_INFO *x);
void *sk_shift(_STACK *st);
int SSL_get_verify_depth(const SSL *s);
int BN_dec2bn(BIGNUM **bn, const char *a);
int RAND_status(void);
ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);
void AUTHORITY_INFO_ACCESS_free(AUTHORITY_INFO_ACCESS *a);
void BIO_vfree(BIO *a);
OCSP_CERTID *OCSP_CERTID_dup(OCSP_CERTID *x);
EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
void EC_GROUP_free(EC_GROUP * group);
void ERR_remove_state(unsigned long pid);
int X509_STORE_load_locations(X509_STORE *ctx, const char *file, const char *path);
int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs);
char *BN_bn2dec(const BIGNUM *a);
BIO *BIO_push(BIO *b, BIO *bio);

int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, unsigned char *x);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);
void ASN1_OBJECT_free(ASN1_OBJECT *a);
ASN1_STRING *ASN1_STRING_new(void);
int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags);
int ASN1_TIME_check(ASN1_TIME *t);
void BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS *a);
BIO_METHOD *BIO_f_base64(void);
void BIO_free_all(BIO *bio);
void CONF_modules_unload(int all);
int CRYPTO_num_locks(void);
void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(*func)(const char *file, int line));
void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line));
void CRYPTO_set_dynlock_destroy_callback(void (*func)(struct CRYPTO_dynlock_value *l, const char *file, int line));
void CRYPTO_set_id_callback(unsigned long (*func)(void));
void CRYPTO_set_locking_callback(void (*func)(int mode, int type, const char *file, int line));
EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length);
ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, const unsigned char **in, long len);
DH *DH_new(void);
int EC_GROUP_get_curve_name(const EC_GROUP * group);
void ERR_free_strings(void);
void ERR_load_crypto_strings(void);
int EVP_PKEY_type(int type);
int EVP_read_pw_string(char *buf, int len, const char *prompt, int verify);
int i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp);
int OBJ_cmp(const ASN1_OBJECT *a, const ASN1_OBJECT *b);
const char *OBJ_nid2ln(int n);
const char *OCSP_crl_reason_str(long s);
int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len);
int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc);
OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs);
void OPENSSL_load_builtin_modules(void);
EC_GROUP *PEM_read_bio_ECPKParameters(BIO *bp, EC_GROUP **x, pem_password_cb *cb, void *u);
STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb, void *u);
int	RAND_pseudo_bytes(unsigned char *buf, int num);
_STACK *sk_new(int (*c)(const void *, const void *));
int (*sk_set_cmp_func(_STACK *sk, int (*c)(const void *, const void *)))(const void *, const void *);
void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey));
void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx, DH *(*dh)(SSL *ssl, int is_export, int keylength));
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
unsigned long SSLeay(void);
STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s);
EVP_PKEY *SSL_get_privatekey(SSL *s);
int SSL_get_verify_mode(const SSL *s);
int SSL_renegotiate(SSL *s);
long SSL_SESSION_get_time(const SSL_SESSION *s);
int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx, unsigned int sid_ctx_len);
void SSL_set_state(SSL *ssl, int state);
void SSL_set_verify_result(SSL *ssl, long arg);
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ex);
ASN1_OBJECT *X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne);
int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth);
void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int err);
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data);
int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag, int indent);
void ERR_put_error(int lib, int func, int reason, const char *file, int line);
ASN1_INTEGER* X509_BC_get_pathlen(BASIC_CONSTRAINTS* bc);

/* Primes from RFC 2409 */
BIGNUM *get_rfc2409_prime_768(BIGNUM *bn);
BIGNUM *get_rfc2409_prime_1024(BIGNUM *bn);

/* Primes from RFC 3526 */
BIGNUM *get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_3072(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_4096(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_8192(BIGNUM *bn);

#endif
