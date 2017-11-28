/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#ifndef _OPENSSL_TYPES_H_
#define _OPENSSL_TYPES_H_

#include <time.h>
#include "openssl/ossl_typ.h"

#define SSL_TXT_DTLS1		"DTLSv1"
#define SSL_TXT_SSLV2		"SSLv2"
#define SSL_TXT_SSLV3		"SSLv3"
#define SSL_TXT_TLSV1		"TLSv1"
#define SSL_TXT_TLSV1_1		"TLSv1.1"
#define SSL_TXT_TLSV1_2		"TLSv1.2"

#define TLS1_2_VERSION			0x0303
#define TLS1_2_VERSION_MAJOR		0x03
#define TLS1_2_VERSION_MINOR		0x03

#define TLS1_1_VERSION			0x0302
#define TLS1_1_VERSION_MAJOR		0x03
#define TLS1_1_VERSION_MINOR		0x02

#define TLS1_VERSION			0x0301
#define DTLS1_VERSION			0xFEFF

#define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
#define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(type *,unsigned char **)
#define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)

TYPEDEF_D2I2D_OF(void);

/* used to hold info on the particular ciphers used */
struct ssl_cipher_st
{
	int valid;
	const char *name;		/* text name */
	unsigned long id;		/* id, 4 bytes, first is version */

	/* changed in 0.9.9: these four used to be portions of a single value 'algorithms' */
	unsigned long algorithm_mkey;	/* key exchange algorithm */
	unsigned long algorithm_auth;	/* server authentication */
	unsigned long algorithm_enc;	/* symmetric encryption */
	unsigned long algorithm_mac;	/* symmetric authentication */
	unsigned long algorithm_ssl;	/* (major) protocol version */

	unsigned long algo_strength;	/* strength and export flags */
	unsigned long algorithm2;	/* Extra flags */
	int strength_bits;		/* Number of bits really used */
	int alg_bits;			/* Number of bits for algorithm */
};

typedef struct ssl_cipher_st SSL_CIPHER;

struct ssl_method_st
{
	int version;
	int (*ssl_new)(SSL *s);
	void (*ssl_clear)(SSL *s);
	void (*ssl_free)(SSL *s);
	int (*ssl_accept)(SSL *s);
	int (*ssl_connect)(SSL *s);
	int (*ssl_read)(SSL *s,void *buf,int len);
	int (*ssl_peek)(SSL *s,void *buf,int len);
	int (*ssl_write)(SSL *s,const void *buf,int len);
	int (*ssl_shutdown)(SSL *s);
	int (*ssl_renegotiate)(SSL *s);
	int (*ssl_renegotiate_check)(SSL *s);
	long (*ssl_get_message)(SSL *s, int st1, int stn, int mt, long
			max, int *ok);
	int (*ssl_read_bytes)(SSL *s, int type, unsigned char *buf, int len, 
			int peek);
	int (*ssl_write_bytes)(SSL *s, int type, const void *buf_, int len);
	int (*ssl_dispatch_alert)(SSL *s);
	long (*ssl_ctrl)(SSL *s,int cmd,long larg,void *parg);
	long (*ssl_ctx_ctrl)(SSL_CTX *ctx,int cmd,long larg,void *parg);
	const SSL_CIPHER *(*get_cipher_by_char)(const unsigned char *ptr);
	int (*put_cipher_by_char)(const SSL_CIPHER *cipher,unsigned char *ptr);
	int (*ssl_pending)(const SSL *s);
	int (*num_ciphers)(void);
	const SSL_CIPHER *(*get_cipher)(unsigned ncipher);
	const struct ssl_method_st *(*get_ssl_method)(int version);
	long (*get_timeout)(void);
	struct ssl3_enc_method *ssl3_enc; /* Extra SSLv3/TLS stuff */
	int (*ssl_version)(void);
	long (*ssl_callback_ctrl)(SSL *s, int cb_id, void (*fp)(void));
	long (*ssl_ctx_callback_ctrl)(SSL_CTX *s, int cb_id, void (*fp)(void));
};

typedef struct ssl_method_st SSL_METHOD;

typedef struct bio_st BIO;

typedef void bio_info_cb(struct bio_st *, int, const char *, int, long, long);

typedef struct bio_method_st {
	int type;
	const char *name;
	int (*bwrite)(BIO *, const char *, int);
	int (*bread)(BIO *, char *, int);
	int (*bputs)(BIO *, const char *);
	int (*bgets)(BIO *, char *, int);
	long (*ctrl)(BIO *, int, long, void *);
	int (*create)(BIO *);
	int (*destroy)(BIO *);
	long (*callback_ctrl)(BIO *, int, bio_info_cb *);
} BIO_METHOD;

#define STACK_OF(type) struct stack_st_##type

struct crypto_ex_data_st {
	STACK_OF(void) *sk;
};

typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

struct bio_st {
	BIO_METHOD *method;
	/* bio, mode, argp, argi, argl, ret */
	long (*callback)(struct bio_st *, int, const char *, int, long, long);
	char *cb_arg; /* first argument for the callback */

	int init;
	int shutdown;
	int flags;	/* extra storage */
	int retry_reason;
	int num;
	void *ptr;
	struct bio_st *next_bio;	/* used by filter BIOs */
	struct bio_st *prev_bio;	/* used by filter BIOs */
	int references;
	unsigned long num_read;
	unsigned long num_write;

	CRYPTO_EX_DATA ex_data;
};

typedef struct bignum_st BIGNUM;

#ifndef BN_ULONG
#define BN_ULONG	unsigned int
#endif

struct bignum_st {
	BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
	int top;	/* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;	/* Size of the d array. */
	int neg;	/* one if the number is negative */
	int flags;
};

typedef struct ec_method_st EC_METHOD;
typedef struct ec_group_st	EC_GROUP;
typedef struct ec_point_st EC_POINT;

struct ec_point_st {
	const EC_METHOD *meth;

	/* All members except 'meth' are handled by the method functions,
	 * even if they appear generic */

	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z; /* Jacobian projective coordinates:
	 * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */
} /* EC_POINT */;

typedef enum {
	/** the point is encoded as z||x, where the octet z specifies
	 *  which solution of the quadratic equation y is  */
	POINT_CONVERSION_COMPRESSED = 2,
	/** the point is encoded as z||x||y, where z is the octet 0x02  */
	POINT_CONVERSION_UNCOMPRESSED = 4,
	/** the point is encoded as z||x||y, where the octet z specifies
	 *  which solution of the quadratic equation y is  */
	POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

struct ec_method_st {
	/* Various method flags */
	int flags;
	/* used by EC_METHOD_get_field_type: */
	int field_type; /* a NID */

	/* used by EC_GROUP_new, EC_GROUP_free, EC_GROUP_clear_free, EC_GROUP_copy: */
	int (*group_init)(EC_GROUP *);
	void (*group_finish)(EC_GROUP *);
	void (*group_clear_finish)(EC_GROUP *);
	int (*group_copy)(EC_GROUP *, const EC_GROUP *);

	/* used by EC_GROUP_set_curve_GFp, EC_GROUP_get_curve_GFp, */
	/* EC_GROUP_set_curve_GF2m, and EC_GROUP_get_curve_GF2m: */
	int (*group_set_curve)(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int (*group_get_curve)(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);

	/* used by EC_GROUP_get_degree: */
	int (*group_get_degree)(const EC_GROUP *);

	/* used by EC_GROUP_check: */
	int (*group_check_discriminant)(const EC_GROUP *, BN_CTX *);

	/* used by EC_POINT_new, EC_POINT_free, EC_POINT_clear_free, EC_POINT_copy: */
	int (*point_init)(EC_POINT *);
	void (*point_finish)(EC_POINT *);
	void (*point_clear_finish)(EC_POINT *);
	int (*point_copy)(EC_POINT *, const EC_POINT *);

	/* used by EC_POINT_set_to_infinity,
	 * EC_POINT_set_Jprojective_coordinates_GFp,
	 * EC_POINT_get_Jprojective_coordinates_GFp,
	 * EC_POINT_set_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_get_affine_coordinates_GFp,     ..._GF2m,
	 * EC_POINT_set_compressed_coordinates_GFp, ..._GF2m:
	 */
	int (*point_set_to_infinity)(const EC_GROUP *, EC_POINT *);
	int (*point_set_Jprojective_coordinates_GFp)(const EC_GROUP *, EC_POINT *,
			const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
	int (*point_get_Jprojective_coordinates_GFp)(const EC_GROUP *, const EC_POINT *,
			BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
	int (*point_set_affine_coordinates)(const EC_GROUP *, EC_POINT *,
			const BIGNUM *x, const BIGNUM *y, BN_CTX *);
	int (*point_get_affine_coordinates)(const EC_GROUP *, const EC_POINT *,
			BIGNUM *x, BIGNUM *y, BN_CTX *);
	int (*point_set_compressed_coordinates)(const EC_GROUP *, EC_POINT *,
			const BIGNUM *x, int y_bit, BN_CTX *);

	/* used by EC_POINT_point2oct, EC_POINT_oct2point: */
	size_t (*point2oct)(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
			unsigned char *buf, size_t len, BN_CTX *);
	int (*oct2point)(const EC_GROUP *, EC_POINT *,
			const unsigned char *buf, size_t len, BN_CTX *);

	/* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
	int (*add)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
	int (*dbl)(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
	int (*invert)(const EC_GROUP *, EC_POINT *, BN_CTX *);

	/* used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp: */
	int (*is_at_infinity)(const EC_GROUP *, const EC_POINT *);
	int (*is_on_curve)(const EC_GROUP *, const EC_POINT *, BN_CTX *);
	int (*point_cmp)(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

	/* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
	int (*make_affine)(const EC_GROUP *, EC_POINT *, BN_CTX *);
	int (*points_make_affine)(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);

	/* used by EC_POINTs_mul, EC_POINT_mul, EC_POINT_precompute_mult, EC_POINT_have_precompute_mult
	 * (default implementations are used if the 'mul' pointer is 0): */
	int (*mul)(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
			size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *);
	int (*precompute_mult)(EC_GROUP *group, BN_CTX *);
	int (*have_precompute_mult)(const EC_GROUP *group);


	/* internal functions */

	/* 'field_mul', 'field_sqr', and 'field_div' can be used by 'add' and 'dbl' so that
	 * the same implementations of point operations can be used with different
	 * optimized implementations of expensive field operations: */
	int (*field_mul)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
	int (*field_sqr)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
	int (*field_div)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);

	int (*field_encode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. to Montgomery */
	int (*field_decode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *); /* e.g. from Montgomery */
	int (*field_set_to_one)(const EC_GROUP *, BIGNUM *r, BN_CTX *);
} /* EC_METHOD */;

typedef struct ec_extra_data_st {
	struct ec_extra_data_st *next;
	void *data;
	void *(*dup_func)(void *);
	void (*free_func)(void *);
	void (*clear_free_func)(void *);
} EC_EXTRA_DATA; /* used in EC_GROUP */

struct ec_group_st {
	const EC_METHOD *meth;

	EC_POINT *generator; /* optional */
	BIGNUM order, cofactor;

	int curve_name;/* optional NID for named curve */
	int asn1_flag; /* flag to control the asn1 encoding */
	point_conversion_form_t asn1_form;

	unsigned char *seed; /* optional seed for parameters (appears in ASN1) */
	size_t seed_len;

	EC_EXTRA_DATA *extra_data; /* linked list */

	/* The following members are handled by the method functions,
	 * even if they appear generic */

	BIGNUM field; /* Field specification.
	 * For curves over GF(p), this is the modulus;
	 * for curves over GF(2^m), this is the
	 * irreducible polynomial defining the field.
	 */

	int poly[6]; /* Field specification for curves over GF(2^m).
	 * The irreducible f(t) is then of the form:
	 *     t^poly[0] + t^poly[1] + ... + t^poly[k]
	 * where m = poly[0] > poly[1] > ... > poly[k] = 0.
	 * The array is terminated with poly[k+1]=-1.
	 * All elliptic curve irreducibles have at most 5
	 * non-zero terms.
	 */

	BIGNUM a, b; /* Curve coefficients.
	 * (Here the assumption is that BIGNUMs can be used
	 * or abused for all kinds of fields, not just GF(p).)
	 * For characteristic  > 3,  the curve is defined
	 * by a Weierstrass equation of the form
	 *     y^2 = x^3 + a*x + b.
	 * For characteristic  2,  the curve is defined by
	 * an equation of the form
	 *     y^2 + x*y = x^3 + a*x^2 + b.
	 */

	int a_is_minus3; /* enable optimized point arithmetics for special case */

	void *field_data1; /* method-specific (e.g., Montgomery structure) */
	void *field_data2; /* method-specific */
	int (*field_mod_func)(BIGNUM *, const BIGNUM *, const BIGNUM *,	BN_CTX *); /* method-specific */
} /* EC_GROUP */;

typedef struct ec_key_st EC_KEY;

struct ec_key_st {
	int version;

	EC_GROUP *group;

	EC_POINT *pub_key;
	BIGNUM	 *priv_key;

	unsigned int enc_flag;
	point_conversion_form_t conv_form;

	int 	references;
	int	flags;

	EC_EXTRA_DATA *method_data;
} /* EC_KEY */;

#define MD5_LONG unsigned int

#define MD5_CBLOCK	64
#define MD5_LBLOCK	(MD5_CBLOCK/4)
#define MD5_DIGEST_LENGTH 16

typedef struct MD5state_st
{
	MD5_LONG A,B,C,D;
	MD5_LONG Nl,Nh;
	MD5_LONG data[MD5_LBLOCK];
	unsigned int num;
} MD5_CTX;

typedef struct asn1_object_st {
	const char *sn, *ln;
	int nid;
	int length;
	const unsigned char *data;	/* data remains const after init */
	int flags;	/* Should we free this one */
} ASN1_OBJECT;

typedef struct X509_name_entry_st
{
	ASN1_OBJECT *object;
	ASN1_STRING *value;
	int set;
	int size; 	/* temp variable */
} X509_NAME_ENTRY;

#define SSL_MAX_MASTER_KEY_LENGTH		48
#define SSL_MAX_SSL_SESSION_ID_LENGTH		32
#define SSL_MAX_SID_CTX_LENGTH			32

struct ssl_session_st {
	int ssl_version;	/* what ssl version session info is
	 * being kept in here? */

	int master_key_length;
	unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
	/* session_id - valid? */
	unsigned int session_id_length;
	unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
	/* this is used to determine whether the session is being reused in
	 * the appropriate context. It is up to the application to set this,
	 * via SSL_new */
	unsigned int sid_ctx_length;
	unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];

	/* Used to indicate that session resumption is not allowed.
	 * Applications can also set this bit for a new session via
	 * not_resumable_session_cb to disable session caching and tickets. */
	int not_resumable;

	/* The cert is the certificate used to establish this connection */
	struct sess_cert_st /* SESS_CERT */ *sess_cert;

	/* This is the cert for the other end.
	 * On clients, it will be the same as sess_cert->peer_key->x509
	 * (the latter is not enough as sess_cert is not retained
	 * in the external representation of sessions, see ssl_asn1.c). */
	X509 *peer;
	/* when app_verify_callback accepts a session where the peer's certificate
	 * is not ok, we must remember the error for session reuse: */
	long verify_result; /* only for servers */

	long timeout;
	time_t time;
	int references;

	const SSL_CIPHER *cipher;
	unsigned long cipher_id;	/* when ASN.1 loaded, this
	 * needs to be used to load
	 * the 'cipher' structure */

	STACK_OF(SSL_CIPHER) *ciphers; /* shared ciphers? */

	CRYPTO_EX_DATA ex_data; /* application specific data */

	/* These are used to make removal of session-ids more
	 * efficient and to implement a maximum cache size. */
	struct ssl_session_st *prev, *next;
	char *tlsext_hostname;
	size_t tlsext_ecpointformatlist_length;
	uint8_t *tlsext_ecpointformatlist; /* peer's list */
	size_t tlsext_ellipticcurvelist_length;
	uint16_t *tlsext_ellipticcurvelist; /* peer's list */

	/* RFC4507 info */
	unsigned char *tlsext_tick;	/* Session ticket */
	size_t tlsext_ticklen;		/* Session ticket length */
	long tlsext_tick_lifetime_hint;	/* Session lifetime hint in seconds */
};

typedef struct ssl_session_st SSL_SESSION;

typedef struct stack_st {
	int num;
	char **data;
	int sorted;

	int num_alloc;
	int (*comp)(const void *, const void *);
} _STACK;  /* Use STACK_OF(...) instead */

typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

typedef int ASN1_BOOLEAN;
typedef struct X509_extension_st
{
	ASN1_OBJECT *object;
	ASN1_BOOLEAN critical;
	ASN1_OCTET_STRING *value;
} X509_EXTENSION;

typedef struct ASN1_VALUE_st ASN1_VALUE;

typedef struct asn1_type_st {
	int type;
	union {
		char *ptr;
		ASN1_BOOLEAN		boolean;
		ASN1_STRING *		asn1_string;
		ASN1_OBJECT *		object;
		ASN1_INTEGER *		integer;
		ASN1_ENUMERATED *	enumerated;
		ASN1_BIT_STRING *	bit_string;
		ASN1_OCTET_STRING *	octet_string;
		ASN1_PRINTABLESTRING *	printablestring;
		ASN1_T61STRING *	t61string;
		ASN1_IA5STRING *	ia5string;
		ASN1_GENERALSTRING *	generalstring;
		ASN1_BMPSTRING *	bmpstring;
		ASN1_UNIVERSALSTRING *	universalstring;
		ASN1_UTCTIME *		utctime;
		ASN1_GENERALIZEDTIME *	generalizedtime;
		ASN1_VISIBLESTRING *	visiblestring;
		ASN1_UTF8STRING *	utf8string;
		/* set and sequence are left complete and still
		 * contain the set or sequence bytes */
		ASN1_STRING *		set;
		ASN1_STRING *		sequence;
		ASN1_VALUE *		asn1_value;
	} value;
} ASN1_TYPE;

typedef const ASN1_ITEM ASN1_ITEM_EXP;

typedef struct otherName_st {
	ASN1_OBJECT *type_id;
	ASN1_TYPE *value;
} OTHERNAME;

typedef struct EDIPartyName_st {
	ASN1_STRING *nameAssigner;
	ASN1_STRING *partyName;
} EDIPARTYNAME;

typedef struct GENERAL_NAME_st {

#define GEN_OTHERNAME	0
#define GEN_EMAIL	1
#define GEN_DNS		2
#define GEN_X400	3
#define GEN_DIRNAME	4
#define GEN_EDIPARTY	5
#define GEN_URI		6
#define GEN_IPADD	7
#define GEN_RID		8

	int type;
	union {
		char *ptr;
		OTHERNAME *otherName; /* otherName */
		ASN1_IA5STRING *rfc822Name;
		ASN1_IA5STRING *dNSName;
		ASN1_TYPE *x400Address;
		X509_NAME *directoryName;
		EDIPARTYNAME *ediPartyName;
		ASN1_IA5STRING *uniformResourceIdentifier;
		ASN1_OCTET_STRING *iPAddress;
		ASN1_OBJECT *registeredID;

		/* Old names */
		ASN1_OCTET_STRING *ip; /* iPAddress */
		X509_NAME *dirn;		/* dirn */
		ASN1_IA5STRING *ia5;/* rfc822Name, dNSName, uniformResourceIdentifier */
		ASN1_OBJECT *rid; /* registeredID */
		ASN1_TYPE *other; /* x400Address */
	} d;
} GENERAL_NAME;

typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;

#define HMAC_MAX_MD_CBLOCK	128	/* largest known is SHA512 */

struct env_md_ctx_st {
	const EVP_MD *digest;
	ENGINE *engine; /* functional reference if 'digest' is ENGINE-provided */
	unsigned long flags;
	void *md_data;
	/* Public key context for sign/verify */
	EVP_PKEY_CTX *pctx;
	/* Update function: usually copied from EVP_MD */
	int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count);
} /* EVP_MD_CTX */;

typedef struct env_md_ctx_st EVP_MD_CTX;

typedef struct hmac_ctx_st {
	const EVP_MD *md;
	EVP_MD_CTX md_ctx;
	EVP_MD_CTX i_ctx;
	EVP_MD_CTX o_ctx;
	unsigned int key_length;
	unsigned char key[HMAC_MAX_MD_CBLOCK];
} HMAC_CTX;

typedef struct ocsp_req_info_st {
	ASN1_INTEGER *version;
	GENERAL_NAME *requestorName;
	STACK_OF(OCSP_ONEREQ) *requestList;
	STACK_OF(X509_EXTENSION) *requestExtensions;
} OCSP_REQINFO;

typedef struct ocsp_signature_st {
	X509_ALGOR *signatureAlgorithm;
	ASN1_BIT_STRING *signature;
	STACK_OF(X509) *certs;
} OCSP_SIGNATURE;

typedef struct ocsp_request_st {
	OCSP_REQINFO *tbsRequest;
	OCSP_SIGNATURE *optionalSignature; /* OPTIONAL */
} OCSP_REQUEST;

typedef struct ocsp_response_data_st {
	ASN1_INTEGER *version;
	OCSP_RESPID  *responderId;
	ASN1_GENERALIZEDTIME *producedAt;
	STACK_OF(OCSP_SINGLERESP) *responses;
	STACK_OF(X509_EXTENSION) *responseExtensions;
} OCSP_RESPDATA;

typedef struct ocsp_basic_response_st {
	OCSP_RESPDATA *tbsResponseData;
	X509_ALGOR *signatureAlgorithm;
	ASN1_BIT_STRING *signature;
	STACK_OF(X509) *certs;
} OCSP_BASICRESP;

typedef struct ocsp_cert_id_st {
	X509_ALGOR *hashAlgorithm;
	ASN1_OCTET_STRING *issuerNameHash;
	ASN1_OCTET_STRING *issuerKeyHash;
	ASN1_INTEGER *serialNumber;
} OCSP_CERTID;

typedef struct ocsp_one_request_st {
	OCSP_CERTID *reqCert;
	STACK_OF(X509_EXTENSION) *singleRequestExtensions;
} OCSP_ONEREQ;

#define SHA_LONG unsigned int
#define SHA_LBLOCK	16

typedef struct SHAstate_st
{
	SHA_LONG h0,h1,h2,h3,h4;
	SHA_LONG Nl,Nh;
	SHA_LONG data[SHA_LBLOCK];
	unsigned int num;
} SHA_CTX;

typedef struct x509_lookup_st X509_LOOKUP;

typedef struct x509_object_st
{
	/* one of the above types */
	int type;
	union	{
		char *ptr;
		X509 *x509;
		X509_CRL *crl;
		EVP_PKEY *pkey;
	} data;
} X509_OBJECT;

/* This is a static that defines the function interface */
typedef struct x509_lookup_method_st
{
	const char *name;
	int (*new_item)(X509_LOOKUP *ctx);
	void (*free)(X509_LOOKUP *ctx);
	int (*init)(X509_LOOKUP *ctx);
	int (*shutdown)(X509_LOOKUP *ctx);
	int (*ctrl)(X509_LOOKUP *ctx,int cmd,const char *argc,long argl,
			char **ret);
	int (*get_by_subject)(X509_LOOKUP *ctx,int type,X509_NAME *name,
			X509_OBJECT *ret);
	int (*get_by_issuer_serial)(X509_LOOKUP *ctx,int type,X509_NAME *name,
			ASN1_INTEGER *serial,X509_OBJECT *ret);
	int (*get_by_fingerprint)(X509_LOOKUP *ctx,int type,
			unsigned char *bytes,int len,
			X509_OBJECT *ret);
	int (*get_by_alias)(X509_LOOKUP *ctx,int type,char *str,int len,
			X509_OBJECT *ret);
} X509_LOOKUP_METHOD;

struct x509_lookup_st
{
	int init;			/* have we been started */
	int skip;			/* don't use us. */
	X509_LOOKUP_METHOD *method;	/* the functions */
	char *method_data;		/* method data */

	X509_STORE *store_ctx;	/* who owns us */
} /* X509_LOOKUP */;

typedef struct {
	char *section;
	char *name;
	char *value;
} CONF_VALUE;

struct stack_st_CONF_VALUE
{
	_STACK stack;
};

/* Forward reference */
struct v3_ext_method;
struct v3_ext_ctx;

/* Useful typedefs */

typedef void * (*X509V3_EXT_NEW)(void);
typedef void (*X509V3_EXT_FREE)(void *);
typedef void * (*X509V3_EXT_D2I)(void *, const unsigned char ** , long);
typedef int (*X509V3_EXT_I2D)(void *, unsigned char **);
typedef STACK_OF(CONF_VALUE) *
  (*X509V3_EXT_I2V)(const struct v3_ext_method *method, void *ext,
		    STACK_OF(CONF_VALUE) *extlist);
typedef void * (*X509V3_EXT_V2I)(const struct v3_ext_method *method,
				 struct v3_ext_ctx *ctx,
				 STACK_OF(CONF_VALUE) *values);
typedef char * (*X509V3_EXT_I2S)(const struct v3_ext_method *method, void *ext);
typedef void * (*X509V3_EXT_S2I)(const struct v3_ext_method *method,
				 struct v3_ext_ctx *ctx, const char *str);
typedef int (*X509V3_EXT_I2R)(const struct v3_ext_method *method, void *ext,
			      BIO *out, int indent);
typedef void * (*X509V3_EXT_R2I)(const struct v3_ext_method *method,
				 struct v3_ext_ctx *ctx, const char *str);

/* V3 extension structure */

struct v3_ext_method {
int ext_nid;
int ext_flags;
/* If this is set the following four fields are ignored */
ASN1_ITEM_EXP *it;
/* Old style ASN1 calls */
X509V3_EXT_NEW ext_new;
X509V3_EXT_FREE ext_free;
X509V3_EXT_D2I d2i;
X509V3_EXT_I2D i2d;

/* The following pair is used for string extensions */
X509V3_EXT_I2S i2s;
X509V3_EXT_S2I s2i;

/* The following pair is used for multi-valued extensions */
X509V3_EXT_I2V i2v;
X509V3_EXT_V2I v2i;

/* The following are used for raw extensions */
X509V3_EXT_I2R i2r;
X509V3_EXT_R2I r2i;

void *usr_data;	/* Any extension specific data */
};

typedef struct X509V3_CONF_METHOD_st {
char * (*get_string)(void *db, char *section, char *value);
STACK_OF(CONF_VALUE) * (*get_section)(void *db, char *section);
void (*free_string)(void *db, char * string);
void (*free_section)(void *db, STACK_OF(CONF_VALUE) *section);
} X509V3_CONF_METHOD;

typedef struct v3_ext_method X509V3_EXT_METHOD;

typedef char *OPENSSL_STRING;

struct stack_st_OPENSSL_STRING
{
	_STACK stack;
};

#define EVP_MAX_IV_LENGTH		16

typedef struct evp_cipher_info_st {
	const EVP_CIPHER *cipher;
	unsigned char iv[EVP_MAX_IV_LENGTH];
} EVP_CIPHER_INFO;

typedef struct private_key_st
	{
	int version;
	/* The PKCS#8 data types */
	X509_ALGOR *enc_algor;
	ASN1_OCTET_STRING *enc_pkey;	/* encrypted pub key */

	/* When decrypted, the following will not be NULL */
	EVP_PKEY *dec_pkey;

	/* used to encrypt and decrypt */
	int key_length;
	char *key_data;
	int key_free;	/* true if we should auto free key_data */

	/* expanded version of 'enc_algor' */
	EVP_CIPHER_INFO cipher;

	int references;
	} X509_PKEY;

#ifndef OPENSSL_NO_EVP
typedef struct X509_info_st
	{
	X509 *x509;
	X509_CRL *crl;
	X509_PKEY *x_pkey;

	EVP_CIPHER_INFO enc_cipher;
	int enc_len;
	char *enc_data;

	int references;
	} X509_INFO;

	struct stack_st_X509_INFO
	{
		_STACK stack;
	};
#endif

struct stack_st_ACCESS_DESCRIPTION
{
	_STACK stack;
};
typedef	struct stack_st_ACCESS_DESCRIPTION AUTHORITY_INFO_ACCESS;

typedef struct BASIC_CONSTRAINTS_st {
	int ca;
	ASN1_INTEGER *pathlen;
} BASIC_CONSTRAINTS;

struct CRYPTO_dynlock_value;

#define OPENSSL_VERSION_NUMBER	0x20000000L
#define SSLEAY_VERSION_NUMBER	OPENSSL_VERSION_NUMBER

#define CRYPTO_NUM_LOCKS		41

typedef struct ssl_aead_ctx_st SSL_AEAD_CTX;

typedef struct X509_VERIFY_PARAM_st
{
	char *name;
	time_t check_time;	/* Time to use */
	unsigned long inh_flags; /* Inheritance flags */
	unsigned long flags;	/* Various verify flags */
	int purpose;		/* purpose to check untrusted certificates */
	int trust;		/* trust setting to check */
	int depth;		/* Verify depth */
	STACK_OF(ASN1_OBJECT) *policies;	/* Permissible policies */
} X509_VERIFY_PARAM;

typedef int (*GEN_SESSION_CB)(const SSL *ssl, unsigned char *id,
    unsigned int *id_len);

typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;

typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;

typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data,
    int len, void *arg);
typedef int (*tls_session_secret_cb_fn)(SSL *s, void *secret, int *secret_len,
    STACK_OF(SSL_CIPHER) *peer_ciphers, SSL_CIPHER **cipher, void *arg);

/* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*/
typedef struct srtp_protection_profile_st {
	const char *name;
	unsigned long id;
} SRTP_PROTECTION_PROFILE;

/* Type needs to be a bit field
 * Sub-type needs to be for variations on the method, as in, can it do
 * arbitrary encryption.... */
struct evp_pkey_st {
	int type;
	int save_type;
	int references;
	const EVP_PKEY_ASN1_METHOD *ameth;
	ENGINE *engine;
	union	{
		char *ptr;
#ifndef OPENSSL_NO_RSA
		struct rsa_st *rsa;	/* RSA */
#endif
#ifndef OPENSSL_NO_DSA
		struct dsa_st *dsa;	/* DSA */
#endif
#ifndef OPENSSL_NO_DH
		struct dh_st *dh;	/* DH */
#endif
#ifndef OPENSSL_NO_EC
		struct ec_key_st *ec;	/* ECC */
#endif
#ifndef OPENSSL_NO_GOST
		struct gost_key_st *gost; /* GOST */
#endif
	} pkey;
	int save_parameters;
	STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
} /* EVP_PKEY */;

#define SSL3_SEQUENCE_SIZE			8
#define EVP_MAX_MD_SIZE			64	/* longest known is SHA512 */
#define SSL3_RANDOM_SIZE			32
#define SSL3_CT_NUMBER			11

typedef struct ssl3_record_st {
/*r */	int type;               /* type of record */
/*rw*/	unsigned int length;    /* How many bytes available */
/*r */	unsigned int off;       /* read/write offset into 'buf' */
/*rw*/	unsigned char *data;    /* pointer to the record data */
/*rw*/	unsigned char *input;   /* where the decode bytes are */
/*r */  unsigned long epoch;    /* epoch number, needed by DTLS1 */
/*r */  unsigned char seq_num[8]; /* sequence number, needed by DTLS1 */
} SSL3_RECORD;

typedef struct ssl3_buffer_st {
	unsigned char *buf;	/* at least SSL3_RT_MAX_PACKET_SIZE bytes,
	                         * see ssl3_setup_buffers() */
	size_t len;		/* buffer size */
	int offset;		/* where to 'copy from' */
	int left;		/* how many bytes left */
} SSL3_BUFFER;

struct evp_aead_st;
typedef struct evp_aead_st EVP_AEAD;

typedef struct ssl3_state_st {
	long flags;
	int delay_buf_pop_ret;

	unsigned char read_sequence[SSL3_SEQUENCE_SIZE];
	int read_mac_secret_size;
	unsigned char read_mac_secret[EVP_MAX_MD_SIZE];
	unsigned char write_sequence[SSL3_SEQUENCE_SIZE];
	int write_mac_secret_size;
	unsigned char write_mac_secret[EVP_MAX_MD_SIZE];

	unsigned char server_random[SSL3_RANDOM_SIZE];
	unsigned char client_random[SSL3_RANDOM_SIZE];

	/* flags for countermeasure against known-IV weakness */
	int need_empty_fragments;
	int empty_fragment_done;

	SSL3_BUFFER rbuf;	/* read IO goes into here */
	SSL3_BUFFER wbuf;	/* write IO goes into here */

	SSL3_RECORD rrec;	/* each decoded record goes in here */
	SSL3_RECORD wrec;	/* goes out from here */

	/* storage for Alert/Handshake protocol data received but not
	 * yet processed by ssl3_read_bytes: */
	unsigned char alert_fragment[2];
	unsigned int alert_fragment_len;
	unsigned char handshake_fragment[4];
	unsigned int handshake_fragment_len;

	/* partial write - check the numbers match */
	unsigned int wnum;	/* number of bytes sent so far */
	int wpend_tot;		/* number bytes written */
	int wpend_type;
	int wpend_ret;		/* number of bytes submitted */
	const unsigned char *wpend_buf;

	/* used during startup, digest all incoming/outgoing packets */
	BIO *handshake_buffer;
	/* When set of handshake digests is determined, buffer is hashed
	 * and freed and MD_CTX-es for all required digests are stored in
	 * this array */
	EVP_MD_CTX **handshake_dgst;
	/* this is set whenerver we see a change_cipher_spec message
	 * come in when we are not looking for one */
	int change_cipher_spec;

	int warn_alert;
	int fatal_alert;
	/* we allow one fatal and one warning alert to be outstanding,
	 * send close alert via the warning alert */
	int alert_dispatch;
	unsigned char send_alert[2];

	/* This flag is set when we should renegotiate ASAP, basically when
	 * there is no more data in the read or write buffers */
	int renegotiate;
	int total_renegotiations;
	int num_renegotiations;

	int in_read_app_data;

	struct	{
		/* actually only needs to be 16+20 */
		unsigned char cert_verify_md[EVP_MAX_MD_SIZE*2];

		/* actually only need to be 16+20 for SSLv3 and 12 for TLS */
		unsigned char finish_md[EVP_MAX_MD_SIZE*2];
		int finish_md_len;
		unsigned char peer_finish_md[EVP_MAX_MD_SIZE*2];
		int peer_finish_md_len;

		unsigned long message_size;
		int message_type;

		/* used to hold the new cipher we are going to use */
		const SSL_CIPHER *new_cipher;
		DH *dh;

		EC_KEY *ecdh; /* holds short lived ECDH key */

		/* used when SSL_ST_FLUSH_DATA is entered */
		int next_state;

		int reuse_message;

		/* used for certificate requests */
		int cert_req;
		int ctype_num;
		char ctype[SSL3_CT_NUMBER];
		STACK_OF(X509_NAME) *ca_names;

		int key_block_length;
		unsigned char *key_block;

		const EVP_CIPHER *new_sym_enc;
		const EVP_AEAD *new_aead;
		const EVP_MD *new_hash;
		int new_mac_pkey_type;
		int new_mac_secret_size;
		int cert_request;
	} tmp;

	/* Connection binding to prevent renegotiation attacks */
	unsigned char previous_client_finished[EVP_MAX_MD_SIZE];
	unsigned char previous_client_finished_len;
	unsigned char previous_server_finished[EVP_MAX_MD_SIZE];
	unsigned char previous_server_finished_len;
	int send_connection_binding; /* TODOEKR */

	/* Set if we saw the Next Protocol Negotiation extension from our peer.
	 */
	int next_proto_neg_seen;

	/*
	 * ALPN information
	 * (we are in the process of transitioning from NPN to ALPN).
	 */

	/*
	 * In a server these point to the selected ALPN protocol after the
	 * ClientHello has been processed. In a client these contain the
	 * protocol that the server selected once the ServerHello has been
	 * processed.
	 */
	unsigned char *alpn_selected;
	unsigned int alpn_selected_len;
} SSL3_STATE;

struct ssl_st {
	/* protocol version
	 * (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION, DTLS1_VERSION)
	 */
	int version;
	int type; /* SSL_ST_CONNECT or SSL_ST_ACCEPT */

	const SSL_METHOD *method; /* SSLv3 */

	/* There are 2 BIO's even though they are normally both the
	 * same.  This is so data can be read and written to different
	 * handlers */

#ifndef OPENSSL_NO_BIO
	BIO *rbio; /* used by SSL_read */
	BIO *wbio; /* used by SSL_write */
	BIO *bbio; /* used during session-id reuse to concatenate
		    * messages */
#else
	char *rbio; /* used by SSL_read */
	char *wbio; /* used by SSL_write */
	char *bbio;
#endif
	/* This holds a variable that indicates what we were doing
	 * when a 0 or -1 is returned.  This is needed for
	 * non-blocking IO so we know what request needs re-doing when
	 * in SSL_accept or SSL_connect */
	int rwstate;

	/* true when we are actually in SSL_accept() or SSL_connect() */
	int in_handshake;
	int (*handshake_func)(SSL *);

	/* Imagine that here's a boolean member "init" that is
	 * switched as soon as SSL_set_{accept/connect}_state
	 * is called for the first time, so that "state" and
	 * "handshake_func" are properly initialized.  But as
	 * handshake_func is == 0 until then, we use this
	 * test instead of an "init" member.
	 */

	int server;	/* are we the server side? - mostly used by SSL_clear*/

	int new_session;/* Generate a new session or reuse an old one.
			 * NB: For servers, the 'new' session may actually be a previously
			 * cached session or even the previous session unless
			 * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set */
	int quiet_shutdown;/* don't send shutdown packets */
	int shutdown;	/* we have shut things down, 0x01 sent, 0x02
			 * for received */
	int state;	/* where we are */
	int rstate;	/* where we are when reading */

	BUF_MEM *init_buf;	/* buffer used during init */
	void *init_msg;		/* pointer to handshake message body, set by ssl3_get_message() */
	int init_num;		/* amount read/written */
	int init_off;		/* amount read/written */

	/* used internally to point at a raw packet */
	unsigned char *packet;
	unsigned int packet_length;

	struct ssl3_state_st *s3; /* SSLv3 variables */
	struct dtls1_state_st *d1; /* DTLSv1 variables */

	int read_ahead;		/* Read as many input bytes as possible
				 * (for non-blocking reads) */

	/* callback that allows applications to peek at protocol messages */
	void (*msg_callback)(int write_p, int version, int content_type,
	    const void *buf, size_t len, SSL *ssl, void *arg);
	void *msg_callback_arg;

	int hit;		/* reusing a previous session */

	X509_VERIFY_PARAM *param;

	/* crypto */
	STACK_OF(SSL_CIPHER) *cipher_list;
	STACK_OF(SSL_CIPHER) *cipher_list_by_id;

	/* These are the ones being used, the ones in SSL_SESSION are
	 * the ones to be 'copied' into these ones */
	int mac_flags;

	SSL_AEAD_CTX *aead_read_ctx;	/* AEAD context. If non-NULL, then
					   enc_read_ctx and read_hash are
					   ignored. */

	EVP_CIPHER_CTX *enc_read_ctx;		/* cryptographic state */
	EVP_MD_CTX *read_hash;			/* used for mac generation */

	SSL_AEAD_CTX *aead_write_ctx;	/* AEAD context. If non-NULL, then
					   enc_write_ctx and write_hash are
					   ignored. */

	EVP_CIPHER_CTX *enc_write_ctx;		/* cryptographic state */
	EVP_MD_CTX *write_hash;			/* used for mac generation */

	/* session info */

	/* client cert? */
	/* This is used to hold the server certificate used */
	struct cert_st /* CERT */ *cert;

	/* the session_id_context is used to ensure sessions are only reused
	 * in the appropriate context */
	unsigned int sid_ctx_length;
	unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];

	/* This can also be in the session once a session is established */
	SSL_SESSION *session;

	/* Default generate session ID callback. */
	GEN_SESSION_CB generate_session_id;

	/* Used in SSL2 and SSL3 */
	int verify_mode;	/* 0 don't care about verify failure.
				 * 1 fail if verify fails */
	int (*verify_callback)(int ok,X509_STORE_CTX *ctx); /* fail if callback returns 0 */

	void (*info_callback)(const SSL *ssl,int type,int val); /* optional informational callback */

	int error;		/* error bytes to be written */
	int error_code;		/* actual code */



	SSL_CTX *ctx;
	/* set this flag to 1 and a sleep(1) is put into all SSL_read()
	 * and SSL_write() calls, good for nbio debuging :-) */
	int debug;


	/* extra application data */
	long verify_result;
	CRYPTO_EX_DATA ex_data;

	/* for server side, keep the list of CA_dn we can use */
	STACK_OF(X509_NAME) *client_CA;

	int references;
	unsigned long options; /* protocol behaviour */
	unsigned long mode; /* API behaviour */
	long max_cert_list;
	int first_packet;
	int client_version;	/* what was passed, used for
				 * SSLv3/TLS rollback check */
	unsigned int max_send_fragment;
	/* TLS extension debug callback */
	void (*tlsext_debug_cb)(SSL *s, int client_server, int type,
	    unsigned char *data, int len, void *arg);
	void *tlsext_debug_arg;
	char *tlsext_hostname;
	int servername_done;	/* no further mod of servername
				   0 : call the servername extension callback.
				   1 : prepare 2, allow last ack just after in server callback.
				   2 : don't call servername callback, no ack in server hello
				   */
	/* certificate status request info */
	/* Status type or -1 if no status type */
	int tlsext_status_type;
	/* Expect OCSP CertificateStatus message */
	int tlsext_status_expected;
	/* OCSP status request only */
	STACK_OF(OCSP_RESPID) *tlsext_ocsp_ids;
	X509_EXTENSIONS *tlsext_ocsp_exts;
	/* OCSP response received or to be sent */
	unsigned char *tlsext_ocsp_resp;
	int tlsext_ocsp_resplen;

	/* RFC4507 session ticket expected to be received or sent */
	int tlsext_ticket_expected;
	size_t tlsext_ecpointformatlist_length;
	uint8_t *tlsext_ecpointformatlist; /* our list */
	size_t tlsext_ellipticcurvelist_length;
	uint16_t *tlsext_ellipticcurvelist; /* our list */

	/* TLS Session Ticket extension override */
	TLS_SESSION_TICKET_EXT *tlsext_session_ticket;

	/* TLS Session Ticket extension callback */
	tls_session_ticket_ext_cb_fn tls_session_ticket_ext_cb;
	void *tls_session_ticket_ext_cb_arg;

	/* TLS pre-shared secret session resumption */
	tls_session_secret_cb_fn tls_session_secret_cb;
	void *tls_session_secret_cb_arg;

	SSL_CTX * initial_ctx; /* initial ctx, used to store sessions */

	/* Next protocol negotiation. For the client, this is the protocol that
	 * we sent in NextProtocol and is set when handling ServerHello
	 * extensions.
	 *
	 * For a server, this is the client's selected_protocol from
	 * NextProtocol and is set when handling the NextProtocol message,
	 * before the Finished message. */
	unsigned char *next_proto_negotiated;
	unsigned char next_proto_negotiated_len;

#define session_ctx initial_ctx

	STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;	/* What we'll do */
	SRTP_PROTECTION_PROFILE *srtp_profile;			/* What's been chosen */

	unsigned int tlsext_heartbeat;	/* Is use of the Heartbeat extension negotiated?
					   0: disabled
					   1: enabled
					   2: enabled, but not allowed to send Requests
					   */
	unsigned int tlsext_hb_pending; /* Indicates if a HeartbeatRequest is in flight */
	unsigned int tlsext_hb_seq;	/* HeartbeatRequest sequence number */

	/* Client list of supported protocols in wire format. */
	unsigned char *alpn_client_proto_list;
	unsigned int alpn_client_proto_list_len;

	int renegotiate;/* 1 if we are renegotiating.
		 	 * 2 if we are a server and are inside a handshake
	                 * (i.e. not just sending a HelloRequest) */

};

typedef long int __ssize_t;
typedef __ssize_t ssize_t;

#ifdef DEFINE_TIME_STRUCT

typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;

struct timeval
{
	__time_t tv_sec;
	__suseconds_t tv_usec;
};

struct timezone
{
	int tz_minuteswest;
	int tz_dsttime;
};

typedef long int __syscall_slong_t;
struct timespec
  {
    __time_t tv_sec;
    __syscall_slong_t tv_nsec;
  };

#else

#include <sys/time.h>

#endif

#ifndef NOT_DEFINED_LSTAT_TYPES

typedef unsigned long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned int mode_t;
typedef unsigned long int __nlink_t;
typedef long int __off_t;
typedef long int __off64_t;
typedef int __pid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;
typedef long int __blksize_t;
typedef long int __blkcnt_t;
typedef long int __blkcnt64_t;
typedef __off_t off_t;

struct stat
  {
    __dev_t st_dev;
    __ino_t st_ino;
    __nlink_t st_nlink;
    __mode_t st_mode;
    __uid_t st_uid;
    __gid_t st_gid;
    int __pad0;
    __dev_t st_rdev;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    __syscall_slong_t __glibc_reserved[3];
  };

struct stat64
  {
    __dev_t st_dev;
    __ino64_t st_ino;
    __nlink_t st_nlink;
    __mode_t st_mode;
    __uid_t st_uid;
    __gid_t st_gid;
    int __pad0;
    __dev_t st_rdev;
    __off_t st_size;
    __blksize_t st_blksize;
    __blkcnt64_t st_blocks;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    __syscall_slong_t __glibc_reserved[3];
  };

#endif

typedef struct crypto_threadid_st {
 void *ptr;
 unsigned long val;
} CRYPTO_THREADID;

#endif
