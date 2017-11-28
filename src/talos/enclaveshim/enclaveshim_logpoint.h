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

#ifndef ENCLAVESHIM_AUDITLOG_H_
#define ENCLAVESHIM_AUDITLOG_H_

#include "openssl/ossl_typ.h"
#include "z2z_async_dlist.h"

#include "enclaveshim_config.h"

// from squid (bio.h)
#define BIO_TO_CLIENT 6000
#define BIO_TO_SERVER 6001

struct log_connection {
	unsigned long id;
	char log_request;
	char ignore_slots;
	struct log_entry* slot;
};

struct log_entry {
	unsigned int req_len; // size of the request
	unsigned int rep_len; // size of the reply
	char* req;			  // pointer to request
	char* rep;			  // pointer to reply
	struct list_head link;
};

void log_https_request(const SSL* s, const char* req, unsigned int len);
void log_https_reply(const SSL* s, const char* rep, unsigned int len);
void log_set_ssl_type(const void* b, const long type);
void log_new_connection(const SSL* s);
void log_free_connection(const SSL* s);

#endif
