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

#include "enclaveshim_config.h"
#include "logpoint.h"

#ifdef COMPILE_WITH_INTEL_SGX
#include "sgx_error.h"
extern int my_printf(const char *format, ...);
#else
#define my_printf(format, ...) printf(format, ##__VA_ARGS__)
#endif

static int initialised = 0;

void logpoint_init(void) {
	if (initialised) {
		return;
	}
	initialised = 1;

	my_printf("Logpoint is initialized!\n");
	//XXX: add other initialisation code here...
}


void logpoint_log(char *req, char *rsp, unsigned int req_len, unsigned int rsp_len) {
	//XXX: process the request/response pair...
	// Do not free the memory pointed to by req/rsp: it is done later in enclaveshim_logpoint.c
	// If you want to save req/rsp, copy them to a new buffer
	
	my_printf("Processing a request @%p of size %u and a reply @%p of size %u\n", req, req_len, rsp, rsp_len);
}

