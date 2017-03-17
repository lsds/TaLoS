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

#ifndef ENCLAVE_SHIM_LOG_H_
#define ENCLAVE_SHIM_LOG_H_

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>

#undef LOG_ENCLAVE_ENTER_EXIT

static uint64_t clock_mhz; // clock frequency in MHz (number of instructions per microseconds)

/****************** rdtsc() related ******************/

// the well-known rdtsc(), in 32 and 64 bits versions
// has to be used with a uint_64t
#ifdef __x86_64__
#define rdtsc(val) { \
	unsigned int __a,__d;                                        \
	asm volatile("rdtsc" : "=a" (__a), "=d" (__d));              \
	(val) = ((unsigned long)__a) | (((unsigned long)__d)<<32);   \
}
#else
#define rdtsc(val) __asm__ __volatile__("rdtsc" : "=A" (val))
#endif

// initialize clock_mhz
static inline void init_clock_mhz()
{
	struct timeval t0, t1;
	uint64_t c0, c1;

	rdtsc(c0);
	gettimeofday(&t0, 0);
	sleep(1);
	rdtsc(c1);
	gettimeofday(&t1, 0);

	//clock_mhz = number of instructions per microseconds
	clock_mhz = (c1 - c0) / ((t1.tv_sec - t0.tv_sec) * 1000000 + t1.tv_usec
			- t0.tv_usec);
}

/****************** timer ******************/

// return the current time in usec
static inline uint64_t get_current_time()
{
	struct timeval t;
	gettimeofday(&t, 0);
	return (t.tv_sec * 1000000 + t.tv_usec);
}

/*
 * return the difference between t1 and t2 (values in cycles), in usec
 * precondition: t1 > t2 and init_clock_mhz() has already been called
 */
static inline uint64_t diffTime(uint64_t t1, uint64_t t2)
{
	return (t1 - t2) / clock_mhz;
}

static inline uint64_t get_clock_mhz(void)
{
	return clock_mhz;
}

/****************** logging ******************/

static inline void log_enterexit_func(const char* inout, const char* type, const char* func) {
#ifdef LOG_ENCLAVE_ENTER_EXIT
	uint64_t t;
	rdtsc(t);
	printf("%s %s %s %lu\n", inout, type, func, t);
	fflush(NULL);
#endif
}

static inline void log_enter_ecall(const char* func) {
	log_enterexit_func("enter", "ecall", func);
}

static inline void log_enter_ocall(const char* func) {
	log_enterexit_func("enter", "ocall", func);
}

static inline void log_exit_ecall(const char* func) {
	log_enterexit_func("exit", "ecall", func);
}

static inline void log_exit_ocall(const char* func) {
	log_enterexit_func("exit", "ocall", func);
}

#endif
