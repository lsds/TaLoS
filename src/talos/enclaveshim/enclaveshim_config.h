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

/*
 * This file contains important macros to configure TaLoS behaviour
 */

#ifndef ENCLAVESHIM_CONFIG_H
#define ENCLAVESHIM_CONFIG_H

#ifdef SGX_MODE_SIM
#define OPENSSL_LIBRARY_PATH "/usr/lib/x86_64-linux-gnu/libssl.so"
#endif

#undef USE_ASYNC_ECALLS_OCALLS // define it to use the asynchronous queues for ecalls and ocalls

#undef COMPILE_OPTIMISATION_FOR_APACHE // define this macro to remove a few unnecessary ocalls for Apache (but needed by nginx/squid)

#undef SQUID_WORKAROUND // define this macro when compiling with Squid, to activate AES-NI and avoid an illegal instruction

#endif
