# TaLoS: Efficient TLS Termination Inside SGX Enclaves for Existing Applications

[![Jenkins Status](https://wwwpub.zih.tu-dresden.de/~krahn/ci/talos/status.svg)](https://wwwpub.zih.tu-dresden.de/~krahn/ci/talos/build.xml)

TaLoS<sup>[1](#talosfootnote)</sup> is a TLS library that allows existing
applications (with an OpenSSL/LibreSSL interface) to securely terminate their
TLS connection. For this, TaLoS places security-sensistive code and data of the
TLS library inside an [Intel SGX enclave](https://software.intel.com/sgx-sdk),
while the rest of the application remains outside. It can then be used as the
building block for a wide range of security-critical applications for which the
integrity and/or confidentiality of TLS connections must be guaranteed.  TaLoS
offers the developper a [simple interface](#secure-processing-of-tls-communications) to process TLS communications securely.  For example, this interface can be used to securely
send the HTTPS requests and responses to another enclave or to encrypt them
before logging them to persistent storage.  TaLoS provides good performance by
executing enclave transitions asynchronously and leveraging user-level
threading inside the enclave.

The code is accompanied with a [technical report](https://www.doc.ic.ac.uk/research/technicalreports/2017/DTRS17-5.pdf), containing
details about the architecture and performance results.  

In contrast to the [SSL add-on for the Intel SGX SDK](https://software.intel.com/en-us/sgx-sdk/download), TaLoS exposes the
OpenSSL/LibreSSL API to untrusted code outside of the enclave. This means that
existing applications can use the TaLoS library with no or only minor
modifications. The Intel SGX SDK SSL add-on does not expose an outside
interface, which means that applications must be modified to use it.

The current implementation of TaLoS utilises libreSSL v2.4.1 and has been
tested with the following applications under Linux:

- [Apache web server](https://httpd.apache.org/) (v2.4.23);

- [Nginx web server](http://nginx.org/) (v1.11.0);

- [Squid proxy](http://www.squid-cache.org/) (v3.5.23).

## Quick set-up using Docker

We provide a Dockerfile that is configured to run Apache with TaLoS and the SGX
simulator. The Dockerfile can be found in the root folder of this
repository. To use it:

- Clone the repository

- Build the TaLoS Docker image by running `docker build -t talos .` from within
  the root directory of the repository

- Run Apache with TaLoS by running the Docker image: `docker run -dt -p
  7778:7778 talos /start.sh`

- Verify that Apache is running: `wget --no-check-certificate
  https://localhost:7778/index.html`

## Manual Installation

Follow these instructions to build the TaLoS library and the sample
applications. We assume that the path to the repository is `${PROJECT_ROOT}`
(eg `/home/<username>/talos/`).

### Compiling the TaLoS Library

The source code specific to TaLoS can be found in `${PROJECT_ROOT}/src/talos`
while the original code of libreSSL is in `${PROJECT_ROOT}/src/libressl-2.4.1`.

To patch libreSSL, you need to execute:
```bash
$ cd ${PROJECT_ROOT}/src/talos
$ ./patch_libressl.sh
```

To compile TaLos, go to the `${PROJECT_ROOT}/src/libressl-2.4.1/crypto`
directory and edit the `enclaveshim_config.h` file. In particular, you need to
undefine `COMPILE_OPTIMISATION_FOR_APACHE` when compiling TaLoS for Squid or
Nginx. Afer that, execute one of the following lines:
```bash
$ make -f Makefile.nosgx # no SGX
$ make -f Makefile.sgx   # SGX, simulator mode
$ SGX_PRERELEASE=1 SGX_MODE=HW make -f Makefile.sgx # SGX, real hardware mode
```

This creates three files:

- `libenclave.so` and `libenclave.a` are the untrusted libraries that link
  against the application. The Makefile generates both a static and shared
  versions, but you should use only one of them, depending on your application.

- The trusted library, which executes inside an SGX enclave, is
  `enclave.signed.so`. The code expects this library to be present in the
  current directory when launching the application. The easiest way to ensure
  this is to create a symbolic link, as shown in the next sections.

Finally, several symbolic links to the untrusted TaLoS library file have to be
created in `${PROJECT_ROOT}/src/libressl-2.4.1/lib` :
```bash
make -f Makefile.nosgx install # without SGX
make -f Makefile.sgx install # with SGX, simulator or hardware mode
```

Note that, since the SGX SDK v2.0, the SDK libraries make calls to OpenSSL in
simulation mode to emulate cryptographic functions that would normally happen
inside the enclave. However, as TaLoS replaces OpenSSL this creates a conflict
(see [issue #12](https://github.com/lsds/TaLoS/issues/12)). TaLoS, when created
in simulation mode, separately loads the system OpenSSL library. The path is
defined by the `OPENSSL_LIBRARY_PATH` macro in `enclaveshim_config.h`.

### Using TaLoS with Nginx

First, download Nginx v1.11.0:
```bash
wget http://nginx.org/download/nginx-1.11.0.tar.gz
```

We assume that you have downloaded and extracted Nginx to `${PROJECT_ROOT}/src/nginx-1.11.0`. You can then to run configure:
```bash
./configure --prefix=${PROJECT_ROOT}/src/nginx-1.11.0/install --with-http_ssl_module --with-openssl=${PROJECT_ROOT}/src/libressl-2.4.1/
```

You then need to edit `objs/Makefile`:

1. check that the path for the include directory of libressl is correct in `ALL_INCS` and `CORE_INCS`;

2. remove the `include/openssl/ssh.h` line in `CORE_DEPS` and the
   `include/openssl/ssh.h` rule (we have already compiled libressl);

3. in `objs/nginx`, for the LINK phase, update the following line with the
   correct path to `libssl.a` and `libcrypto.a` and add `-lsgx_urts
   -lsgx_uae_service`. Depending on how you compiled TaLoS, you may want to
   change `-lsgx_urts -lsgx_uae_service` (real hardware) to `-lsgx_urts_sim
   -lsgx_uae_service_sim` (simulator).

The code is ready to be compiled:
```bash
$ make
$ make install
```

Before starting the server, you need to copy the Nginx configuration from
`${PROJECT_ROOT}/conf/nginx/` to `install/conf`, create your own TLS certificate
and associated keys, and change the paths in `install/conf/nginx.conf` to
reflect the location where you cloned TaLoS:
```bash
$ cp ${PROJECT_ROOT}/conf/nginx/* install/conf/
$ sed -i 's#/home/talos/talos#${PROJECT_ROOT}#' install/conf/nginx.conf
$ echo "\nABC\nMy City\nMy Institution\n\nwww.example.com\n\n" | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${PROJECT_ROOT}/src/nginx-1.11.0/install/conf/cert.key -out ${PROJECT_ROOT}/src/nginx-1.11.0/install/conf/cert.crt
$ ln -s ../libressl-2.4.1/crypto/enclave.signed.so
```

To start Nginx (`LD_LIBRARY_PATH` is needed only if you use the TaLoS shared library):
```bash
$ LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:$(pwd)/../libressl-2.4.1/crypto ./objs/nginx
```

You should be able to access the web pages with:
```bash
$ wget --no-check-certificate https://localhost:7778/index.html
```
### Using TaLoS with Apache

First, download Apache v2.4.23:
```bash
wget http://archive.apache.org/dist/httpd/httpd-2.4.23.tar.bz2
```

We assume that you have extracted Apache to
`${PROJECT_ROOT}/src/httpd-2.4.23`. You can now configure it:
```bash
$ ./configure --prefix=${PROJECT_ROOT}/src/httpd-2.4.23/install --enable-http --enable-proxy --enable-ssl --enable-ssl-staticlib-deps --with-ssl=${PROJECT_ROOT}/src/libressl-2.4.1 --enable-file-cache --enable-cache --enable-disk-cache --enable-mem-cache --enable-deflate --enable-expires --enable-headers --enable-usertrack --enable-cgi --enable-vhost-alias --enable-rewrite --enable-so --with-mpm=worker
```
You then need to update `modules/ssl/modules.mk` as follows (you may want to
change `-lsgx_urts -lsgx_uae_service` to `-lsgx_urts_sim -lsgx_uae_service_sim`
to use the SGX simulator; note that you need to expand the ${PROJECT_ROOT}
variable in this file):
```bash
MOD_CFLAGS = -I${PROJECT_ROOT}/src/libressl-2.4.1/include
MOD_LDFLAGS = -L${PROJECT_ROOT}/src/libressl-2.4.1/lib -lssl -lcrypto -ldl -luuid -lrt -lcrypt -lpthread -lsgx_urts -lsgx_uae_service
```

To work properly with TaLoS, Apache requires the `COMPILE_OPTIMISATION_FOR_APACHE` macro in `enclaveshim_config.h` to be defined. If this is not the case, then you will first need to define it and compile TaLoS again.

Apache is now ready to be compiled and installed:
```bash
$ make
$ make install
```

The configuration to use Apache with HTTPS can be found in
`${PROJECT_ROOT}/conf/apache/`. You need to copy the content of this directory
to `install/conf/` and edit it to reflect your configuration. You may want to
change the user and group to run httpd as well as the `/talos` path.  You also
need to create your own TLS certificate and associated keys:
```bash
$ echo "\nABC\nMy City\nMy Institution\n\nwww.example.com\n\n" | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${PROJECT_ROOT}/src/httpd-2.4.23/install/conf/cert.key -out ${PROJECT_ROOT}/src/httpd-2.4.23/install/conf/cert.crt
$ ln -s ../libressl-2.4.1/crypto/enclave.signed.so
```

Before starting Apache, you need to create the following symbolic links:
```bash
$ ln -s ../libressl-2.4.1/crypto/enclave.signed.so
$ ln -s ../../../libressl-2.4.1/lib/libssl.so install/lib/libssl.so
$ ln -s ../../../libressl-2.4.1/lib/libcrypto.so install/lib/libcrypto.so
```

Finally, you can use the following command to start Apache:
```bash
$ ./install/bin/httpd -X #-> only 1 process, no fork
```

You can access web pages with:
```bash
$ wget --no-check-certificate https://localhost:7778/index.html
```

Note that, by default, TaLoS is compiled for 50 concurrent threads inside the
enclave (see `TCSNum` in `enclave.config.xml`) while Apache might use hundreds
of threads (see the worker module options in
`http-2.4.23/install/config/extra/http-mpm.conf`). You might want to make
these numbers consistent.

### Using TaLoS with Squid

First, download Squid v3.5.23:
```bash
wget http://www.squid-cache.org/Versions/v3/3.5/squid-3.5.23.tar.gz
```

We assume that you have downloaded and extracted the code to
`${PROJECT_ROOT}/src/squid-3.5.23`. You first need to configure it:
```
$ ./configure --prefix=${PROJECT_ROOT}/src/squid-3.5.23/install --disable-shared --enable-static --enable-silent-rules --enable-dependency-tracking --enable-icmp --enable-delay-pools --enable-useragent-log --enable-esi --enable-follow-x-forwarded-for --enable-auth --with-openssl=/home/talos/talos/src/libressl-2.4.1
$ patch -p0 -i ${PROJECT_ROOT}/conf/squid/src.ssl.gadgets.cc.patch
$ find . -name "Makefile" -exec sed --in-place 's/-lcrypto/-lcrypto -lsgx_urts -lsgx_uae_service -lpthread/' {} \; # as stated previously, add _sim if TaLoS has been compiled for the SGX simulator
$ make && make install
```

To configure Squid, copy the content of `${PROJECT_ROOT}/conf/squid/` to
`install/etc/`, update the configuration to reflect your installation and
create your own TLS certificate and associated keys. This installation is
configured to use the `ssl_bump` module to decrypt the HTTPS traffic.
```bash
$ cp ${PROJECT_ROOT}/conf/squid/* install/etc/
$ echo "\nABC\nMy City\nMy Institution\n\nwww.example.com\n\n" | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${PROJECT_ROOT}/src/squid-3.5.23/install/etc/cert.key -out ${PROJECT_ROOT}/src/squid-3.5.23/install/etc/cert.crt
```
You also need to create a symbolic link to the enclave library:
```bash
$ ln -s ../libressl-2.4.1/crypto/enclave.signed.so
```

To run Squid (`LD_LIBRARY_PATH` is needed only if you use TaLoS shared library):
```bash
LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:$(pwd)/../libressl-2.4.1/lib ./install/sbin/squid -CNd3
# -C: do not catch fatal signals
# -N: no daemon mode (i.e., stays on foreground)
# -d3 is to have some debugging messages
```

For testing, the port is 3128 in `https_proxy`, which corresponds to the http
proxy port, as the client needs to send a CONNECT request in clear text first:
```bash
$ wget --no-check-certificate --debug --verbose -e use_proxy=on -e https_proxy=localhost:3128 https://google.com
```

### Limtations and Common Compilation Errors

- Intel SGX does not support the fork system call. Therefore neither the
  multi-processes version of Nginx nor the prefork module of Apache can be
  used.

- `application/source_file.c:` undefined reference to `SSL_function`: this
  error happens when the untrusted library of TaLoS does not export the symbol
  `SSL_function`. To fix this, you need to add the definition of the function
  in `enclaveshim_ecalls.c` and its declaration in `enclaveshim_ecalls.h`:
```c
// we assume the following prototype for SSL_function:
int SSL_function(SSL* ssl, void* args) {
   fprintf(stderr, "%s:%i need to implement ecall %s\n", __FILE__, __LINE__, __func__);
   return 0;
}
```

- when compiling Apache you might encounter the following warning. In addition,
Apache might fail to load the SSL module because the `RAND_egd` function is not
defined. This is due to the configure step that uses the system OpenSSL headers
instead of TaLoS ones. To fix this, you need to undefine the `HAVE_RAND_EGD`
macro in `http-2.4.23/include/ap_config_auto.h`.
```c
ssl_engine_rand.c: In function 'ssl_rand_seed':
ssl_engine_rand.c:90:26: warning: implicit declaration of function 'RAND_egd' [-Wimplicit-function-declaration]
                 if ((n = RAND_egd(pRandSeed->cpPath)) == -1)
```

- In simulation mode and when compiling TaLoS as a shared library, Apache fails
with a call to `free()` inside the enclave when processing an HTTPS request.
Other modes (static library and/or hardware mode) are not affected.


## Documentation

### TaLoS Interface

TaLoS exposes the same interface as LibreSSL. The functions of the interface
are defined in `enclaveshim_ecalls.c`. This file also loads the enclave (ie
`enclave.signed.so`) and makes the necessary ecalls, transitioning from
untrusted code to enclave code.

The functions of the interface follow a common schema:
```c
<type> function(<arguments>) {
   type retval = 0;
   log_enter_ecall(__func__);

   sgx_status_t ret = SGX_ERROR_UNEXPECTED;
   ret = ecall_function(global_eid, &retval, <arguments>);
   if (ret != SGX_SUCCESS) {
      print_error_message(ret, __func__);
      return <error_code>; // generally 0, -1 or NULL
   }

   log_exit_ecall(__func__);
   return retval;
}
```

The `log_enter_ecall()` and `log_exit_ecall()` functions are defined in
`enclaveshim_log.h`. If the `LOG_ENCLAVE_ENTER_EXIT` macro is defined, a printf
will be issued with the current time and the called function for every ecall
and ocall for debugging.

The `ecall_function()` function is defined in `enclave.edl`. Refer to the Intel
SGX SDK syntax for its format. It is also defined in libreSSL code near the
definition of `function()`. While `ecall_function()` is the entry point of the
enclave, `function()` is the actual function of the TLS library. For example,
in `ssl/ssl_lib.c`:
```c
ecall_SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx,
    unsigned int sid_ctx_len) {
        return SSL_CTX_set_session_id_context(ctx, sid_ctx, sid_ctx_len);
}
int
SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx,
    unsigned int sid_ctx_len)
{
  ...
}
```

Ocalls, ie transitions from enclave code to untrusted code, are defined in a
similar way in `enclaveshim_ocalls.c` (code executed inside the enclave) and
`ocalls.c` (code executed outside of the enclave).

If an interface function does not have an associated ecall, it prints a `need to implement ecall ...` message.

### Secure processing of TLS communications

TaLoS can be used to build other systems that need to process the TLS communication in a secure manner, inside an SGX enclave. The interface consists of a set of private functions, called by LibreSSL, and public functions, used by your TLS processing module to register callbacks. These callbacks are called by the "private" functions.
The public interface is the following:
  * `void tls_processing_register_ssl_read_processing_cb(void (*cb)(const SSL*, char*, unsigned int))`: register the callback that will be called by `ssl3_read_bytes()` in `ssl/s3_pkt.c` when data is read from the TLS connection socket;
  * `void tls_processing_register_ssl_write_processing_cb(void (*cb)(const SSL*, char*, unsigned int))`: register the callback that will be called by `do_ssl3_write()` in `ssl/s3_pkt.c` when data is read from the TLS connection socket;
  * `void tls_processing_register_set_ssl_type_cb(void (*cb)(const void*, const long))`: register the callback that will be called by `BIO_int_ctrl()` when the command is `BIO_C_SET_FD`. This callback is used for Squid in SSL proxy mode to differentiate the connection between the client and the proxy from the connection between the proxy and the server;
  * `void tls_processing_register_new_connection_cb(void (*cb)(const SSL*))`: register the callback that will be called from `SSL_new()` in `ssl/ssl_lib.c` when a new TLS connection is created;
  * `void tls_processing_register_free_connection_cb(void (*cb)(const SSL*))`: register the callback that will be called from `SSL_free()` in `ssl/ssl_lib.c` when a TLS connection is terminated.

In addition, your TLS processing module must implement the `void tls_processing_module_init(void)`, which is called upon the enclave creation. In this function you can register the callbacks and initialise your code.

The callbacks registered for `tls_processing_register_ssl_read_processing_cb()` and `tls_processing_register_ssl_write_processing_cb()` can not only read the data buffer but also modify it in place. This can for example be used to ensure that an application calling `SSL_read()` does not observe sensitive data that goes through the TLS connection.

The file `logpoint.c` is a minimal example of a TLS processing module that uses this interface to log the TLS communications. To enable it, please define the `DO_LOGGING` macro in `logpoint.c`.
The Makefiles define a variable `TLSPROCESSINGMODULE` which lists the files that need to be compiled for your module.

Not that, because LibSEAL cannot load existing shared libraries inside an enclave, a recompilation of TaLoS is necessary to use a different module.

### Asynchronous Enclave Transitions

To reduce the cost of enclave transitions, it is possible to activate the
asynchronous queue. Instead of threads entering and exiting the enclave,
user-level tasks, implemented by the [lthread](https://github.com/halayli/lthread) library inside the enclave,
perform call executions.

Applications threads share two arrays with the lthread tasks to send ecalls and
ocalls requests and results. These arrays are defined at lines 206 and 207 of
`enclaveshim_ecalls.c`.

To add an ecall/ocall to the asynchronous queue, you need to:

- modify `make_asynchronous_ecall` in `enclaveshim_ecalls.c` to enqueue your
  async ecall and wait for the result or any ocall to execute;

- modify your interface function in `enclaveshim_ecalls.c` to create the async
  ecall with the necessary arguments and read the result (see `SSL_read()` line
  545 for an example);

- add your new ecall (or ocall) type in `ecall_queue.h`;

- create a new function in `enclaveshim_ocalls.h` to make an asynchronous ocall;

- modify `lthread_main_handler()` in `../ssl/ssl_lib.c` to read your ecall from
  the ecall queue and execute the corresponding function.

### Shadow Data Structure Mechanism

TaLoS uses shadow structures to protect the security and integrity of the SSL
object. It maintains a sanitised copy of the SSL structure outside the enclave,
with all sensitive data removed.

The association between the enclave structure and the shadow structure is
stored in a hashmap inside the enclave.

TaLoS synchronises the two SSL structures at ecalls and ocalls, as shown in the
listing below:
```c
BIO* ecall_SSL_get_wbio(const SSL *s)
{
  SSL* out_s = (SSL*)s;

  // retrieve the in-enclave structure from the hashmap
  sgx_spin_lock(&ssl_hardening_map_lock);
  SSL* in_s = (SSL*) hashmapGet(ssl_hardening_map, (unsigned long)out_s);
  sgx_spin_unlock(&ssl_hardening_map_lock);

  // copy fields from out structure to in structure
  SSL_copy_fields_to_in_struct(in_s, out_s);

  // execute the TLS function by passing it a pointer to the in structure
  BIO* ret = SSL_get_wbio((const SSL*)in_s);

  // copy fields form in structure to out structure
  SSL_copy_fields_to_out_struct(in_s, out_s);

  return ret;
}
```

### Secure Callbacks

Several API functions permit the application to submit function pointers. As
TaLoS executes inside an SGX enclave, it must trigger an ocall before calling
such functions. To address this problem, we create wrapper functions. See
`bio/bio_lib.c` for more details.

## References

<a name="talosfootnote">1</a>: "In Greek mythology, Talos was a giant automaton made of bronze to protect
Europa in Crete from pirates and invaders.", https://en.wikipedia.org/wiki/Talos
