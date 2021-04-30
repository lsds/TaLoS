FROM ubuntu:16.04
MAINTAINER Florian Kelbert <f.kelbert@imperial.ac.uk>

ENV	APACHE_VERSION 2.4.23
ENV	LIBRESSL_VERSION 2.4.1

ARG 	MAIN_DIR=/talos/

ARG	SGX_FILE=sgx_linux_x64_sdk_2.3.100.46354.bin
ARG	SGX_URL=https://download.01.org/intel-sgx/linux-2.3/ubuntu16.04-desktop/${SGX_FILE}

ARG	LIBRESSL_ROOT=${MAIN_DIR}/src/libressl-${LIBRESSL_VERSION}/
ARG	LIBRESSL_CRYPTO=${LIBRESSL_ROOT}/crypto
ARG	LIBRESSL_LIB=${LIBRESSL_ROOT}/lib

ARG	APACHE_FILE=httpd-2.4.23.tar.bz2
ARG	APACHE_URL=https://archive.apache.org/dist/httpd/${APACHE_FILE}
ARG 	APACHE_ROOT=${MAIN_DIR}/httpd-${APACHE_VERSION}
ARG 	APACHE_INSTALL=${APACHE_ROOT}/install
ARG 	APACHE_HTDOCS=${APACHE_INSTALL}/htdocs
ARG 	APACHE_USR=www-data
ARG 	APACHE_GRP=www-data

ARG 	STARTFILE=$MAIN_DIR/start.sh

RUN 	apt-get update && \
	apt-get install -y --no-install-recommends \
		gcc \
		avr-libc \
		build-essential \
		libpcre3-dev \
		zlib1g-dev \
		git \
		bison \
		flex \
		libtool \
		git \
		openssh-client \
		wget \
		ca-certificates \
		make \
		patch \
		libapr1-dev \
		libaprutil1-dev \
	&& apt-get clean \
	&& apt-get autoclean \
	&& rm -rf /var/lib/apt/lists/*

# Create main directory
RUN    mkdir -p ${MAIN_DIR}

# Copy repository into container
WORKDIR ${MAIN_DIR}
COPY . .

# Install Intel SGX SDK
RUN 	wget ${SGX_URL} \
	&& chmod +x ${SGX_FILE} \
	&& echo "yes" | ./${SGX_FILE} \
	&& rm ${SGX_FILE}

# Patch libressl with TaLoS code
WORKDIR ${MAIN_DIR}/src/talos
RUN	./patch_libressl.sh

# Compile and install TaLoS
WORKDIR ${LIBRESSL_CRYPTO}
RUN	ln -s Makefile.sgx Makefile \
	&& . "${MAIN_DIR}/sgxsdk/environment" \
	&& make \
	&& make install

# Download, unpack, configure, compile and install Apache Httpd
WORKDIR ${MAIN_DIR}
RUN	wget ${APACHE_URL} \
	&& tar xjvf ${APACHE_FILE} \
	&& rm ${APACHE_FILE}
WORKDIR ${APACHE_ROOT}
RUN 	./configure --prefix="${APACHE_INSTALL}" --enable-http --enable-proxy --enable-ssl --enable-ssl-staticlib-deps --with-ssl="${LIBRESSL_ROOT}" --enable-file-cache --enable-cache --enable-disk-cache --enable-mem-cache --enable-deflate --enable-expires --enable-headers --enable-usertrack --enable-cgi --enable-vhost-alias --enable-rewrite --enable-so --enable-dav --with-mpm=worker
RUN	sed -i -e "s#MOD_LDFLAGS.*#MOD_LDFLAGS=-L${LIBRESSL_LIB} -lssl -lcrypto -lsgx_urts_sim -lsgx_uae_service_sim -ldl -lrt -lcrypt -lpthread#" -e "$ iMOD_CFLAGS=-I${LIBRESSL_ROOT}/include" modules/ssl/modules.mk
RUN	. "${MAIN_DIR}/sgxsdk/environment" && \
	export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${LIBRESSL_LIB} && \
	LIBRARY_PATH=${LIBRARY_PATH}:${LD_LIBRARY_PATH} make
RUN	make install

# Configure httpd, set links, create certificate, set owner
RUN 	mkdir -p ${APACHE_INSTALL}/lib \
	&& ln -s ${LIBRESSL_CRYPTO}/enclave.signed.so \
	&& ln -s ${LIBRESSL_LIB}/libssl.so ${APACHE_INSTALL}/lib/ \
	&& ln -s ${LIBRESSL_LIB}/libcrypto.so ${APACHE_INSTALL}/lib/
RUN	cp ${MAIN_DIR}/conf/apache/httpd.conf ${APACHE_INSTALL}/conf/
RUN	echo "\nABC\nMy City\nMy Institution\n\nwww.example.com\n\n" | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ${APACHE_INSTALL}/conf/cert.key -out ${APACHE_INSTALL}/conf/cert.crt
RUN	chown -R ${APACHE_USR}:${APACHE_GRP} ${APACHE_INSTALL}

# Create httpd startup file
RUN	echo "#!/bin/bash\n\
	cd ${APACHE_ROOT}; \n\
	source ${MAIN_DIR}/sgxsdk/environment;\n\
	export LD_LIBRARY_PATH=\${LD_LIBRARY_PATH}:${LIBRESSL_LIB};\n\
	./install/bin/httpd -X" > /start.sh \
	&& chmod +x /start.sh

EXPOSE 7777
EXPOSE 7778

