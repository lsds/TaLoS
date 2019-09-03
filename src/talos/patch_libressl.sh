#!/bin/bash

LIBRESSL=../libressl-2.4.1

# copy the new files to the crypto directory
cp enclaveshim/* ${LIBRESSL}/crypto/

# patch the libressl files
cd $LIBRESSL
find ../talos/patch -mindepth 1 -maxdepth 1 -type f -name "*.patch" -print0 | xargs -0 -I {} patch -p0 -i {} 
find . | grep .c$ | xargs grep "explicit_bzero" -r -l | xargs sed -i -e 's/explicit_bzero/bzero/g'
