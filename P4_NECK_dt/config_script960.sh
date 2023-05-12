#!/usr/bin/env bash

P4_PROGRAM=$"tna_nbnswitch"
MAIN=$"tna_nbnswitch"
if ! [[ -f $P4_PROGRAM/${MAIN}.p4 ]]; then
  echo "P4 source file doesn't exist"
  exit 1
fi

pushd $P4_PROGRAM > /dev/null
/home/yifan/Intel/bf-sde-9.6.0/pkgsrc/p4-build/configure \
--with-p4c=/home/yifan/Intel/bf-sde-9.6.0/install/bin/bf-p4c \
--with-tofino \
--with-bf-runtime \
--prefix=/home/yifan/Intel/bf-sde-9.6.0/install \
--bindir=/home/yifan/Intel/bf-sde-9.6.0/install/bin \
P4_NAME=$P4_PROGRAM \
P4_PATH=$(pwd)/${MAIN}.p4 \
P4_VERSION=p4-16 \
P4_ARCHITECTURE=tna \
LDFLAGS="-L/home/yifan/Intel/bf-sde-9.6.0/install/lib" \
P4FLAGS="" \
P4PPFLAGS=""
popd > /dev/null
