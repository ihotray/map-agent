#!/bin/bash
set -e
echo "compile warns stage"

pwd

cd src/
make "CFLAGS+=-I/usr/include/libnl3 -Werror -Wall -DAGENT_ISLAND_PREVENTION -DAGENT_SYNC_DYNAMIC_CNTLR_CONFIG -DEASYMESH_VERSION=4"
