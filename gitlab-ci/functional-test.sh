#!/bin/bash
set -e
. /usr/share/libubox/jshn.sh
. /usr/bin/tap.sh

cntlrlog="/tmp/cntlr.test.log"
agentlog="/tmp/agent.test.log"

echo "preparation script"
pwd

echo "Cleaning..."
make clean
make -C test/cmocka clean

make -C src

supervisorctl status all
supervisorctl update
supervisorctl restart ubusd wifimngr ieee1905d mapagent
sleep 2
supervisorctl status all

echo "Running the unit test cases, pwd ${LIB_DIR}"
#ret=$?

tap_validate_md5sum() {
    sha1=$(md5sum "$1" | cut -d' ' -f1)
    sha2=$(md5sum "$2" | cut -d' ' -f1)

    tap_is_str "$sha1" "$sha2" "ubus call $3 $4 $5"
}

ubus_invoke() {
    object=$1
    method=$2
    args=$3

    ubus call $object $method $args
    echo "$?"
}

json_load "$(cat test/api/json/mapagent.validation.json)"
json_dump
json_get_var object object
json_get_keys methods methods
json_select methods

for i in $methods; do
    json_select "$i"
    json_get_var method method
    json_get_var args args

    rv=$(ubus_invoke $object $method $args)
    if [ "$rv" != 0 ]; then
        tap_is_str "return code: 0" "return code: $rv" "ubus call $object $method $args"
        continue
    fi
    sleep 1
    tap_validate_md5sum "$agentlog" "$cntlrlog" "$object" "$method" "$args"

    echo "" > "$cntlrlog"
    echo "" > "$agentlog"
    json_select ..
done

tap_done_testing
tap_finish

supervisorctl stop ubusd ieee1905d wifimngr mapagent
supervisorctl status all


#report part
#GitLab-CI output
gcovr -r .
# Artefact
gcovr -r . --xml -o ./unit-test-coverage.xml
date +%s > timestamp.log

#echo "$0 Return status ${ret}"
