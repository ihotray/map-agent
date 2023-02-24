#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <libubox/blobmsg.h>

#include <json-c/json.h>


static int group_setup(void **state)
{
	return 0;
}

static int setup(void **state)
{
	return 0;
}

static int group_teardown(void **state)
{
	return 0;
}

static void test_cmdu(void **state)
{
	printf("init test\n");
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_cmdu, setup),
	};

	return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
