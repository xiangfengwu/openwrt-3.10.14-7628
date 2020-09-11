#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <uci.h>


#if 0
int main(int argc, char **argv)
{
	do_config();

}
#else
#if 0
int main(int argc, char **argv)
{
	char *bufptr = NULL;
	char buf[64];
	int ret = UCI_OK;

	config_init();

	
	snprintf(buf, 64, "%s=%s", "network.lan.macaddr2", "11:22:33:44:55:66");
	myset(buf);

	snprintf(buf, 64, "%s", "network.lan.macaddr2");
	myget(buf, &bufptr);

	printf("result: %s", bufptr);

/*
	if (strcmp(argv[1], "get") == 0){
		ret = myget(argv[2], &buf);
	}
	else if (strcmp(argv[1], "set") == 0){
		ret = myset(argv[2], argv[3]);
	}
	else if (strcmp(argv[1], "commit") == 0){
		ret = mycommit(argv[2]);
	}
*/
	config_uninit();

	exit(ret);
}
#endif
#endif

