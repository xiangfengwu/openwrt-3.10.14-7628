#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <uci.h>
 
/* libuci APIs:
	
struct uci_context *uci_alloc_context(void);
void uci_free_context(struct uci_context *ctx);
int uci_load(struct uci_context *ctx, const char *name, struct uci_package **package);
int uci_unload(struct uci_context *ctx, struct uci_package *p);
int uci_set(struct uci_context *ctx, struct uci_ptr *ptr);
int uci_add_list(struct uci_context *ctx, struct uci_ptr *ptr);
int uci_del_list(struct uci_context *ctx, struct uci_ptr *ptr);
int uci_delete(struct uci_context *ctx, struct uci_ptr *ptr);
int uci_commit(struct uci_context *ctx, struct uci_package **p, bool overwrite);
int uci_set_confdir(struct uci_context *ctx, const char *dir);
struct uci_option *uci_lookup_option(struct uci_context *ctx, struct uci_section *s, const char *name)
inline const char *uci_lookup_option_string(struct uci_context *ctx, struct uci_section *s, const char *name)
{ struct uci_option *o = uci_lookup_option(ctx, s, name);  return o->v.string; }

*/

#define myprintf(format, ...) \
	do{  if (verbose)  { printf(format, ##__VA_ARGS__); } } while(0)

enum {
	/* section cmds */
	CMD_GET,
	CMD_SET,
	CMD_ADD_LIST,
	CMD_DEL_LIST,
	CMD_DEL,
	/* package cmds */
	CMD_COMMIT,
	/* other cmds */
	CMD_ADD,
};

static struct uci_context * ctx = NULL;
static struct uci_package * pkg = NULL;
static verbose = 1;
#define FILENAME "ipip"
#define SECTIONNANE "ipip"
/*********************************************
*   载入配置文件,并遍历Section.
*/

int config_init()
{
	int ret = UCI_OK;
    ctx = uci_alloc_context();
	if (!ctx) {
		printf("uci_alloc_context failed!\n");
		exit(6);
	}

/*
	if (uci_set_confdir(ctx, "/tmp/myuci/") != UCI_OK) {  //it's tested ok
		uci_perror(ctx,"uci_set_confdir failed!");
		ret = 7;
        goto cleanup;
	}
*/
/*
    if (UCI_OK != uci_load(ctx, cfilename, &pkg)) {
		uci_perror(ctx,"uci_load failed!");
		ret = 8;
        goto cleanup;
    }
*/
	return UCI_OK;
cleanup:
    uci_free_context(ctx);
    ctx = NULL;
	exit(ret);
}

void config_uninit()
{
	if (ctx) {
		uci_free_context(ctx);
		ctx = NULL;
	}
}

void loop_options(char *sname)
{
	struct uci_element *e;
	char *value;
	char *val;
    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);
        //if section have no name, then s->anonymous = false.
        // s->e->name is option's name
        if (NULL != (value = uci_lookup_option_string(ctx, s, "ipaddr")))
        {
            val = strdup(value); //you should copy the value, if detroy pkg the value will be freed
        	// if you are not sure it's string type; you can call uci_lookup_option firstly, then make decision
        	// Option has two types: UCI_TYPE_STRING, UCI_TYPE_LIST
        }
    }
}

void loop_list(char *listname)
{
	struct uci_element *e;
    uci_foreach_element(&pkg->sections, e)
    {
    	struct uci_section *s = uci_to_section(e);
		struct uci_option * o = uci_lookup_option(ctx, s, listname);
		if ((NULL != o) && (UCI_TYPE_LIST == o->type))
		{
			struct uci_element *e;
			uci_foreach_element(&o->v.list, e)
			{
				//loop the list
			}
		}
    }
}

int myget(char *path, char **ovalue)
{
	if(!ctx) return UCI_ERR_MEM;
	//char path[]="network.ppp.enabled";
	//struct  uci_ptr ptr;
	struct	uci_ptr ptr = {
		 .package = FILENAME,
		 .section = SECTIONNANE,
	};
	ptr.option = path;
	char * val = NULL;

	myprintf("myget: %s\n", path);
	//if ((uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK) || (ptr.o==NULL || ptr.o->v.string==NULL)) {
	if ((uci_lookup_ptr(ctx, &ptr, NULL, true) != UCI_OK) || (ptr.o==NULL || ptr.o->v.string==NULL)) {
		//uci_free_context(ctx);
		uci_perror(ctx,"uci_lookup_ptr failed!");
		return UCI_ERR_NOTFOUND;
	}

	myprintf("myget: flags=0x%x; type=%d; val=%s\n", ptr.flags, ptr.o->type, ptr.o->v.string);
    if(ptr.flags & UCI_LOOKUP_COMPLETE)
		//strcpy(buffer, ptr.o->v.string);
		val = strdup(ptr.o->v.string);

    //uci_free_context(ctx);  //maybe do it later
	//printf("\n\nUCI result data: %s\n\n", buffer);
	if (ovalue)
		*ovalue = val;
	return UCI_OK;
}

int myset(char *path, char *ivalue)
{
	if(!ctx) return UCI_ERR_MEM;
	//char path[]="network.ppp.enabled";
	int ret = UCI_OK;
	struct	uci_ptr ptr = {
		 .package = FILENAME,
		 .section = SECTIONNANE,
	};
	ptr.option = path;
/*
	myprintf("myset: %s,%s\n", path, ivalue);
	if ((uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK) || (ptr.o==NULL || ptr.o->v.string==NULL)) {
		//uci_free_context(ctx); //maybe do it later
		uci_perror(ctx,"uci_lookup_ptr failed!");
		return UCI_ERR_NOTFOUND;
	}
*/
	//myprintf("myset: flags=0x%x; type=%d; val=%s\n", ptr.flags, ptr.o->type, ptr.o->v.string);
	ptr.value = ivalue;  //Note: ptr.o->v.string = ivalue; will not work fine
	if ((uci_set(ctx, &ptr) != UCI_OK) || (ptr.o==NULL || ptr.o->v.string==NULL)) {
		//uci_free_context(ctx); //maybe do it later
		uci_perror(ctx,"uci_set failed!");
		return UCI_ERR_UNKNOWN;
	}
	else {
		/* save changes, but don't commit them yet,after calling uci_save,we can get /tmp/.uci/xxx */
		ret = uci_save(ctx, ptr.p);
	}

	return ret;
}

int mycommit(char *path)
{
	if(!ctx) return UCI_ERR_MEM;
	//struct  uci_ptr ptr;
	struct	uci_ptr ptr = {
		 .package = FILENAME,
	};

	//myprintf("mycommit: %s\n", path);
	//if (uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK ) {
	if (uci_lookup_ptr(ctx, &ptr, NULL, true) != UCI_OK ) {
		//uci_free_context(ctx); //maybe do it later
		uci_perror(ctx,"uci_lookup_ptr failed!");
		return UCI_ERR_NOTFOUND;
	}

	myprintf("mycommit: flags=0x%x\n", ptr.flags);
	if (uci_commit(ctx, &ptr.p, false) != UCI_OK)
	{
		//uci_free_context(ctx);
		uci_perror(ctx,"uci_commit failed!");
		return UCI_ERR_IO;
	}

	return UCI_OK;
}

int main(int argc, char **argv)
{
	//format: prog cmd arg1 arg2
	//char *cfilename = "ipip";
	cfilename = argv[1];
	char buf[80];
	int ret = UCI_OK;

	config_init();

	if (strcmp(argv[1], "get") == 0){
		ret = myget(argv[2], &buf);
	}
	else if (strcmp(argv[1], "set") == 0){
		ret = myset(argv[2], argv[3]);
	}
	else if (strcmp(argv[1], "commit") == 0){
		ret = mycommit(argv[2]);
	}

	config_uninit();

	exit(ret);
}

/*
myconfig set ipaddr 192.168.255.88
myconfig get ipaddr
myconfig commit
*/

