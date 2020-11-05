/*
 * 这个例程适用于`Linux`这类支持pthread的POSIX设备, 它演示了用SDK配置MQTT参数并建立连接, 之后创建2个线程
 *
 * + 一个线程用于保活长连接
 * + 一个线程用于接收消息, 并在有消息到达时进入默认的数据回调, 在连接状态变化时进入事件回调
 *
 * 需要用户关注或修改的部分, 已经用 TODO 在注释中标明
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>  //have define for howmany; roundup
#include <dirent.h>

#include <sys/wait.h>
#include <signal.h>
#include <limits.h> /* For PATH_MAX, _POSIX_HOST_NAME_MAX */
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <net/if.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h> /* For typedefs */
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/epoll.h>  //bytian
#include <sys/timerfd.h> //bytian
#include <sys/resource.h> //bytian

#include <time.h> //byxfwu

#include <pthread.h>



#include "aiot_state_api.h"
#include "aiot_sysdep_api.h"
#include "aiot_mqtt_api.h"


/* 位于portfiles/aiot_port文件夹下的系统适配函数集合 */
extern aiot_sysdep_portfile_t g_aiot_sysdep_portfile;

/* 位于external/ali_ca_cert.c中的服务器证书 */
extern const char *ali_ca_cert;

static pthread_t g_mqtt_process_thread;
static pthread_t g_mqtt_recv_thread;
static uint8_t g_mqtt_process_thread_running = 0;
static uint8_t g_mqtt_recv_thread_running = 0;

///////////  bytian  //////////////
#define DEFAULT_SOCK "/var/run/aiot-demo.sock"
#define READ_FULL			0
#define READ_NOTFULL		1
#define READ_HAVEERROR		2
#define READ_TIMEOUT		3

int epfd = -1;
int connfd = -1;
int listenfd = -1;

static int execute(const char *cmd_line, int quiet)
{
    int pid,
        status,
        rc;

    const char *new_argv[4];
    new_argv[0] = "/bin/sh";
    new_argv[1] = "-c";
    new_argv[2] = cmd_line;
    new_argv[3] = NULL;

    pid = fork();
    if (pid == 0) {    /* for the child process:         */
        /* We don't want to see any errors if quiet flag is on */
        if (quiet) close(2);
        if (execvp("/bin/sh", (char *const *)new_argv) == -1) {    /* execute the command  */
            fprintf(stderr, "execvp(): %s", strerror(errno));
        } else {
            fprintf(stderr, "execvp() failed");
        }
        exit(1);
    }

    /* for the parent:      */
	printf("Waiting for PID %d to exit", pid);
	rc = waitpid(pid, &status, 0);
	printf("Process PID %d exited", rc);

    return (WEXITSTATUS(status));
}

static int set_nonblock(int fd)
{
	int val;

	val = fcntl(fd, F_GETFL);
	if (val < 0) {
		fprintf(stderr, "fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		return (-1);
	}
	if (val & O_NONBLOCK) {
		fprintf(stderr, "fd %d is O_NONBLOCK", fd);
		return (0);
	}
	printf("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1) {
		fprintf(stderr, "fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		return (-1);
	}
	return (0);
}

int epfd_epolladd(int fd, int events)
{
	struct epoll_event ev;
	ev.events = events;
	ev.data.fd = fd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1 ) {
		fprintf(stderr, "epoll ctl add(%d) failed! err=%d(%s)\n",fd, errno, strerror(errno));
        return (-1);
	}
	return 0;
}

int unixsvr_listen()
{
	struct 	sockaddr_un	sa_un;
	int listenfd = -1;
	char *sockname = strdup(DEFAULT_SOCK);

	memset(&sa_un, 0, sizeof(sa_un));

	if (strlen(sockname) > (sizeof(sa_un.sun_path) - 1)) {
		/* TODO: Die handler with logging.... */
		fprintf(stderr, "socket name too long\n");
		exit(2);
	}

	printf("Creating unix socket\n");
	listenfd = socket(PF_UNIX, SOCK_STREAM, 0);

	printf("Got server socket %d\n", listenfd);

	/* If it exists, delete... Not the cleanest way to deal. */
	unlink(sockname);

 	strcpy(sa_un.sun_path, sockname); /* XXX No size check because we check a few lines before. */
	sa_un.sun_family = AF_UNIX;


	/* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
	if (bind(listenfd, (struct sockaddr *)&sa_un, strlen(sockname)
				+ sizeof(sa_un.sun_family))) {
		fprintf(stderr, "Could not bind control socket: %s\n", strerror(errno));
		exit(9);
	}

	if (listen(listenfd, 5)) {
 		fprintf(stderr, "Could not listen on control socket: %s\n", strerror(errno));
		exit(10);
	}

	printf("Server listening on %d port %s\n", listenfd, sockname);

	return listenfd;
}

int unixsvr_accept_handler(int listenfd)
{
	int acceptedfd;
	struct 	sockaddr_un	sa_un;
	socklen_t len;

	len = sizeof(sa_un);
	memset(&sa_un, 0, len);
	if ((acceptedfd = accept(listenfd, (struct sockaddr *)&sa_un, &len)) == -1){
		fprintf(stderr, "Accept failed on control socket: %s\n", strerror(errno));
	} else {
		//logit("unix client socket %d (%s)\n", acceptedfd, sa_un.sun_path);
		printf("UNIXSVR: listenfd=%d, acceptFD=%d", listenfd, acceptedfd);  //bytian,debug
		set_nonblock(acceptedfd);
		epfd_epolladd(acceptedfd, EPOLLIN);  //bytian
	}

	return 0;
}

int read_sockdata(int sockfd, char *readbuf, int sizeofbuf, int *status)  //bytian
{	//when read fully;     *status=READ_FULL
	//when read not fully; *status=READ_NOTFULL
	//have error,          *status=READ_HAVEERROR
	int nread = -1;
	int totalread = 0;
	int full = 1;
	
	if(!readbuf) {
		fprintf(stderr, " read_sockdata ptr is empty ");
		return 0;
	}
	else{ //if have any data incoming
		//logit("\tdata is comming, u can read !\n");
		int sock_closed = 0;  //check socket have closed
		char * pbuff = readbuf;
		int left = sizeofbuf;
		printf("read_sockdata(%d): begin: free dataspace to read:%d\n", sockfd, sizeofbuf);
		while(left > 0 ) { //bytian; exit the loop: 1. left<=0(recv buf is full); 2. input buffer is empty
			nread = read(sockfd, pbuff, left);  //API read();
			if (nread < 0) {  //have errors, 分析处理不同的错误
				if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK){ //errors: maybe input buffer is empty
					//kernel socket input buffer is empty
					fprintf(stderr, "read_sockdata(%d): warning: no more data! totalread:%d\n", sockfd, totalread);
					full = 0;
					goto final;
				}
				else{  //have any other errors. close local socket 
 					fprintf(stderr, "read_sockdata(%d): error: should close socket .\n", sockfd);
					sock_closed = 1;
					goto freeresource;
				}
			}
			else if( nread == 0){  //errors: maybe peer socket closed or have no data to read
				if (errno != 0) {
					fprintf(stderr, "read_sockdata(%d): error: peer closed!\n", sockfd);
					sock_closed = 1;
					goto freeresource;
				}
				else {
					full = 0;
					goto final;
				}
				
			}
			else {  //have no error
				fprintf(stderr, "read_sockdata: read %s!\n", pbuff);
				pbuff += nread;
				left -= nread;
				totalread += nread;
			}
		}

	}

final:
	if (status) {
		if (full)
			*status = READ_FULL;
		else
			*status = READ_NOTFULL;
	}
	return totalread;

freeresource:
	if (status)
		*status = READ_HAVEERROR;
	return totalread;

}

void write_filedata(char *filename, unsigned char *databuf, int datalen)
{
	int fd,n;
	fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH);
	if (fd == -1)  {
		fprintf(stderr, "create file failed!\n");
	}
	n = write(fd, databuf, datalen);
	if (n != datalen ) {
		fprintf(stderr, "write file failed!\n");
	}
	close(fd);
}


typedef struct cstring {
	char *pstr;
	int curlen;
	int leftlen;
} string;

static int read_filedata(char *filename, string *pfilebuf)  //bytian,191010
{
	struct stat statbuf;
	FILE *fp; int filesize;
	ssize_t len = 0;
	int ret = -1;

	//1. some check for file
	if (stat(filename,&statbuf) == -1) {
		//perror("stat");
		fprintf(stderr, "error: file %s not exist\n", filename);
		goto final;
	}

	filesize = statbuf.st_size;

	if (filesize >= pfilebuf->leftlen) {
		fprintf(stderr, "error: %s filesize too long\n", filename);
		goto final;
	}

	fp = fopen(filename,"r");
	if (!fp) {
		fprintf(stderr, "error: open %s failed\n", filename);
		goto final_close;
	}

	len = fread(pfilebuf->pstr + pfilebuf->curlen, 1, pfilebuf->leftlen, fp);
	if (len > 0) {
		pfilebuf->curlen += len;  pfilebuf->leftlen -= len;
		ret = len;
	}
	else
		fprintf(stderr, "error: read %s failed\n", filename);

final_close:
	fclose(fp);

final:

	return ret;
}

int reply_mqtt_pub(void *handle, char *paramin)
{
	char *ptrtmp = paramin;
	char pub_payload[8192]; char *pub_topic = NULL;  char *path = NULL;
	int res = 0; int len;
	string filebuf = {.curlen=0, .leftlen=8192, .pstr = pub_payload};
	memset(pub_payload, 0, sizeof(pub_payload));

	//char *pub_topic = "/sys/a13FN5TplKq/mqtt_basic_demo/thing/event/property/post";
	//char *pub_payload = "{\"id\":\"1\",\"version\":\"1.0\",\"params\":{\"LightSwitch\":0}}";

	while (isspace(*ptrtmp)) ptrtmp++;	//bytian, skip head whitespace
	if ((!ptrtmp) || (*ptrtmp=='\0')) {
		fprintf(stderr, "error: postfile param(urlaction) is NULL - exiting");
		return (-1);
	}
	pub_topic = ptrtmp;
	strsep(&ptrtmp,"@");  //bytian, divide param into pub_topic and filename
	if ((!ptrtmp) || (*ptrtmp=='\0')) {
		fprintf(stderr, "error: filename param is NULL - exiting");
		return (-1);
	}
	
	path = ptrtmp;
	//////////////////////////read filename as pub_payload
	res = read_filedata(path, &filebuf);
	if (res <= -1) {
		fprintf(stderr, "error: filename param is NULL - exiting");
		return (-1);
	}
	
	res = aiot_mqtt_pub(handle, pub_topic, (uint8_t *)pub_payload, (uint32_t)strlen(pub_payload), 0);
	if (res < 0) {
		printf("aiot_mqtt_sub failed, res: -0x%04X\n", -res);
		return -1;
	}

	return res;
}

///////////  bytian   /////////

/* TODO: 如果要关闭日志, 就把这个函数实现为空, 如果要减少日志, 可根据code选择不打印
 *
 * 例如: [1577589489.033][LK-0317] mqtt_basic_demo&a13FN5TplKq
 *
 * 上面这条日志的code就是0317(十六进制), code值的定义见core/aiot_state_api.h
 *
 */

/* 日志回调函数, SDK的日志会从这里输出 */
int32_t demo_state_logcb(int32_t code, char *message)
{
    printf("%s", message);
    return 0;
}

/* MQTT事件回调函数, 当网络连接/重连/断开时被触发, 事件定义见core/aiot_mqtt_api.h */
void demo_mqtt_event_handler(void *handle, const aiot_mqtt_event_t *event, void *userdata)
{
    switch (event->type) {
        /* SDK因为用户调用了aiot_mqtt_connect()接口, 与mqtt服务器建立连接已成功 */
        case AIOT_MQTTEVT_CONNECT: {
            printf("AIOT_MQTTEVT_CONNECT\n");
            /* TODO: 处理SDK建连成功, 不可以在这里调用耗时较长的阻塞函数 */
			execute("/opt/bin/iot_rcv.sh connected", 0);
        }
        break;

        /* SDK因为网络状况被动断连后, 自动发起重连已成功 */
        case AIOT_MQTTEVT_RECONNECT: {
            printf("AIOT_MQTTEVT_RECONNECT\n");
			execute("/opt/bin/iot_rcv.sh reconnect", 0);
            /* TODO: 处理SDK重连成功, 不可以在这里调用耗时较长的阻塞函数 */
        }
        break;

        /* SDK因为网络的状况而被动断开了连接, network是底层读写失败, heartbeat是没有按预期得到服务端心跳应答 */
        case AIOT_MQTTEVT_DISCONNECT: {
            char *cause = (event->data.disconnect == AIOT_MQTTDISCONNEVT_NETWORK_DISCONNECT) ? ("network disconnect") :
                          ("heartbeat disconnect");
            printf("AIOT_MQTTEVT_DISCONNECT: %s\n", cause);
			execute("/opt/bin/iot_rcv.sh disconnect", 0);
            /* TODO: 处理SDK被动断连, 不可以在这里调用耗时较长的阻塞函数 */
        }
        break;

        default: {

        }
    }
}

/* MQTT默认消息处理回调, 当SDK从服务器收到MQTT消息时, 且无对应用户回调处理时被调用 */
void demo_mqtt_default_recv_handler(void *handle, const aiot_mqtt_recv_t *packet, void *userdata)
{
	
	time_t t;
	struct tm *lt;
	time(&t);
	lt = localtime(&t);
	//char *command = NULL;
    switch (packet->type) {
        case AIOT_MQTTRECV_HEARTBEAT_RESPONSE: {
            printf("%d/%d/%d %d:%d:%d  heartbeat response\n",lt->tm_year+1900, lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
            /* TODO: 处理服务器对心跳的回应, 一般不处理 */
        }
        break;

        case AIOT_MQTTRECV_SUB_ACK: {
            printf("suback, res: -0x%04X, packet id: %d, max qos: %d\n",
                   -packet->data.sub_ack.res, packet->data.sub_ack.packet_id, packet->data.sub_ack.max_qos);
            /* TODO: 处理服务器对订阅请求的回应, 一般不处理 */
        }
        break;

        case AIOT_MQTTRECV_PUB: {
            printf("pub, qos: %d, topic: %.*s\n", packet->data.pub.qos, packet->data.pub.topic_len, packet->data.pub.topic);
            printf("pub, payload: %.*s\n", packet->data.pub.payload_len, packet->data.pub.payload);
            /* TODO: 处理服务器下发的业务报文 */
			//bytian. call external shell script
			//asprintf(&command, "%s %s %s", "/opt/bin/iot_rcv.sh", packet->data.pub.topic, packet->data.pub.payload);
			write_filedata("/tmp/iot/pubtopic.json", packet->data.pub.topic, packet->data.pub.topic_len);
			write_filedata("/tmp/iot/pubpayload.json", packet->data.pub.payload, packet->data.pub.payload_len);
			//if (command) {
				execute("/opt/bin/iot_rcv.sh recvpub /tmp/iot/pubtopic.json /tmp/iot/pubpayload.json", 0);
				//free(command);
			//}
        }
        break;

        case AIOT_MQTTRECV_PUB_ACK: {
            printf("puback, packet id: %d\n", packet->data.pub_ack.packet_id);
            /* TODO: 处理服务器对QoS1上报消息的回应, 一般不处理 */
        }
        break;

        default: {
			printf("%d/%d/%d %d:%d:%d  22222222222222\n",lt->tm_year+1900, lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec);
        }
    }
}

/* 执行aiot_mqtt_process的线程, 包含心跳发送和QoS1消息重发 */
void *demo_mqtt_process_thread(void *args)
{
    int32_t res = STATE_SUCCESS;

    while (g_mqtt_process_thread_running) {
        res = aiot_mqtt_process(args);
        if (res == STATE_USER_INPUT_EXEC_DISABLED) {
            break;
        }
        sleep(1);
    }
    return NULL;
}

/* 执行aiot_mqtt_recv的线程, 包含网络自动重连和从服务器收取MQTT消息 */
void *demo_mqtt_recv_thread(void *args)
{
    int32_t res = STATE_SUCCESS;
	char request[4096] = {0};
#define MAXEPOLL 16
	struct epoll_event evs[MAXEPOLL];
	int retfds; int efd, event; int i; int len; int status = 0;

    while (g_mqtt_recv_thread_running) {

		retfds = epoll_wait(epfd, evs, MAXEPOLL, -1 ); //bytian
		if( retfds < 0 ) {
			if (errno != EINTR) {
				fprintf(stderr, "Epoll Wait Error(%d): %s\n", errno, strerror(errno) );
				exit(22);  //epoll is fatal error, maybe restart this program
			}
		}

		for( i = 0; i < retfds; i++ ) {  //bytian
			efd = evs[i].data.fd;
			event = evs[i].events;
			if (efd == connfd) {  //bytian
		        res = aiot_mqtt_recv(args);
		        if (res < STATE_SUCCESS) {
		            if (res == STATE_USER_INPUT_EXEC_DISABLED) {
		                break;
		            }
		            sleep(1);
		        }
			}
			else if (efd == listenfd) {  //bytian
				unixsvr_accept_handler(listenfd);
			}
			else {  ////bytian; the fd come from cunix; or some broken connfd
				//1. read message;
				if (event & EPOLLIN) {
					memset(request, 0, sizeof(request));
					len = read_sockdata(efd, request, 4095, &status);

					//2. reply mqtt; if len < 2; not call reply_*
					if (len > 8) {
						reply_mqtt_pub(args, request);
						write(efd, "send ok", 7);
					}
					if (status == READ_HAVEERROR) {
						fprintf(stderr, "read have error!");  //bytian,200516
					}
					else if (len < 8) {
						fprintf(stderr, "param invalid!");
						write(efd, "param invalid!", 14);
					}
					close(efd);
					continue;
				}
				if( ( event & EPOLLERR ) || ( event & EPOLLHUP ) ) {
					close(efd);
				}

			}
		}

    }
    return NULL;
}

static void usage(void)
{
    printf("Usage: mqtt_basic_demo [options]\n");
    printf("\n");
    printf("options:\n");
    printf("  -p <product_key> -d <device_name> -s <device_secret>\n");
    printf("  -h                Print usage\n");
    printf("\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int32_t     res = STATE_SUCCESS;
    void       *mqtt_handle = NULL;
    //char       *url = "iot-as-mqtt.ap-southeast-1.aliyuncs.com"; /* 阿里云平台上海站点的域名后缀  线下*/
	char       *url = "iot-as-mqtt.cn-shanghai.aliyuncs.com"; /* 阿里云平台上海站点的域名后缀 线上*/
    char        host[100] = {0}; /* 用这个数组拼接设备连接的云平台站点全地址, 规则是 ${productKey}.iot-as-mqtt.cn-shanghai.aliyuncs.com */
    uint16_t    port = 1883;      /* 无论设备是否使用TLS连接阿里云平台, 目的端口都是443 */
    aiot_sysdep_network_cred_t cred; /* 安全凭据结构体, 如果要用TLS, 这个结构体中配置CA证书等参数 */
	int opt;
	
	/*int count;
	for(count = 1;count < argc;count++)
	{
		printf("xfwu----%d: %s \r\n", count, argv[count]);
	}*/

    /* TODO: 替换为自己设备的三元组 */
    char *product_key       = "a2Wl5a1kUzm";
    char *device_name       = "8000000240159904";
    char *device_secret     = "74H4pLD7oyHuOeLokfMPV14bWgSw79Ft";
	
	
	

    while (-1 != (opt = getopt(argc, argv, "p:d:s:h"))) {
		
		
     /*   printf("opt = %c\n", opt);
        printf("optarg = %s\n", optarg);
        printf("optind = %d\n", optind);
        printf("argv[optind - 1] = %s\n\n",  argv[optind - 1]);
		*/
		
        switch(opt) {
            case 'p':
		    	product_key = optarg;
				//printf("aaaaaaaaaaaa = %s\n", product_key);
                break;
            case 'd':
		    	device_name = optarg;
				//printf("bbbbbbbbbbb = %s\n", device_name);
                break;
			case 's':
				device_secret = optarg;
				//printf("ccccccccccccc = %s\n", device_secret);
				break;
			case 'h':
            default:
                usage();
                exit(1);
                break;
        }
    }

    /* 配置SDK的底层依赖 */
    aiot_sysdep_set_portfile(&g_aiot_sysdep_portfile);
    /* 配置SDK的日志输出 */
    aiot_state_set_logcb(demo_state_logcb);

    /* 创建SDK的安全凭据, 用于建立TLS连接 */
    memset(&cred, 0, sizeof(aiot_sysdep_network_cred_t));
    cred.option = AIOT_SYSDEP_NETWORK_CRED_SVRCERT_CA;  /* 使用RSA证书校验MQTT服务端 */
    cred.max_tls_fragment = 16384; /* 最大的分片长度为16K, 其它可选值还有4K, 2K, 1K, 0.5K */
    cred.sni_enabled = 1;                               /* TLS建连时, 支持Server Name Indicator */
    cred.x509_server_cert = ali_ca_cert;                 /* 用来验证MQTT服务端的RSA根证书 */
    cred.x509_server_cert_len = strlen(ali_ca_cert);     /* 用来验证MQTT服务端的RSA根证书长度 */

    /* 创建1个MQTT客户端实例并内部初始化默认参数 */
    mqtt_handle = aiot_mqtt_init();
    if (mqtt_handle == NULL) {
		//printf("xfwu---------------------333333333333333333333333");
        printf("aiot_mqtt_init failed\n");
        return -1;
    }

    /* TODO: 如果以下代码不被注释, 则例程会用TCP而不是TLS连接云平台 */
    /*
    {
        memset(&cred, 0, sizeof(aiot_sysdep_network_cred_t));
        cred.option = AIOT_SYSDEP_NETWORK_CRED_NONE;
    }
    */
	
    snprintf(host, 100, "%s.%s", product_key, url);
    /* 配置MQTT服务器地址 */
    aiot_mqtt_setopt(mqtt_handle, AIOT_MQTTOPT_HOST, (void *)host);
    /* 配置MQTT服务器端口 */
    aiot_mqtt_setopt(mqtt_handle, AIOT_MQTTOPT_PORT, (void *)&port);
    /* 配置设备productKey */
    aiot_mqtt_setopt(mqtt_handle, AIOT_MQTTOPT_PRODUCT_KEY, (void *)product_key);
    /* 配置设备deviceName */
    aiot_mqtt_setopt(mqtt_handle, AIOT_MQTTOPT_DEVICE_NAME, (void *)device_name);
    /* 配置设备deviceSecret */
    aiot_mqtt_setopt(mqtt_handle, AIOT_MQTTOPT_DEVICE_SECRET, (void *)device_secret);
    /* 配置网络连接的安全凭据, 上面已经创建好了 */
    aiot_mqtt_setopt(mqtt_handle, AIOT_MQTTOPT_NETWORK_CRED, (void *)&cred);
    /* 配置MQTT默认消息接收回调函数 */
    aiot_mqtt_setopt(mqtt_handle, AIOT_MQTTOPT_RECV_HANDLER, (void *)demo_mqtt_default_recv_handler);
    /* 配置MQTT事件回调函数 */
    aiot_mqtt_setopt(mqtt_handle, AIOT_MQTTOPT_EVENT_HANDLER, (void *)demo_mqtt_event_handler);

	//bytian; BEGIN
	signal(SIGPIPE, SIG_IGN);
	//create epoll
	epfd = epoll_create(16);  //bytian
	if (epfd == -1) {
		fprintf(stderr, "epoll create failed! err=%d(%s); exit(10)\n", errno, strerror(errno));
        exit(10);
	}
	//create unix socket
	listenfd = unixsvr_listen();
	if (listenfd != -1){
		//printf("xfwu---------------------44444444444444");
		epfd_epolladd(listenfd, EPOLLIN);
		
	}
	//bytian; END

    /* 与服务器建立MQTT连接 */
    res = aiot_mqtt_connect(mqtt_handle);  //bytian
    if (res < STATE_SUCCESS) {
        /* 尝试建立连接失败, 销毁MQTT实例, 回收资源 */
		//printf("xfwu---------------------555555555555555555555");
        aiot_mqtt_deinit(&mqtt_handle);
        printf("aiot_mqtt_connect failed: -0x%04X\n", -res);
        return -1;
    }
	
	
	char *tmpk="/";
	char *tmpm="/user/push";
	char *tmp = (char *) malloc(strlen(tmpk) + strlen(product_key) + strlen(tmpk) + strlen(device_name)+ strlen(tmpm));
	
	
	
	strcpy(tmp,tmpk);
	strcat(tmp,product_key);
	strcat(tmp,tmpk);
	strcat(tmp,device_name);
	strcat(tmp,tmpm);
	
    /* MQTT 订阅topic功能示例, 请根据自己的业务需求进行使用 */
     
        //char *sub_topic = "/a2Wl5a1kUzm/8000000781612294/user/push";
		char *sub_topic = tmp;
		printf("xfwu-------------subtopic successfully----------sub_topic2:-%s",sub_topic);
        res = aiot_mqtt_sub(mqtt_handle, sub_topic, NULL, 1, NULL);
        if (res < 0) {
            printf("aiot_mqtt_sub failed, res: -0x%04X\n", -res);
            return -1;
        }
    //by xfwu 20201027
	char *xfwutmpk="/sys/";	
	char *xfwutmpm="/rrpc/request/+";
	char *xfwutmp = (char *) malloc(strlen(xfwutmpk) + strlen(product_key) + strlen(tmpk) + strlen(device_name)+ strlen(xfwutmpm));
	strcpy(xfwutmp,xfwutmpk);
	strcat(xfwutmp,product_key);
	strcat(xfwutmp,tmpk);
	strcat(xfwutmp,device_name);
	strcat(xfwutmp,xfwutmpm);
    //char *sub_topic = "/sys/a2Wl5a1kUzm/8000000781612294/rrpc/request/+";
	char *xfwusub_topic = xfwutmp;
	printf("xfwu---rrpc----------subtopic successfully----------sub_topic2:-%s",xfwusub_topic);
    res = aiot_mqtt_sub(mqtt_handle, xfwusub_topic, NULL, 1, NULL);
    if (res < 0) {
        printf("aiot_mqtt_sub failed, res: -0x%04X\n", -res);
        return -1;
    }
		

    /* MQTT 发布消息功能示例, 请根据自己的业务需求进行使用 */
    /* {
        char *pub_topic = "/sys/a13FN5TplKq/mqtt_basic_demo/thing/event/property/post";
        char *pub_payload = "{\"id\":\"1\",\"version\":\"1.0\",\"params\":{\"LightSwitch\":0}}";

        res = aiot_mqtt_pub(mqtt_handle, pub_topic, (uint8_t *)pub_payload, (uint32_t)strlen(pub_payload), 0);
        if (res < 0) {
            printf("aiot_mqtt_sub failed, res: -0x%04X\n", -res);
            return -1;
        }
    } */

    /* 创建一个单独的线程, 专用于执行aiot_mqtt_process, 它会自动发送心跳保活, 以及重发QoS1的未应答报文 */
    g_mqtt_process_thread_running = 1;
    res = pthread_create(&g_mqtt_process_thread, NULL, demo_mqtt_process_thread, mqtt_handle);
    if (res < 0) {
        printf("pthread_create demo_mqtt_process_thread failed: %d\n", res);
        return -1;
    }

    /* 创建一个单独的线程用于执行aiot_mqtt_recv, 它会循环收取服务器下发的MQTT消息, 并在断线时自动重连 */
    g_mqtt_recv_thread_running = 1;
    res = pthread_create(&g_mqtt_recv_thread, NULL, demo_mqtt_recv_thread, mqtt_handle);
    if (res < 0) {
        printf("pthread_create demo_mqtt_recv_thread failed: %d\n", res);
        return -1;
    }

    /* 主循环进入休眠 */
    while (1) {
        sleep(1);
    }

    /* 断开MQTT连接, 一般不会运行到这里 */
    res = aiot_mqtt_disconnect(mqtt_handle);
    if (res < STATE_SUCCESS) {
        aiot_mqtt_deinit(&mqtt_handle);
        printf("aiot_mqtt_disconnect failed: -0x%04X\n", -res);
        return -1;
    }

    /* 销毁MQTT实例, 一般不会运行到这里 */
    res = aiot_mqtt_deinit(&mqtt_handle);
    if (res < STATE_SUCCESS) {
        printf("aiot_mqtt_deinit failed: -0x%04X\n", -res);
        return -1;
    }

    g_mqtt_process_thread_running = 0;
    g_mqtt_recv_thread_running = 0;
    pthread_join(g_mqtt_process_thread, NULL);
    pthread_join(g_mqtt_recv_thread, NULL);

    return 0;
}

