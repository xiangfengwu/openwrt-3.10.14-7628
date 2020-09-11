
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

#include <pthread.h>


static int verb = 0;

#define MIN_BUFSIZE 2048
#define MAX_BUFSIZE 8192

#define DEFAULT_SOCK "/var/run/aiot-demo.sock"
char *sockname = "/var/run/aiot-demo.sock";

#define READ_FULL			0
#define READ_NOTFULL		1
#define READ_HAVEERROR		2
#define READ_TIMEOUT		3
#define FAILED				1
#define OK					0



static void usage(void)
{
    printf("Usage: cunix [options] command [arguments]\n");
    printf("\n");
    printf("options:\n");
    printf("  -s <path>         Path to the socket, default: %s\n", DEFAULT_SOCK);
	printf("  -t <timeout>      timeout, default 7s\n");
	printf("  -c <shellname>    callback shell filename\n");
    printf("  -h                Print usage\n");
    printf("\n");
    printf("\n");
}


static void mylogit(const char *fmt,...)
{
	if (verb) {
		va_list args;

		va_start(args, fmt);
		vfprintf(stdout, fmt, args);
		va_end(args);
	}
}
static void myerror(const char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

}

int set_nonblock(int fd)
{
	int val;

	val = fcntl(fd, F_GETFL);
	if (val < 0) {
		myerror("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		return (-1);
	}
	if (val & O_NONBLOCK) {
		mylogit("fd %d is O_NONBLOCK", fd);
		return (0);
	}
	mylogit("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1) {
		myerror("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		return (-1);
	}
	return (0);
}

int read_sockdata(int sockfd, char *readbuf, int sizeofbuf, int *status)  //bytian
{	//when read fully;     *status=READ_FULL
	//when read not fully; *status=READ_NOTFULL
	//have error,          *status=READ_HAVEERROR
	int nread = -1;
	int totalread = 0;
	int full = 1;
	if(!readbuf) {
		myerror(" read_sockdata ptr is empty ");
		return 0;
	}
	else{ //if have any data incoming
		//logit("\tdata is comming, u can read !\n");
		int sock_closed = 0;  //check socket have closed
		char * pbuff = readbuf;
		int left = sizeofbuf;
		//myerror("read_sockdata(%d): begin: free dataspace to read:%d\n", sockfd, sizeofbuf); //for debug
		while(left > 0 ) { //bytian; exit the loop: 1. left<=0(recv buf is full); 2. input buffer is empty
			nread = read(sockfd, pbuff, left);  //API read();
			if (nread < 0) {  //have errors, 分析处理不同的错误
				if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK){ //errors: maybe input buffer is empty
					//kernel socket input buffer is empty
					myerror("read_sockdata(%d): warning: no more data! totalread:%d\n", sockfd, totalread);
					full = 0;
					goto final;
				}
				else{  //have any other errors. close local socket 
 					myerror("read_sockdata(%d): error: should close socket .\n", sockfd);
					sock_closed = 1;
					goto freeresource;
				}
			}
			else if( nread == 0){  //errors: maybe peer socket closed or have no data to read
				if (errno != 0) {
					myerror("read_sockdata(%d): error: peer closed!\n", sockfd);
					sock_closed = 1;
					goto freeresource;
				}
				else {
					full = 0;
					goto final;
				}
				
			}
			else {  //have no error
				//myerror("read_sockdata: [ %s ]\n", pbuff);  //for debug
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


static int connect_to_server(const char *sock_name)
{
	int sock;
	struct sockaddr_un	sa_un;
	
	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un, 
			strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		fprintf(stderr, "cunix: proxycli probably not started (Error: %s)\n", strerror(errno));
		exit(7);
	}

	set_nonblock(sock);

	return sock;
}

static size_t send_request(int sock, const char *request)
{
	size_t	len;
    ssize_t written;
		
	len = 0;
	while (len != strlen(request)) {
		written = write(sock, (request + len), strlen(request) - len);
		if (written == -1) {
			fprintf(stderr, "Write to peer failed: %s\n", strerror(errno));
			exit(8);
		}
		len += written;
	}

	return len;
}

int send_recv(char *paydata, char *callback, int timeout, char *recvbuf, int recvlen, int *status)
{
	fd_set readfds;
	struct timeval	tmo;
	int	sockfd, nfds, ret;
	int len;
	char *request = NULL;

	if (callback) {
		asprintf(&request, "%s%s%s", paydata, "\t\r\n\t\r\n", callback);
		if (!request) {
			mylogit("malloc failed!\n");
			exit(2);
		}
	}

	sockfd = connect_to_server(sockname);

	if (request) {
		len = send_request(sockfd, request);
	}
	else {  //there is no callback; only send strcmd
		len = send_request(sockfd, paydata);
	}
	mylogit("sent[%d] % bytes\n", sockfd, len);

	len  = 0;
	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);

	tmo.tv_sec = timeout;  //bytian
	tmo.tv_usec = 0;
	nfds = sockfd + 1;

	nfds = select(nfds, &readfds, NULL, NULL, &tmo);
	if (nfds > 0) {
		/** We don't have to use FD_ISSET() because there was only one fd. */
		len = read_sockdata(sockfd, recvbuf, recvlen, status);
		if (len <= 0) {
			snprintf(recvbuf, recvlen, "%s", "unknown");
		}
	}
	else if (nfds == 0) {
		mylogit("%s:: Timed out reading data via select() from peer", __FUNCTION__);
		if (status)
			*status = READ_TIMEOUT;
		snprintf(recvbuf, recvlen, "%s", "timedout");
		/* FIXME */
		//goto freeresource;
	}
	else if (nfds < 0) {
		mylogit("%s:: Error reading data via select() from peer: %s", __FUNCTION__, strerror(errno));
		if (status)
			*status = READ_HAVEERROR;
		snprintf(recvbuf, recvlen, "%s", "error");
		/* FIXME */
		//goto freeresource;
	}


freeresource:  //we will always close socket whether have error or not
	if (request)
		free(request);
	close(sockfd);
	return len;
}

int cmd_hdl_cmdparam(char *paydata, char *callback, int timeout)   //bytian
{
	char recvbuffer[MAX_BUFSIZE] = {0};
	int	ret = 1;
	int status = 0;

	ret = send_recv(paydata, callback, timeout, recvbuffer, MAX_BUFSIZE, &status);

	printf("%s", recvbuffer);  //bytian
	if (status <= READ_NOTFULL) {
		if (strstr(recvbuffer, "error") )
			status = READ_HAVEERROR;
		else
			status = 0;
	}

	return status;

}

int main(int argc, char **argv)
{
	/* Init configuration */
	int ret = 0;
    extern int optind; int check = 1;
    int c; int i;
	int timeout = 1;
	unsigned char paydata[8192];
	unsigned char *callback = NULL;
	//char cmd[512];

    while (-1 != (c = getopt(argc, argv, "s:t:c:fvh"))) {
        switch(c) {
            case 's':
		    	sockname = optarg;
                break;
            case 't':
		    	timeout = atoi(optarg);
                break;
			case 'c':
				callback = optarg;
				break;
			case 'v':
				verb = 1;
				break;
			case 'f':
				check = 0;
				break;
			case 'h':
            default:
                usage();
                exit(1);
                break;
        }
    }

	mylogit("sockname=%s\n", sockname);

    if ((argc - optind) <= 0) {
	    myerror("senddata-empty");
	    exit(2);
    }

	int rlen, curlen = 0 , leftlen = 8192-1;
	for (i=optind; i < argc; i++) {
		if (i < argc-1)
			rlen = snprintf(paydata + curlen, leftlen, "%s ", argv[i]);
		else
			rlen = snprintf(paydata + curlen, leftlen, "%s", argv[i]);
		curlen += rlen;
		leftlen -= rlen;	
	}

	ret = cmd_hdl_cmdparam(paydata, callback, timeout);

	exit(ret);

}



