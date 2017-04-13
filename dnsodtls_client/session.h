#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#define in_port_t u_short
#define ssize_t int
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#endif

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>


union mysockaddr
{
	struct sockaddr_storage ss;
	struct sockaddr_in6 s6;
	struct sockaddr_in s4;
};

typedef struct session
{
	unsigned short id;
	union mysockaddr from;
	time_t start_time;
	struct session *next;
	struct session *prev;
} session;

char addrbuf[INET6_ADDRSTRLEN];

void printList(session *session_list);
int get_session_count(session *session_list);
session *get_session(session *session_list, unsigned short id);
int add_session(session **psession_list, unsigned short id, union mysockaddr from);
int remove_session(session **psession_list, session **psession);
void clear_session(session **psession_list);

