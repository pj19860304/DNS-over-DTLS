#include "session.h"

#if _WIN32
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")
#endif

#define BUFFER_SIZE          65536
#define COOKIE_SECRET_LENGTH 16
#define DNS_TIMEOUT 15 //second
#define SESSION_TIMEOUT 10 //second

int verbose = 1;
int dns_client_count = 0;
char buf[BUFFER_SIZE];
union mysockaddr remote_addr;
union mysockaddr dns_local_addr;
int dns_fd, dtls_fd;
SSL_CTX *ctx;
SSL *ssl;
session *session_list = NULL;
time_t active_time, heartbeat_time;
time_t now;
int connected = 0;

int handle_socket_error() {
	printf("[ERROR] ");
	switch (errno) {
	case EINTR:
		/* Interrupted system call.
		* Just ignore.
		*/
		printf("Interrupted system call!\n");
		return 1;
	case EBADF:
		/* Invalid socket.
		* Must close connection.
		*/
		printf("Invalid socket!\n");
		return 0;
		break;
#ifdef EHOSTDOWN
	case EHOSTDOWN:
		/* Host is down.
		* Just ignore, might be an attacker
		* sending fake ICMP messages.
		*/
		printf("Host is down!\n");
		return 1;
#endif
#ifdef ECONNRESET
	case ECONNRESET:
		/* Connection reset by peer.
		* Just ignore, might be an attacker
		* sending fake ICMP messages.
		*/
		printf("Connection reset by peer!\n");
		return 1;
#endif
	case ENOMEM:
		/* Out of memory.
		* Must close connection.
		*/
		printf("Out of memory!\n");
		return 0;
		break;
	case EACCES:
		/* Permission denied.
		* Just ignore, we might be blocked
		* by some firewall policy. Try again
		* and hope for the best.
		*/
		printf("Permission denied!\n");
		return 1;
		break;
	default:
		/* Something unexpected happened */
		printf("Unexpected error! (errno = %d)\n", errno);
		return 0;
		break;
	}
	return 0;
}

int handle_ssl_error(int code)
{
	switch (SSL_get_error(ssl, code))
	{
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_WRITE:
		/* Just try again later */
		break;
	case SSL_ERROR_WANT_READ:
		/* continue with reading */
		break;
	case SSL_ERROR_SYSCALL:
		if (!handle_socket_error())
			exit(EXIT_FAILURE);
		break;
	default:
		printf("[ERROR] SSL error!\n");
		exit(EXIT_FAILURE);
		break;
	}
	return 0;
}

void init_dns_socket()
{
	int dns_port = 53;

	dns_fd = socket(dns_local_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (dns_fd == -1)
	{
		perror("[ERROR] Failed to open UDP socket for local DNS.\n");
		exit(EXIT_FAILURE);
	}

	if (-1 == bind(dns_fd, (struct sockaddr*)&dns_local_addr, sizeof(dns_local_addr)))
	{
		if (dns_local_addr.ss.ss_family == AF_INET)
			printf("[ERROR] Failed to bind UDP socket on %s:%d, %s.\n",
			inet_ntop(AF_INET, &dns_local_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
			dns_port, strerror(errno));
		else
			printf("[ERROR] Failed to bind UDP socket on %s:%d, %s.\n",
			inet_ntop(AF_INET, &dns_local_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
			dns_port, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void init_dtls_socket()
{
	dtls_fd = socket(remote_addr.ss.ss_family, SOCK_DGRAM, 0);
	if (dtls_fd < 0)
	{
		perror("[ERROR] Failed to open UDP socket for dtls.\n");
		exit(EXIT_FAILURE);
	}
	connect(dtls_fd, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
}

int dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
	int ret = 0;
	X509* localcert = X509_new();
	BIO* bio_cert = BIO_new_file("dns.crt", "rb");
	if (!bio_cert){
		printf("[ERROR] Failed to read local cert.\n");
	}
	else {
		PEM_read_bio_X509(bio_cert, &localcert, NULL, NULL);

		X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

		ASN1_BIT_STRING *k1 = X509_get0_pubkey_bitstr(cert);
		ASN1_BIT_STRING *k2 = X509_get0_pubkey_bitstr(localcert);
		if (k1 && k2 && k1->length == k2->length && k1->length > 0 &&
			memcmp(k1->data, k2->data, (size_t)k1->length) == 0)
			ret = 1; /* accept */
	}
	BIO_set_close(bio_cert, BIO_CLOSE);
	BIO_free(bio_cert);
	X509_free(localcert);
	return ret;
}

void init_ssl_ctx()
{
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(DTLS_client_method());
	//	SSL_CTX_set_cipher_list(ctx, "AES128-SHA");

	SSL_CTX_set_verify_depth(ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
}

int create_ssl()
{
	ssl = SSL_new(ctx);

	// Create BIO, connect and set to already connected
	BIO *bio = BIO_new_dgram(dtls_fd, BIO_CLOSE);
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr.ss);

	SSL_set_bio(ssl, bio, bio);

	if (SSL_connect(ssl) < 0)
	{
		printf("[ERROR] Failed to connect server.\n");
		return 0;
	}
	
	if (verbose)
	{
		if (remote_addr.ss.ss_family == AF_INET)
		{
			printf("Connected to %s:%d.\n",
				inet_ntop(AF_INET, &remote_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
				ntohs(remote_addr.s4.sin_port));
		}
		else
		{
			printf("Connected to %s:%d.\n",
				inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
				ntohs(remote_addr.s6.sin6_port));
		}

		X509 *cer = SSL_get_peer_certificate(ssl);
		if (cer)
		{
			printf("------------------------------------------------------------\n");
#if _WIN32
			printf("%s", X509_NAME_oneline(X509_get_subject_name(SSL_get_peer_certificate(ssl)), buf, 65535));
#else
			X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)), 1, XN_FLAG_MULTILINE);
#endif

			//EVP_PKEY *pkey = X509_get_pubkey(cer);		

			printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
			printf("\n------------------------------------------------------------\n\n");
		}
	}
	connected = 1;
	return 1;
}

void reconnect()
{
	connected = 0;
	int count = 5;
	while (count > 0)
	{
		printf("Reconnect...\n");
		clear_session(&session_list);
		init_dtls_socket();
		if (create_ssl(dtls_fd))
			break;
		else
			count --;
#ifdef _WIN32
		Sleep(5000);
#else
		usleep(5000000);
#endif
	}
	if (!connected)
	{
		printf("Exit.\n");
		exit(EXIT_FAILURE);
	}
}

void show_session_count()
{
	if (verbose)
	{
		int sessioncount = get_session_count(session_list);
		if (sessioncount != dns_client_count)
		{
			dns_client_count = sessioncount;
			printf("The number of DNS clients becomes %d.\n", dns_client_count);
		}
	}
}

void start()
{
	union mysockaddr dns_from_addr;
	int ret;
	unsigned short transaction_id;
	int len;
	struct timeval timeout;
	fd_set fds;
	int maxfdp;
	session *current_session;
	socklen_t from_len = sizeof(dns_from_addr);
	memset((void *)&dns_from_addr, 0, sizeof(struct sockaddr_storage));

	init_dns_socket();
	init_dtls_socket();
	init_ssl_ctx();
	if (!create_ssl(dtls_fd))
		reconnect();

	time(&active_time);
	time(&heartbeat_time);

	while (1)
	{
		if (!connected)
		{
#ifdef _WIN32
			Sleep(1000);
#else
			usleep(1000000);
#endif
			continue;
		}
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(dns_fd, &fds);
		FD_SET(dtls_fd, &fds);
		maxfdp = dns_fd > dtls_fd ? dns_fd + 1 : dtls_fd + 1;
		ret = select(maxfdp, &fds, NULL, NULL, &timeout);
		if (ret > 0)
		{
			if (FD_ISSET(dns_fd, &fds))
			{
				len = recvfrom(dns_fd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&dns_from_addr, &from_len);
				if (len == -1)
				{
					if (dns_from_addr.ss.ss_family == AF_INET)
					{
						printf("[ERROR] Failed to receive DNS data from %s:%d, %s.\n",
							inet_ntop(AF_INET, &dns_from_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
							ntohs(dns_from_addr.s4.sin_port),
							strerror(errno));
					}
					else
					{
						printf("[ERROR] Failed to receive DNS data from %s:%d, %s.\n",
							inet_ntop(AF_INET6, &dns_from_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
							ntohs(dns_from_addr.s4.sin_port),
							strerror(errno));
					}					
				}
				else
				{
					if (verbose)
					{
						if (dns_from_addr.ss.ss_family == AF_INET)
						{
							printf("Received DNS request from %s:%d, length:%d.\n",
								inet_ntop(AF_INET, &dns_from_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
								ntohs(dns_from_addr.s4.sin_port), len);
						}
						else
						{
							printf("Received DNS request from %s:%d, length:%d.\n",
								inet_ntop(AF_INET6, &dns_from_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
								ntohs(dns_from_addr.s6.sin6_port), len);
						}
					}

					transaction_id = *(unsigned short*)buf;
					add_session(&session_list, transaction_id, dns_from_addr);
					show_session_count();

					//DTLS Send
					if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
					{
						if (verbose)
							printf("[ERROR] SSL has shutdown.\n");
						reconnect();
					}
					else
					{
						ret = SSL_write(ssl, buf, len);
						time(&active_time);
						if (ret != -1)
						{
							if (verbose)
								printf("Sent %d bytes to DTLS server.\n", (int)len);
						}
						else
						{
							handle_ssl_error(ret);
						}
					}
				}
			}
			else if (FD_ISSET(dtls_fd, &fds))
			{
				//DTLS Read
				if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
				{
					printf("[ERROR] SSL has shutdown.\n");
					reconnect();
				}
				else
				{
					len = SSL_read(ssl, buf, sizeof(buf));
					time(&active_time);
					if (len > 0)
					{
						if (verbose)
							printf("Received %d bytes from DTLS server.\n", len);
						//send to client
						transaction_id = *(unsigned short*)buf;
						current_session = get_session(session_list, transaction_id);
						if (current_session != NULL)
						{
							len = sendto(dns_fd, buf, len, 0, (struct sockaddr *)&current_session->from, sizeof(current_session->from));
							if (len == -1)
							{
								perror("[ERROR] Failed to send DNS response.\n");
							}
							else if (verbose)
							{
								if (current_session->from.ss.ss_family == AF_INET)
								{
									printf("Sent DNS Response to %s:%d.\n",
										inet_ntop(AF_INET, &current_session->from.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
										ntohs(dns_from_addr.s4.sin_port));
								}
								else
								{
									printf("Sent DNS Response to %s:%d.\n",
										inet_ntop(AF_INET6, &current_session->from.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
										ntohs(dns_from_addr.s6.sin6_port));
								}
							}
							//remove_session(&session_list, &current_session);
							remove_sessions(&session_list, transaction_id);
							if (verbose)
							{
								show_session_count();
							}
						}
					}
					else if (len == 0)
					{
						//shutdown
						if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
						{
							printf("[ERROR] SSL has shutdown.\n");
							reconnect();
						}
					}
					else
					{
						handle_ssl_error(ret);
					}
				}
			}
		}

		current_session = session_list;
		struct session *removenode = NULL;
		time(&now);
		while (current_session != NULL) {
			if (now - current_session->start_time > DNS_TIMEOUT) {
				removenode = current_session;
				current_session = current_session->next;
				remove_session(&session_list, &removenode);
				printf("[ERROR] A DNS query timed out.\n");
				continue;
			}
			else
			{
				current_session = current_session->next;
			}
		}

		time(&now);
		if (now - heartbeat_time >= 2 && now - active_time >= 2)
		{
			//Send heartbeat. Requires Heartbeat extension.
			time(&heartbeat_time);
			if (-1 != SSL_heartbeat(ssl))
			{
				time(&active_time);
			}
			else
			{
				printf("[ERROR] DTLS heartbeat failure.\n");
			}
			if (now - active_time > SESSION_TIMEOUT)
			{
				printf("[ERROR] DTLS session timed out.\n");
				reconnect();
			}
		}
	}
}

int main(int argc, char **argv)
{
	char *remote_address = "202.112.51.154";
	char *dns_address = "127.0.0.1";
	int remote_port = 853;
	int dns_port = 53;

#if _WIN32
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

	memset((void *)&dns_local_addr, 0, sizeof(struct sockaddr_storage));
	if (inet_pton(AF_INET, dns_address, &dns_local_addr.s4.sin_addr) == 1)
	{
		dns_local_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		dns_local_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
		dns_local_addr.s4.sin_port = htons(dns_port);
	}
	else if (inet_pton(AF_INET6, dns_address, &dns_local_addr.s6.sin6_addr) == 1)
	{
		dns_local_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		dns_local_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		dns_local_addr.s6.sin6_port = htons(dns_port);
	}
	else
	{
		printf("[ERROR] Local dns address: %s.\n", dns_address);
		exit(EXIT_FAILURE);
	}

	memset((void *)&remote_addr, 0, sizeof(struct sockaddr_storage));
	if (inet_pton(AF_INET, remote_address, &remote_addr.s4.sin_addr) == 1)
	{
		remote_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		remote_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
		remote_addr.s4.sin_port = htons(remote_port);
	}
	else if (inet_pton(AF_INET6, remote_address, &remote_addr.s6.sin6_addr) == 1)
	{
		remote_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
		remote_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
		remote_addr.s6.sin6_port = htons(remote_port);
	}
	else
	{
		printf("[ERROR] Remote dtls address: %s.\n", remote_address);
		exit(EXIT_FAILURE);
	}

	start();

	return 0;
}
