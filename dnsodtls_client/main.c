#include "session.h"

#define BUFFER_SIZE          65536
#define COOKIE_SECRET_LENGTH 16

int verbose = 1;
int veryverbose = 1;

int dns_client_count = 0;

int handle_socket_error()
{
    printf("Error: ");
    switch (errno)
    {
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

int handle_ssl_error(SSL *ssl, int code, char* buf)
{
    int a = SSL_get_error(ssl, code);
    switch (a)
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
        printf("Socket write error: ");
        if (!handle_socket_error()) exit(1);
        break;
    case SSL_ERROR_SSL:
        printf("SSL write error: ");
        printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, code));
        exit(1);
        break;
    default:
        printf("Unexpected error while writing!\n");
        exit(1);
        break;
    }
    return 0;
}

void start(char *remote_address, int remote_port, char *dns_address)
{
    union mysockaddr remote_addr, local_addr, dns_from_addr, dns_local_addr;
    char buf[BUFFER_SIZE];
    char addrbuf[INET6_ADDRSTRLEN];
    int dtls_fd;
    socklen_t len;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    struct timeval timeout;
#if WIN32
    WSADATA wsaData;
#endif
    memset((void *) &remote_addr, 0, sizeof(struct sockaddr_storage));
    memset((void *) &local_addr, 0, sizeof(struct sockaddr_storage));

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
        return;
    }

    if (inet_pton(AF_INET, dns_address, &dns_local_addr.s4.sin_addr) == 1)
    {
        dns_local_addr.s4.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
        dns_local_addr.s4.sin_len = sizeof(struct sockaddr_in);
#endif
        dns_local_addr.s4.sin_port = htons(53);
    }
    else if (inet_pton(AF_INET6, remote_address, &dns_local_addr.s6.sin6_addr) == 1)
    {
        dns_local_addr.s6.sin6_family = AF_INET6;
#ifdef HAVE_SIN6_LEN
        dns_local_addr.s6.sin6_len = sizeof(struct sockaddr_in6);
#endif
        dns_local_addr.s6.sin6_port = htons(53);
    }
    else
    {
        return;
    }

#ifdef WIN32
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    dtls_fd = socket(remote_addr.ss.ss_family, SOCK_DGRAM, 0);
    if (dtls_fd < 0)
    {
        exit(-1);
    }

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_cipher_list(ctx, "AES128-SHA");

    if (!SSL_CTX_use_certificate_file(ctx, "client.pem", SSL_FILETYPE_PEM))
        printf("ERROR: no certificate found!\n");

    if (!SSL_CTX_use_PrivateKey_file(ctx, "client.pem", SSL_FILETYPE_PEM))
        printf("ERROR: no private key found!\n");

    if (!SSL_CTX_check_private_key (ctx))
        printf("ERROR: invalid private key!\n");

    SSL_CTX_set_verify_depth (ctx, 2);
    SSL_CTX_set_read_ahead(ctx, 1);

    ssl = SSL_new(ctx);

    /* Create BIO, connect and set to already connected */
    bio = BIO_new_dgram(dtls_fd, BIO_CLOSE);
    if (remote_addr.ss.ss_family == AF_INET)
    {
        connect(dtls_fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in));
    }
    else
    {
        connect(dtls_fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in6));
    }
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr.ss);

    SSL_set_bio(ssl, bio, bio);

    if (SSL_connect(ssl) < 0)
    {
        perror("Error: failed to connect DTLS server\n");
        printf("%s\n", ERR_error_string(ERR_get_error(), buf));
        exit(-1);
    }

    /* Set and activate timeouts */
    timeout.tv_sec = 0;
    timeout.tv_usec = 5;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    if (verbose)
    {
        if (remote_addr.ss.ss_family == AF_INET)
        {
            printf ("Connected to %s:%d\n",
                    inet_ntop(AF_INET, &remote_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
                    ntohs(remote_addr.s4.sin_port));
        }
        else
        {
            printf ("Connected to %s:%d\n",
                    inet_ntop(AF_INET6, &remote_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
                    ntohs(remote_addr.s6.sin6_port));
        }
    }

    if (veryverbose && SSL_get_peer_certificate(ssl))
    {
        printf ("------------------------------------------------------------\n");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
                              1, XN_FLAG_MULTILINE);
        printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
        printf ("\n------------------------------------------------------------\n\n");
    }


    ////////////DNS Server//////////
    session *session_list = NULL;
    int id, ret;
    socklen_t from_len = sizeof(union mysockaddr);

    int dns_fd = socket(dns_local_addr.ss.ss_family, SOCK_DGRAM, 0);
    if(dns_fd == -1)
    {
        perror("Error: failed to open UDP socket for DTLS\n");
        exit(EXIT_FAILURE);
    }

    if(-1 == bind(dns_fd, (struct sockaddr*)&dns_local_addr, sizeof(dns_local_addr)))
    {
        if(dns_local_addr.ss.ss_family == AF_INET)
            printf("Error: failed to bind UDP socket on %s:53\n",
                   inet_ntop(AF_INET, &dns_local_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
        else
            printf("Error: failed to bind UDP socket on %s:53\n",
                   inet_ntop(AF_INET, &dns_local_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
        exit(EXIT_FAILURE);
    }

    struct timeval dns_timeout;


    fd_set fds;
    FD_ZERO(&fds);
    while(1)
    {
        FD_SET(dns_fd, &fds);
        dns_timeout.tv_sec = 0;
        dns_timeout.tv_usec = 5;

        ret = select(dns_fd + 1, &fds, NULL, NULL, &dns_timeout);
        if(ret > 0 && FD_ISSET(dns_fd, &fds))
        {
            len = recvfrom(dns_fd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&dns_from_addr, &from_len);
            if(len == -1)
            {
                if(dns_from_addr.ss.ss_family == AF_INET)
                {
                    printf("Error: failed to receive data from %s\n",
                           inet_ntop(AF_INET, &dns_from_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
                }
                else
                {
                    printf("Error: failed to receive data from %s\n",
                           inet_ntop(AF_INET6, &dns_from_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
                }
                SSL_shutdown(ssl);
                close(dns_fd);
                exit(EXIT_FAILURE);
            }
            else
            {
                if(dns_from_addr.ss.ss_family == AF_INET)
                {
                    printf("Received DNS request from %s\n",
                           inet_ntop(AF_INET, &dns_from_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
                }
                else
                {
                    printf("Received DNS request from %s\n",
                           inet_ntop(AF_INET6, &dns_from_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
                }
            }

            //
            id = *(unsigned short*)buf;
            add_session(&session_list, id, dns_from_addr);

            int sessioncount = get_session_count(session_list);
            if(sessioncount != dns_client_count)
            {
                dns_client_count = sessioncount;
                printf("The number of DNS clients becomes %d\n", dns_client_count);
            }

            //DTLS Send
            if(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
            {
                printf("Error: SSL has shutdown\n");
            }
            else
            {
                ret = SSL_write(ssl, buf, len);
                if(ret != -1)
                {
                    printf("Sent %d bytes to DTLS server\n", (int) len);
                }
                else
                {
                    handle_ssl_error(ssl, ret, buf);
                }
            }
        }

        //DTLS Read
        if(!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
        {
            ret = SSL_read(ssl, buf, sizeof(buf));
            if(ret != -1)
            {
                printf("Received %d bytes from DTLS server\n", len);
                //send to client
                id = *(unsigned short*)buf;
                session *current_session = get_session(session_list, id);
                if(current_session != NULL)
                {
                    from_len =  sizeof(current_session->from);

                    len = sendto(dns_fd, buf, len, 0, (struct sockaddr *)&current_session->from, from_len);
                    if(len == -1)
                    {
                         printf("Error: failed to send DNS response\n");
                        //  exit(EXIT_FAILURE);
                    }
                    else
                    {
                        if(current_session->from.ss.ss_family == AF_INET)
                        {
                            printf("Sent DNS Response to %s\n",
                                   inet_ntop(AF_INET, &current_session->from.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN));
                        }
                        else
                        {
                            printf("Sent DNS Response to %s\n",
                                   inet_ntop(AF_INET6, &current_session->from.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN));
                        }
                    }
                    remove_session(&session_list, &current_session);
                    int sessioncount = get_session_count(session_list);
                    if(sessioncount != dns_client_count)
                    {
                        dns_client_count = sessioncount;
                        printf("The number of DNS clients becomes %d\n", dns_client_count);
                    }
                }
            }
            else
            {
                handle_ssl_error(ssl, ret, buf);
            }
        }

        /* Send heartbeat. Requires Heartbeat extension. */
        //SSL_heartbeat(ssl);
    }
}

int main(int argc, char **argv)
{
    char *remote_address = "::1";
    char *dns_server_address = "127.0.0.1";
    int remote_port = 853;

    start(remote_address, remote_port, dns_server_address);

    return 0;
}
