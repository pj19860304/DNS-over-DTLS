#include "session.h"

void printList(session *session_list)
{
    session* current = session_list;
    if(NULL == current)
    {
        printf("session count = 0\n");
    }
    else
    {
        while(NULL != current)
        {
            if(current->client_addr.ss.ss_family == 2)
            {
                printf("ip:%s ,port:%d,ssl_status:%d\n",
                       inet_ntop(AF_INET, &current->client_addr.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
                       ntohs(current->client_addr.s4.sin_port),
                       current->ssl_status);
            }
            else
            {
                printf("ip:%s ,port:%d,ssl_status:%d\n",
                       inet_ntop(AF_INET6, &current->client_addr.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
                       ntohs(current->client_addr.s6.sin6_port),
                       current->ssl_status);
            }
            current = current->next;
        }
        printf("\n");
    }
}

int get_session_count(session *session_list)
{
    int count = 0;
    session* pNode = session_list;
    while(NULL != pNode)
    {
        count++;
        pNode = pNode->next;
    }
    return count;
}

session *get_session(session *session_list, union mysockaddr addr)
{
    session *current = session_list;

    if(NULL == session_list)
    {
        return NULL;
    }

    while((memcmp(&(current->client_addr.ss), &addr, sizeof(union mysockaddr)) != 0) && (NULL != current->next))
    {
        current = current->next;
    }

    if((memcmp(&(current->client_addr.ss), &addr, sizeof(union mysockaddr)) != 0) && (current != NULL))
    {
        return NULL;
    }

    return current;
}

session *add_session(session **psession_list, union mysockaddr server_addr,
                     union mysockaddr client_addr, SSL *ssl, BIO *for_reading,
                     BIO *for_writing, int dns_fd)
{
    session *insert;
    insert = (session *)malloc(sizeof(session));

    memset(insert, 0, sizeof(session));
    memcpy(&insert->server_addr, &server_addr, sizeof(server_addr));
    memcpy(&insert->client_addr, &client_addr, sizeof(client_addr));
    insert->ssl = ssl;
    insert->ssl_status = SSL_STATUS_HANDSHAKE;
    insert->for_reading = for_reading;
    insert->for_writing = for_writing;
    insert->dns_fd = dns_fd;

    if(*psession_list != NULL)
        (*psession_list)->prev = insert;
    insert->next = *psession_list;
    *psession_list = insert;

    return insert;
}

int remove_session(session **psession_list, session **psession)
{
    if((*psession)->next != NULL)
        (*psession)->next->prev = (*psession)->prev;
    if((*psession)->prev != NULL)
        (*psession)->prev->next = (*psession)->next;
    else
        *psession_list = (*psession)->next;
#if _WIN64
	closesocket((*psession)->dns_fd);
#else
    close((*psession)->dns_fd);
#endif
    SSL_free((*psession)->ssl);
    free(*psession);
    return 1;
}
