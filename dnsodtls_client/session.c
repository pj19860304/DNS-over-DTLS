#include "session.h"

void printList(session *session_list)
{
	session* current = session_list;
	if (NULL == current)
	{
		printf("session count = 0\n");
	}
	else
	{
		while (NULL != current)
		{
			if (current->from.ss.ss_family == 2)
			{
				printf("ip:%s ,port:%d\n",
					inet_ntop(AF_INET, &current->from.s4.sin_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(current->from.s4.sin_port));
			}
			else
			{
				printf("ip:%s ,port:%d\n",
					inet_ntop(AF_INET6, &current->from.s6.sin6_addr, addrbuf, INET6_ADDRSTRLEN),
					ntohs(current->from.s6.sin6_port));
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
	while (NULL != pNode)
	{
		count++;
		pNode = pNode->next;
	}
	return count;
}

session *get_session(session *session_list, unsigned short id)
{
	session *current = session_list;

	if (NULL == current)
	{
		return NULL;
	}

	while ((current->id != id) && (NULL != current->next))
	{
		current = current->next;
	}

	if ((current->id != id) && (current != NULL))
	{
		return NULL;
	}
	return current;
}

int add_session(session **psession_list, unsigned short id, union mysockaddr from)
{
	session *insert;
	insert = (session *)malloc(sizeof(session));
	memset(insert, 0, sizeof(session));
	insert->id = id;
	insert->from = from;
	time(&insert->start_time);
	insert->prev = NULL;
	if (*psession_list != NULL)
		(*psession_list)->prev = insert;
	insert->next = *psession_list;
	*psession_list = insert;
	return 1;
}

int remove_session(session **psession_list, session **psession)
{
	if ((*psession)->next != NULL)
		(*psession)->next->prev = (*psession)->prev;
	if ((*psession)->prev != NULL)
		(*psession)->prev->next = (*psession)->next;
	else
		*psession_list = (*psession)->next;
	free(*psession);
	return 1;
}

void clear_session(session **psession_list)
{
	while (NULL != *psession_list)
	{
		*psession_list = (*psession_list)->next;
		session *current = *psession_list;
		free(current);
	}
}
