/*
 * liblist.c - implements list utility functions
 *
 * Copyright (C) 2018 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <libubox/list.h>

#define list_singular(l)	((l)->next->next == (l))

int list_split(struct list_head *head, struct list_head *second)
{
	struct list_head *fast, *slow;
	int cnt = 0;

	if (list_empty(head) || list_singular(head))
		return cnt;

	fast = head;
	list_for_each(slow, head) {
		cnt++;
		fast = fast->next;
		if (fast->next == head)
			break;

		fast = fast->next;
		if (fast->next == head)
			break;
	}

	second->next = slow->next;
	second->prev = fast;
	fast->next = second;
	slow->next->prev = second;

	head->prev = slow;
	slow->next = head;

	return cnt;
}

void list_merge(void *priv, struct list_head *a, struct list_head *b,
		int (*cmp)(void *priv, struct list_head *x, struct list_head *y))
{
	struct list_head *p;

	/* trivial when one sublist is empty */
	if (list_empty(b))
		return;

	if (list_empty(a)) {
		while (!list_empty(b))
			list_move_tail(b->next, a);

		return;
	}

	p = a;
	while (p->next != a && !list_empty(b)) {
		if (cmp(priv, p->next, b->next) <= 0)
			p = p->next;
		else
			list_move(b->next, p);
	}

	/* merge leftover from right sublist, if any */
	if (p->next == a) {
		while (!list_empty(b))
			list_move_tail(b->next, a);
	}
}

void merge_sort(void *priv, struct list_head *head,
		int (*cmp)(void *priv, struct list_head *x, struct list_head *y))
{
	struct list_head right;

	INIT_LIST_HEAD(&right);

	if (list_empty(head) || list_singular(head))
		return;

	list_split(head, &right);

	merge_sort(priv, head, cmp);
	merge_sort(priv, &right, cmp);

	list_merge(priv, head, &right, cmp);
}
