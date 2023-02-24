/*
 * liblist.h - list utility functions header file
 *
 * Copyright (C) 2018 iopsys Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef LIBLIST_H
#define LIBLIST_H

#include <libubox/list.h>


/**
 * list_split - split a list into two sublists.
 * @head:	pointer to list head
 * @second:	pointer to the right sublist
 */
int list_split(struct list_head *head, struct list_head *second);

/**
 * list_merge - merge two lists.
 * @priv:	opaque private data passed by caller
 * @a:		pointer to first list
 * @b:		pointer to second list
 * @cmp:	comparator function pointer, which decides relative ordering
 *		between two list elements during the merge
 */
void list_merge(void *priv, struct list_head *a, struct list_head *b,
		int (*cmp)(void *priv, struct list_head *x, struct list_head *y));

/**
 * merge_sort - merge sort a list.
 * @priv:	opaque private data passed by caller
 * @head:	pointer to list head
 * @cmp:	comparator function pointer, which decides relative ordering
 *		between two list elements during the sort.
 */
void merge_sort(void *priv, struct list_head *head,
		int (*cmp)(void *priv, struct list_head *x, struct list_head *y));

#ifndef list_sort
#define list_sort	merge_sort
#endif

#endif /* LIBLIST_H */
