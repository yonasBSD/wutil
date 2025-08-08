/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025, Muhammad Saheed <saheed@FreeBSD.org>
 */

#ifndef ARRAY_H
#define ARRAY_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#define ARRAY(name, type)        \
	struct name {            \
		type *items;     \
		size_t len, cap; \
	}

#define ARRAY_INITIALIZER(name) ((struct name) { NULL, 0, 0 })

#define ARRAY_FREE(array)                        \
	do {                                     \
		if ((array) == NULL)             \
			break;                   \
		free((array)->items);            \
		(array)->items = NULL;           \
		(array)->len = (array)->cap = 0; \
	} while (0)

#define ARRAY_APPEND(name, array, item) name##_append(array, item)
#define ARRAY_APPEND_PROTOTYPE(name) \
	bool name##_append(struct name *array, typeof(*array->items) item);
#define ARRAY_APPEND_DEFINITION(name)                                          \
	bool name##_append(struct name *array, typeof(*array->items) item)     \
	{                                                                      \
		assert(array != NULL);                                         \
                                                                               \
		if (array->len == array->cap) {                                \
			size_t new_cap = array->cap == 0 ? 1 : array->cap * 2; \
			void *new_items = reallocarray(array->items, new_cap,  \
			    sizeof(*(array->items)));                          \
                                                                               \
			if (new_items == NULL)                                 \
				return (false);                                \
                                                                               \
			array->items = new_items;                              \
			array->cap = new_cap;                                  \
		}                                                              \
                                                                               \
		array->items[array->len++] = item;                             \
                                                                               \
		return (true);                                                 \
	}
#define ARRAY_APPEND_STATIC(name) static ARRAY_APPEND_DEFINITION(name)

#endif /* !ARRAY_H */
