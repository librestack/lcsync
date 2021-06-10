/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "mdex.h"
#include <assert.h>
#include <string.h>
#include <sys/param.h>

struct bnode {
	struct bnode *l;
	struct bnode *r;
	size_t klen;
	size_t vlen;
	void *key;
	void *val;
};

char blah[1024];
struct bnode *last = (struct bnode *)blah;
size_t sz;

//static int mdex_put_type_file(struct in6_addr *addr, char *fpath ... );

int mdex_del(struct in6_addr *addr)
{
	return 0;
}

int mdex_get(struct in6_addr *addr, void **data, size_t *size, char *type)
{
	return 0;
}

/* for MDEX_FILE, mmap the file, store the mtree and fstat 
 * for MDEX_MEM, store mtree and ptr + size
 * for MDEX_SUBTREE, point to the mtree + node */
int mdex_put(struct in6_addr *addr, void *data, size_t size, char type)
{
	/* MDEX_FILE
	 *
	 * key = addr
	 * val = fpath
	 *
	 *  +++
	 *
	 *  key = fpath
	 *  val = mtree, fstat
	 *
	 *  -------------
	 *  MDEX_MEM
	 *
	 *  key = addr
	 *  val = ptr, size, mtree
	 *
	 *  no additional data needed
	 *  -------------
	 *  MDEX_SUBTREE
	 *
	 *  key = addr
	 *  val = fpath, node
	 *
	 *  +++
	 *
	 *  key = fpath
	 *  val = mtree, fstat
	 */

	struct s_s {
		char   type;
		void * data;
		size_t size;
	} s;

	s.type = type;
	s.size = size;
	memcpy(&s.data, data, size);

	return 0;
}
