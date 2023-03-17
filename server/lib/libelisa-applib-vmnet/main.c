/*
 *
 * Copyright 2023 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <rvs.h>

int rvs_lock_init(char *lock)
{
	unsigned int i;
	for (i = 0; i < RVS_LOCK_BUF_SIZE; i++)
		lock[i] = 0;
	return 0;
}

int rvs_lock_destroy(char *lock)
{
	(void) lock;
	return 0;
}

int rvs_wrlock(char *lock)
{
	short c = __atomic_add_fetch(&(((short *) lock)[2]), 1, __ATOMIC_ACQ_REL);
	while (c != (short)((((short *) lock)[0]) + 1)) asm volatile ("nop");
	return 0;
}

int rvs_wrunlock(char *lock)
{
	__atomic_add_fetch(&(((short *) lock)[0]), 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&(((short *) lock)[1]), 1, __ATOMIC_RELAXED);
	return 0;
}

int rvs_rdlock(char *lock)
{
	short c = __atomic_add_fetch(&(((short *) lock)[2]), 1, __ATOMIC_ACQ_REL);
	while (c != (short)((((short *) lock)[1]) + 1)) asm volatile ("nop");
	__atomic_add_fetch(&(((short *) lock)[1]), 1, __ATOMIC_RELAXED);
	return 0;
}

int rvs_rdunlock(char *lock)
{
	__atomic_add_fetch(&(((short *) lock)[0]), 1, __ATOMIC_RELAXED);
	return 0;
}

int rvs_notify(struct rvs *vs __attribute__((unused)),
	       unsigned short p __attribute__((unused)),
	       unsigned short q __attribute__((unused)))
{
	return 0;
}

struct rvs *vs = (void *) 0;
unsigned short port_id = 0xffff;

static long elisa_app_net_work(unsigned short dummy __attribute__((unused)), unsigned short qid)
{
	rvs_fwd(vs, port_id, qid, 512);
	return 0;
}

long entry_function(long rdi,
		    long rsi,
		    long rdx __attribute__((unused)),
		    long rcx __attribute__((unused)),
		    long r8 __attribute__((unused)),
		    long r9 __attribute__((unused)))
{
	return elisa_app_net_work((unsigned short) rdi, (unsigned short) rsi);
}
