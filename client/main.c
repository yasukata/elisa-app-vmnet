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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <assert.h>

#include <sys/sysinfo.h>

#include <libelisa.h>
#include <libelisa_extra/irq.h>

static unsigned long prev_yield = 0;

#define YIELD_PERIOD_NS (10000000UL) // 10ms

static void do_io(int queue_id)
{
	unsigned long t;
	{
		struct timespec ts;
		assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
		t = ts.tv_sec * 1000000000UL + ts.tv_nsec;
	}
	if (YIELD_PERIOD_NS < t - prev_yield) {
		sched_yield();
		prev_yield = t;
	}
	elisa_disable_irq_if_enabled();

	assert(!elisa_gate_entry(0, queue_id, 0, 511, 0, 0));
}

void dpdk_rvif_io_hook(void *p __attribute__((unused)),
		       unsigned short q,
		       void *b __attribute__((unused)),
		       unsigned short n __attribute__((unused)),
		       unsigned short c __attribute__((unused)),
		       char is_tx,
		       char is_post)
{
	if (is_tx) {
		if (is_post)
			do_io(q);
	}
}

static int elisa_client_cb(int sockfd __attribute__((unused)))
{
	return 0;
}

#define MAX_ELISA_APP_VMNET_CPU (64)

static int elisa_fd[MAX_ELISA_APP_VMNET_CPU];

#define ENV_APP_VMNET_SERVER_STR "ELISA_APP_VMNET_SERVER"

int dpdk_rvif_setup_hook(void *d __attribute__((unused)), char is_exit)
{
	if (!is_exit) {
		char *server_str;
		int server_port = 0;
		assert(getenv(ENV_APP_VMNET_SERVER_STR));
		assert((server_str = strdup(getenv(ENV_APP_VMNET_SERVER_STR))) != NULL);
		{
			size_t i, l = strlen(server_str);
			for (i = 0; i < l; i++) {
				if (server_str[i] == ':') {
					server_str[i] = '\0';
					assert(i + 1 < l);
					sscanf(&server_str[i + 1], "%d", &server_port);
				}
			}
		}
		assert(server_port);
		{
			int num_cpus = get_nprocs();
			{
				int i;
				for (i = 0; i < MAX_ELISA_APP_VMNET_CPU; i++) {
					if (i < num_cpus) {
						cpu_set_t cs;
						CPU_ZERO(&cs);
						CPU_SET(i, &cs);
						assert(sched_setaffinity(gettid(), sizeof(cs), &cs) == 0);
						assert((unsigned int) i == ({ unsigned int cpu; assert(!getcpu(&cpu, NULL)); cpu; }));
						assert((elisa_fd[i] = elisa_client(server_str,
										   server_port,
										   elisa_client_cb)) >= 0);
						printf("elisa_fd[%d]: %d\n", i, elisa_fd[i]);
					} else
						elisa_fd[i] = -1;
				}
			}
			{
				cpu_set_t cs;
				CPU_ZERO(&cs);
				{
					int i;
					for (i = 0; i < num_cpus; i++)
						CPU_SET(i, &cs);
					assert(sched_setaffinity(gettid(), sizeof(cs), &cs) == 0);
				}
			}
		}
		free(server_str);
	} else {
		int i;
		for (i = 0; i < MAX_ELISA_APP_VMNET_CPU; i++) {
			if (elisa_fd[i] != -1) {
				close(elisa_fd[i]);
				elisa_fd[i] = -1;
			}
		}
	}

	return 0;
}
