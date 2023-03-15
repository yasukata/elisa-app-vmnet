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

#include <rvs.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#include <time.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <dlfcn.h>

#include <libelisa.h>
#include <libelisa_extra/map.h>

#define BASE_GPA (1UL << 37) /* TODO: ensure no-overlap with others */

#define ENV_APPLIB_FILE_STR "ELISA_APPLIB_FILE"
#define ENV_APP_VMNET_MEM_STR "ELISA_APP_VMNET_MEM"
#define ENV_APP_VMNET_USR_STR "ELISA_APP_VMNET_USR"

static struct in_addr user_addr[RVS_MAX_PORT] = { { 0xffffffff /* driver domain */ }, };
static uint64_t vif_mem_paddr[RVS_MAX_PORT] = { 0 };
static size_t vif_mem_size[RVS_MAX_PORT] = { 0 };
static unsigned int shm_cnt = 0, user_cnt = 0;

static struct rvs *vs = NULL; /* exposed to guest */

int elisa__server_exit_cb(uint64_t *user_any __attribute__((unused)))
{
	return 0;
}

int elisa__server_cb(int sockfd,
		    uint64_t *user_any __attribute__((unused)),
		    struct elisa_map_req **map_req,
		    int *map_req_cnt,
		    uint64_t *entry_function)
{
	void *handle = NULL;
	int map_req_num = 0;

	{
		const char *filename;
		assert((filename = getenv(ENV_APPLIB_FILE_STR)) != NULL);
		assert(!elisa_create_program_map_req(filename,
						    BASE_GPA,
						    &handle,
						    map_req,
						    map_req_cnt,
						    &map_req_num));
	}

	assert(handle);
	assert(((void *)(*entry_function = (uint64_t) dlsym(handle, "entry_function"))) != NULL);

	{
		{
			uintptr_t *__vs;
			assert((__vs = dlsym(handle, "vs")) != NULL);
			*(__vs) = (uintptr_t) vs;
		}
		{ /* current implementation assumes 1 vif per vm */
			unsigned long *__port_id;
			assert((__port_id = dlsym(handle, "port_id")) != NULL);
			{
				struct sockaddr_in sin;
				socklen_t len = sizeof(sin);
				assert(!getpeername(sockfd, (struct sockaddr *) &sin, &len));
				assert(len == sizeof(sin));
				{
					int i;
					for (i = 0; i < RVS_MAX_PORT; i++) {
						if (!memcmp(&user_addr[i], &sin.sin_addr, sizeof(user_addr[i])))
							break;
					}
					assert(i != RVS_MAX_PORT); // must be in config
					*__port_id = i;
				}
			}
		}
	}

	{
		unsigned int i;
		for (i = 0; i < shm_cnt; i++) {
			size_t j;
			for (j = 0; j < (vif_mem_size[i] / 0x1000); j++) {
				if (*map_req_cnt == map_req_num) {
					map_req_num *= 2;
					assert((*map_req = realloc(*map_req, sizeof(struct elisa_map_req) * map_req_num)) != NULL);
				}
				(*map_req)[*map_req_cnt].dst_gpa = 0x1000 * *map_req_cnt + BASE_GPA;
				(*map_req)[*map_req_cnt].dst_gva = (uint64_t) vs->port[i].vif + 0x1000 * j;
				(*map_req)[*map_req_cnt].src_gxa = vif_mem_paddr[i] + 0x1000 * j;
				(*map_req)[*map_req_cnt].flags = ELISA_MAP_REQ_FLAGS_SRC_GPA;
				(*map_req)[*map_req_cnt].level = 1;
				(*map_req)[*map_req_cnt].pt_flags = PT_P | PT_W | PT_U;
				(*map_req)[*map_req_cnt].ept_flags = EPT_R | EPT_W | /* EPT_X |*/ EPT_U | EPT_MT;
				(*map_req_cnt)++;
			}
		}
	}

	{
		size_t i;
		for (i = 0; i < ((sizeof(struct rvs) / 0x1000) + 1); i++) {
			if (*map_req_cnt == map_req_num) {
				map_req_num *= 2;
				assert((*map_req = realloc(*map_req, sizeof(struct elisa_map_req) * map_req_num)) != NULL);
			}
			(*map_req)[*map_req_cnt].dst_gpa = 0x1000 * *map_req_cnt + BASE_GPA;
			(*map_req)[*map_req_cnt].dst_gva = (uint64_t) vs + 0x1000 * i;
			(*map_req)[*map_req_cnt].src_gxa = (uint64_t) vs + 0x1000 * i;
			(*map_req)[*map_req_cnt].flags = 0;
			(*map_req)[*map_req_cnt].level = 1;
			(*map_req)[*map_req_cnt].pt_flags = PT_P | PT_W | PT_U;
			(*map_req)[*map_req_cnt].ept_flags = EPT_R | EPT_W | /* EPT_X |*/ EPT_U | EPT_MT;
			(*map_req_cnt)++;
		}
	}

	return 0;
}

int elisa__exec_init(void)
{
	assert(getenv(ENV_APPLIB_FILE_STR));
	assert(getenv(ENV_APP_VMNET_MEM_STR));
	assert(getenv(ENV_APP_VMNET_USR_STR));

	{
		assert((vs = mmap(NULL, ((sizeof(struct rvs) / 0x1000) + 1) * 0x1000,
						PROT_READ | PROT_WRITE,
						MAP_SHARED /* for fork */ | MAP_ANONYMOUS,
						-1, 0)) != MAP_FAILED);
		memset(vs, 0, sizeof(*vs));
	}


	{
		char *s;
		assert((s = strdup(getenv(ENV_APP_VMNET_MEM_STR))) != NULL);
		{
			size_t i, j;
			for (i = 0, j = 0; i < strlen(getenv(ENV_APP_VMNET_MEM_STR)); i++) {
				if (s[i] == ',' || s[i] == '\0' || s[i] == '\n' || i == strlen(getenv(ENV_APP_VMNET_MEM_STR)) - 1) {
					assert(shm_cnt < RVS_MAX_PORT);
					if (i != strlen(getenv(ENV_APP_VMNET_MEM_STR)) - 1)
						s[i] = '\0';
					{
						char path[PATH_MAX];
						assert(snprintf(path, sizeof(path), "/sys/devices/pci0000:00/%s/resource", &s[j]) < PATH_MAX);
						{
							int fd;
							assert((fd = open(path, O_RDONLY)) != -1);
							assert(lseek(fd, 114,SEEK_SET) == 114);
							{
								char buf[19] = { 0 };
								assert(read(fd, buf, 18) == 18);
								assert(sscanf(buf, "0x%016lx", &vif_mem_paddr[shm_cnt]) == 1);
							}
							close(fd);
						}
					}
					{
						char path[PATH_MAX];
						assert(snprintf(path, sizeof(path), "/sys/devices/pci0000:00/%s/resource2", &s[j]) < PATH_MAX);
						{
							struct stat st;
							assert(!stat(path, &st));
							vif_mem_size[shm_cnt] = st.st_size;
						}
						{
							int fd;
							assert((fd = open(path, O_RDWR)) != -1); // we do not close this fd
							assert((void *)(vs->port[shm_cnt].vif = (struct rvif *) mmap(NULL,
											vif_mem_size[shm_cnt],
											PROT_READ | PROT_WRITE,
											MAP_SHARED | MAP_POPULATE,
											fd, 0)) != MAP_FAILED);
						}
					}
					shm_cnt++;
					j = i + 1;
				}
			}
		}
		free(s);
	}

	{
		char *s;
		assert((s = strdup(getenv(ENV_APP_VMNET_USR_STR))) != NULL);
		{
			size_t i, j;
			for (i = 0, j = 0; i < strlen(getenv(ENV_APP_VMNET_USR_STR)); i++) {
				if (s[i] == ',' || s[i] == '\0' || s[i] == '\n' || i == strlen(getenv(ENV_APP_VMNET_USR_STR)) - 1) {
					assert(shm_cnt < RVS_MAX_PORT);
					if (i != strlen(getenv(ENV_APP_VMNET_USR_STR)) - 1)
						s[i] = '\0';
					assert(inet_pton(AF_INET, &s[j], &user_addr[user_cnt]) == 1);
					user_cnt++;
					j = i + 1;
				}
			}
		}
		free(s);
	}

	return 0;
}
