PROGS = lib.so

CD := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

RVS_DIR := $(CD)/../../../deps/librte_pmd_rvif/deps/rvs

CLEANFILES = $(PROGS) *.o

NO_MAN =
CFLAGS += -O3 -pipe -g -rdynamic
CFLAGS += -Werror -Wextra -Wall -Wunused-function
CFLAGS += -ffreestanding -fno-stack-protector
CFLAGS += -nostdlib -nodefaultlibs -nostdinc -fno-builtin
CFLAGS += -fno-strict-aliasing
CFLAGS += -static
CFLAGS += -shared -fPIC

CFLAGS += -I$(RVS_DIR)/include

LDFLAGS += -fPIC

C_SRCS = main.c

C_OBJS = $(C_SRCS:.c=.o) rvs.o

OBJS = $(C_OBJS)

.PHONY: all
all: $(PROGS)

rvs.o: $(RVS_DIR)/rvs.c
	$(CC) $(CFLAGS) -c -o $@ $^

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
