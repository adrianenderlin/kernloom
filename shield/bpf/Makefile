# SPDX-License-Identifier: GPL-2.0-only

BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -Wall -Werror
OUTDIR := out

SRC := xdp_kernloom_shield.bpf.c
OBJ := $(OUTDIR)/xdp_kernloom_shield.bpf.o

all: $(OBJ)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OBJ): $(SRC) | $(OUTDIR)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTDIR)

.PHONY: all clean