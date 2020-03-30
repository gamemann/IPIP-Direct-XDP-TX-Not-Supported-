XDP_TARGETS := IPIPDirect_kern
USER_TARGETS := IPIPDirect_loader

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = xdp-tutorial/libbpf/src
COMMON_DIR = xdp-tutorial/common

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o