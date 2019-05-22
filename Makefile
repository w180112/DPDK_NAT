# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = nat

# all source are stored in SRCS-y
SRCS-y := nat.c mlx5_nat.c mlx5_flow.c ethtool.c nat_learning.c ixgbe_82599_flow.c ixgbe_82599_nat.c

# Build using pkg-config variables if possible
$(shell pkg-config --exists libdpdk)

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -O3 -std=c99 -D_XOPEN_SOURCE=700 -D_BSD_SOURCE
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk

