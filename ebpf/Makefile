CLANG ?= clang
LLC ?= llc
CC ?= gcc

CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
INCLUDES := -Iinclude -I/usr/include -I/usr/include/bpf

SRC_DIR := src
OUT_DIR := bin
TARGET := $(OUT_DIR)/osoosi-ebpf.o

all: $(TARGET)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(TARGET): $(SRC_DIR)/osoosi_probe.bpf.c | $(OUT_DIR)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OUT_DIR)

.PHONY: all clean
