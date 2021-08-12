AS	= riscv64-unknown-elf-as
CC	= riscv64-unknown-elf-gcc
LD	= riscv64-unknown-elf-ld
CFLAGS = -fno-builtin -fno-stack-protector -Wall -mcmodel=medany -mabi=lp64d -march=rv64imadc -O2 -g -Ilibfdt
LDFLAGS = -nostdlib -Wl,-melf64lriscv,-T,riscvos.lds,-Map,System.map
LDFLAGS_USER = -melf64lriscv -nostdlib
QEMU = qemu-system-riscv64

include libfdt/Makefile.libfdt

SRC_PATH	= .
BUILD_PATH  = ./obj
LIBSRCS		= lib/vsprintf.c lib/strlen.c lib/memcpy.c lib/memcmp.c lib/memchr.c lib/memmove.c \
				lib/memset.c lib/strnlen.c lib/strrchr.c lib/strtoul.c lib/strchr.c lib/strcmp.c \
				lib/assert.c lib/rand.c lib/malloc.c
EXTSRCS		= $(patsubst %.c, libfdt/%.c, $(LIBFDT_SRCS)) \
					protobuf-c/protobuf-c.c \
					hdrhistogram/hdr_histogram.c
PROTOFILES      = proto/ssd_config.proto proto/sim_result.proto
PROTOSRCS		= $(patsubst %.proto, %.pb-c.c, $(PROTOFILES))
SRCS		= head.S trap.S main.c fdt.c of.c proc.c sched.c vm.c global.c direct_tty.c memory.c \
				exc.c irq.c timer.c user.c gate.S alloc.c slab.c virtio.c blk.c \
				pci.c smp.c virtio_mmio.c virtio_pci.c vsock.c ivshmem.c ringbuf.c\
				ssd/ssd.c ssd/hostif.c ssd/hostif_nvme.c ssd/worker.c ssd/data_cache.c ssd/amu.c \
				ssd/block_manager.c ssd/tsu.c ssd/nvm_ctlr.c \
				$(LIBSRCS) $(EXTSRCS) $(PROTOSRCS)
OBJS		= $(patsubst %.c, $(BUILD_PATH)/%.o, $(patsubst %.S, $(BUILD_PATH)/%.o, $(patsubst %.asm, $(BUILD_PATH)/%.o, $(SRCS))))

DEPS		= $(OBJS:.o=.d)

PATH := $(RISCV)/bin:$(PATH)

KERNEL	= $(BUILD_PATH)/kernel

.PHONY : everything all image run clean realclean

all : $(BUILD_PATH) $(KERNEL)
	@true

everything : $(BUILD_PATH) $(KERNEL)
	@true

image : all
	@sh gen-image.sh

run :
	@spike bbl

qemu :
	@$(QEMU) -smp 8 -m 8G -M virt -kernel bbl -drive id=disk0,file=HD,if=none,format=raw -device virtio-blk-device,drive=disk0 -bios none -device ivshmem-plain,memdev=hostmem -object memory-backend-file,size=128M,share=on,mem-path=/dev/shm/ivshmem,id=hostmem -device vhost-vsock-pci,guest-cid=3 -nographic

qemudbg :
	@$(QEMU) -smp 4 -m 8G -M virt -kernel bbl -drive id=disk0,file=HD,if=none,format=raw -device virtio-blk-device,drive=disk0 -monitor stdio -bios none -device ivshmem-plain,memdev=hostmem -object memory-backend-file,size=128M,share=on,mem-path=/dev/shm/ivshmem,id=hostmem -device vhost-vsock-pci,guest-cid=3 -s -S

clean :
	rm $(KERNEL)

realclean :
	rm $(KERNEL) $(OBJS)

$(KERNEL) : $(OBJS)
#	$(LD) $(LDFLAGS) -o $(KERNEL) $(OBJS)
	$(CC) $(LDFLAGS) -o $(KERNEL) $(OBJS) -lm -lgcc

$(BUILD_PATH) :
	mkdir $(BUILD_PATH)
	mkdir $(BUILD_PATH)/lib
	mkdir $(BUILD_PATH)/libfdt
	mkdir $(BUILD_PATH)/ssd
	mkdir $(BUILD_PATH)/proto
	mkdir $(BUILD_PATH)/obj
	mkdir $(BUILD_PATH)/protobuf-c
	mkdir $(BUILD_PATH)/hdrhistogram

-include $(DEPS)

$(BUILD_PATH)/%.o : $(SRC_PATH)/%.c
	$(CC) $(CFLAGS) -MP -MMD -c -I${SRC_PATH} $< -o $@

$(BUILD_PATH)/%.o : $(SRC_PATH)/%.S
	$(CC) $(CFLAGS) -MP -MMD -c -D__ASSEMBLY__ -o $@ $<

%.pb-c.c: $(SRC_PATH)/%.proto
	protoc --c_out=$(SRC_PATH) $<

%.pb-c.h: $(SRC_PATH)/%.proto
	protoc --c_out=$(SRC_PATH) $<
