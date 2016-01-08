all: build-all
# Dummy command so that make thinks it has done something
	@true

BULD_DIR=$(CURDIR)
include ../../config-host.mak
include $(SRC_PATH)/rules.mak

$(call set-vpath, $(SRC_PATH)/pc-bios/optionrom)

.PHONY : all clean build-all

CFLAGS := -Wall -Wstrict-prototypes -Werror -fomit-frame-pointer -fno-builtin
CFLAGS += -I$(SRC_PATH)
CFLAGS += -I$(SRC_PATH)/include
CFLAGS += $(call cc-option, $(CFLAGS), -fno-stack-protector)
CFLAGS += $(CFLAGS_NOPIE)
CFLAGS += -m32
QEMU_CFLAGS = $(CFLAGS)

build-all: multiboot.bin linuxboot.bin linuxboot_dma.bin kvmvapic.bin

# suppress auto-removal of intermediate files
.SECONDARY:

linuxboot_dma.img: linuxboot_dma.o
	$(call quiet-command,$(LD) $(LDFLAGS_NOPIE) -m elf_i386 -static -Ttext 0 -e _start -s -o $@ $<,"  Building $(TARGET_DIR)$@")

%.img: %.o
	$(call quiet-command,$(LD) $(LDFLAGS_NOPIE) -Ttext 0 -e _start -s -o $@ $<,"  Building $(TARGET_DIR)$@")

%.raw: %.img
	$(call quiet-command,$(OBJCOPY) -O binary -j .text $< $@,"  Building $(TARGET_DIR)$@")

%.bin: %.raw
	$(call quiet-command,$(PYTHON) $(SRC_PATH)/scripts/signrom.py $< $@,"  Signing $(TARGET_DIR)$@")

clean:
	rm -f *.o *.d *.raw *.img *.bin *~
