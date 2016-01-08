/*
 * Linux Boot Option ROM for fw_cfg DMA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2015 Red Hat Inc.
 *   Authors: Marc Marí <markmb@redhat.com>
 */

asm(
".text\n"
".global _start\n"
"_start:\n"
"   .short	0xaa55\n"
"   .byte (_end - _start) / 512\n"
"   lret\n"
"   .org 0x18\n"
"   .short 0\n"
"   .short _pnph\n"
"_pnph:\n"
"   .ascii \"$PnP\"\n"
"   .byte 0x01\n"
"   .byte ( _pnph_len / 16 )\n"
"   .short 0x0000\n"
"   .byte 0x00\n"
"   .byte 0x00\n"
"   .long 0x00000000\n"
"   .short _manufacturer\n"
"   .short _product\n"
"   .long 0x00000000\n"
"   .short 0x0000\n"
"   .short 0x0000\n"
"   .short _bev\n"
"   .short 0x0000\n"
"   .short 0x0000\n"
"   .equ _pnph_len, . - _pnph\n"
"   .align 4, 0\n"
".global gdt\n"
"gdt:\n"
/* 0x00 */
"   .byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00\n"
/* 0x08: code segment (base=0, limit=0xfffff,
 * type=32bit code exec/read, DPL=0, 4k)
 */
"   .byte 0xff, 0xff, 0x00, 0x00, 0x00, 0x9a, 0xcf, 0x00\n"
/* 0x10: data segment (base=0, limit=0xfffff,
 * type=32bit data read/write, DPL=0, 4k)
 */
"   .byte 0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0xcf, 0x00\n"
"_bev:\n"
".code16gcc\n"
/* DS = CS */
"   movw %cs, %ax\n"
"   movw %ax, %ds\n"
"   movl %esp, %ebp\n"
"run_linuxboot:\n"
"   cli\n"
"   cld\n"
"   jmp load_kernel\n"
);

#define C_CODE

/* Do not include all QEMU dependencies */
#include <stdint.h>
#include <byteswap.h>
#include "optionrom.h"

#define BOOT_ROM_PRODUCT "Linux loader"

/* QEMU_CFG_DMA_CONTROL bits */
#define BIOS_CFG_DMA_CTL_ERROR   0x01
#define BIOS_CFG_DMA_CTL_READ    0x02
#define BIOS_CFG_DMA_CTL_SKIP    0x04
#define BIOS_CFG_DMA_CTL_SELECT  0x08

#define BIOS_CFG_DMA_ADDR_HIGH 0x514
#define BIOS_CFG_DMA_ADDR_LOW  0x518

#define _stringify(S)   #S
#define stringify(S) _stringify(S)

#define barrier() asm("": : :"memory")

typedef struct FWCfgDmaAccess {
    uint32_t control;
    uint32_t length;
    uint64_t address;
} __attribute__((gcc_struct, packed)) FWCfgDmaAccess;

struct length_addr {
    uint16_t length;
    uint32_t addr;
} __attribute__((gcc_struct, packed));

static inline void outl(uint32_t value, uint16_t port) {
    asm("outl %0, %w1" : : "a"(value), "Nd"(port));
}

static inline uint16_t read_ds(void) {
    uint16_t ds;
    asm("movw %%ds, %w0" : "=r"(ds) : );
    return ds;
}

static inline uint16_t readw(const void *addr) {
    uint16_t val = *(volatile const uint16_t *)addr;
    barrier();
    return val;
}

static inline uint16_t readw_addr32(const void *addr) {
    uint16_t val;
    asm("addr32 movw %1, %0" : "=r"(val) : "g"(addr));
    barrier();
    return val;
}

static inline uint32_t readl(const void *addr) {
    uint32_t val = *(volatile const uint32_t *)addr;
    barrier();
    return val;
}

static inline uint32_t readl_addr32(const void *addr) {
    uint32_t val;
    asm("addr32 movl %1, %0" : "=r"(val) : "g"(addr));
    barrier();
    return val;
}

static inline void writel(void *addr, uint32_t val) {
    barrier();
    *(volatile uint32_t *)addr = val;
}

static inline void writel_addr32(void *addr, uint32_t val) {
    barrier();
    asm("addr32 movl %0, %1" : : "r"(val), "g"(addr));
}

static inline uint64_t cpu_to_be64(uint64_t x) {
    return bswap_64(x);
}

static inline uint32_t cpu_to_be32(uint32_t x) {
    return bswap_32(x);
}

static inline uint32_t be32_to_cpu(uint32_t x) {
    return bswap_32(x);
}

static void bios_cfg_read_entry(void *buf, uint16_t entry, uint32_t len)
{
    FWCfgDmaAccess access;
    uint32_t control = (entry << 16) | BIOS_CFG_DMA_CTL_SELECT
                        | BIOS_CFG_DMA_CTL_READ;

    access.address = cpu_to_be64((uint64_t)(uint32_t)buf);
    access.length = cpu_to_be32(len);
    access.control = cpu_to_be32(control);

    barrier();

    outl(cpu_to_be32((uint32_t)&access), BIOS_CFG_DMA_ADDR_LOW);

    while(be32_to_cpu(access.control) & ~BIOS_CFG_DMA_CTL_ERROR) {
        barrier();
    }
}

static uint32_t get_e801_addr(void)
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t ret;

    eax = 0xe801;
    ebx = 0;
    ecx = 0;
    edx = 0;
    asm("int $0x15\n"
        : "+a"(eax)
        : "b"(ebx), "c"(ecx), "d"(edx));

    /* Output could be in AX/BX or CX/DX */
    if ((uint16_t)ecx || (uint16_t)edx) {
        if(!(uint16_t)edx) {
            /* Add 1 MB and convert to bytes */
            ret = (ecx + 1024) << 10;
        } else {
            /* Add 16 MB and convert to bytes */
            ret = (edx + 256) << 16;
        }
    } else {
        if(!(uint16_t)ebx) {
            /* Add 1 MB and convert to bytes */
            ret = (eax + 1024) << 10;
        } else {
            /* Add 16 MB and convert to bytes */
            ret = (ebx + 256) << 16;
        }
    }

    return ret;
}

static void transition32(void)
{
    extern void *gdt;
    uint32_t data_segment;
    struct length_addr rombios_gdt;

    data_segment = read_ds();
    rombios_gdt.addr = (uint32_t)((data_segment << 4) + (uint32_t)(&gdt));
    rombios_gdt.length = (3 * 8) - 1;

    /* Load GDT */
    asm("data32 lgdt %0" : : "m"(rombios_gdt): "memory");

	/* Get us to protected mode and set ES to a 32 bit segment */
    asm("mov $1, %%eax\n"
        "mov %%eax, %%cr0\n"
        "mov $0x10, %%eax\n"
        "mov %%eax, %%es\n"
        : : : "eax");

    /* We're now running in 16-bit CS, but 32-bit ES! */
}

static void transition16(void)
{
    asm("mov $0, %%eax\n"
        "mov %%eax, %%cr0\n"
        "mov %%cs, %%ax\n"
        "mov %%ax, %%es\n"
        : : : "eax");
}

void load_kernel(void)
{
    void *setup_addr;
    void *initrd_addr;
    void *kernel_addr;
    void *cmdline_addr;
    uint32_t setup_size;
    uint32_t initrd_size;
    uint32_t kernel_size;
    uint32_t cmdline_size;
    uint32_t initrd_end_page, max_allowed_page;
    uint32_t segment_addr, stack_addr;

    bios_cfg_read_entry(&setup_addr, FW_CFG_SETUP_ADDR, 4);
    bios_cfg_read_entry(&setup_size, FW_CFG_SETUP_SIZE, 4);
    bios_cfg_read_entry(setup_addr, FW_CFG_SETUP_DATA, setup_size);

    if (readw_addr32(setup_addr + 0x206) < 0x203) {
        /* Assume initrd_max 0x37ffffff */
        writel_addr32(setup_addr + 0x22c, 0x37ffffff);
    }

    bios_cfg_read_entry(&initrd_addr, FW_CFG_INITRD_ADDR, 4);
    bios_cfg_read_entry(&initrd_size, FW_CFG_INITRD_SIZE, 4);

    initrd_end_page = ((uint32_t)(initrd_addr + initrd_size) & -4096);
    max_allowed_page = (readl_addr32(setup_addr + 0x22c) & -4096);

    if (initrd_end_page != 0 && max_allowed_page != 0 &&
        initrd_end_page != max_allowed_page) {
        /* Initrd at the end of memory. Compute better initrd address
         * based on e801 data
         */
        initrd_addr = (void *)((get_e801_addr() - initrd_size) & -4096);
        writel_addr32(setup_addr + 0x218, (uint32_t)initrd_addr);

    }

    transition32();

    bios_cfg_read_entry(initrd_addr, FW_CFG_INITRD_DATA, initrd_size);

    bios_cfg_read_entry(&kernel_addr, FW_CFG_KERNEL_ADDR, 4);
    bios_cfg_read_entry(&kernel_size, FW_CFG_KERNEL_SIZE, 4);
    bios_cfg_read_entry(kernel_addr, FW_CFG_KERNEL_DATA, kernel_size);

    bios_cfg_read_entry(&cmdline_addr, FW_CFG_CMDLINE_ADDR, 4);
    bios_cfg_read_entry(&cmdline_size, FW_CFG_CMDLINE_SIZE, 4);
    bios_cfg_read_entry(cmdline_addr, FW_CFG_CMDLINE_DATA, cmdline_size);

    transition16();

    /* Boot linux */
    segment_addr = ((uint32_t)setup_addr >> 4);
    stack_addr = (uint32_t)(cmdline_addr - setup_addr - 16);

    /* As we are changing crytical registers, we cannot leave freedom to the
     * compiler.
     */
    asm("movw %%ax, %%ds\n"
        "movw %%ax, %%es\n"
        "movw %%ax, %%fs\n"
        "movw %%ax, %%gs\n"
        "movw %%ax, %%ss\n"
        "movl %%ebx, %%esp\n"
        "addw $0x20, %%ax\n"
        "pushw %%ax\n" /* CS */
        "pushw $0\n" /* IP */
        /* Clear registers and jump to Linux */
        "xor %%ebx, %%ebx\n"
        "xor %%ecx, %%ecx\n"
        "xor %%edx, %%edx\n"
        "xor %%edi, %%edi\n"
        "xor %%ebp, %%ebp\n"
        "lretw\n"
        : : "a"(segment_addr), "b"(stack_addr));
}

asm(
"_manufacturer:\n"
".asciz \"QEMU\"\n"
"_product:\n"
".asciz "stringify(BOOT_ROM_PRODUCT)"\n"
".byte 0\n"
".align 512, 0\n"
"_end:\n"
);

