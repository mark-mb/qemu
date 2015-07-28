/*
 * QEMU Firmware configuration device emulation
 *
 * Copyright (c) 2008 Gleb Natapov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "hw/hw.h"
#include "sysemu/sysemu.h"
#include "sysemu/dma.h"
#include "hw/isa/isa.h"
#include "hw/nvram/fw_cfg.h"
#include "hw/sysbus.h"
#include "trace.h"
#include "qemu/error-report.h"
#include "qemu/config-file.h"

#define FW_CFG_SIZE 2
#define FW_CFG_NAME "fw_cfg"
#define FW_CFG_PATH "/machine/" FW_CFG_NAME

#define TYPE_FW_CFG     "fw_cfg"
#define TYPE_FW_CFG_IO  "fw_cfg_io"
#define TYPE_FW_CFG_MEM "fw_cfg_mem"

#define FW_CFG(obj)     OBJECT_CHECK(FWCfgState,    (obj), TYPE_FW_CFG)
#define FW_CFG_IO(obj)  OBJECT_CHECK(FWCfgIoState,  (obj), TYPE_FW_CFG_IO)
#define FW_CFG_MEM(obj) OBJECT_CHECK(FWCfgMemState, (obj), TYPE_FW_CFG_MEM)

/* fw_cfg dma registers */
#define FW_CFG_DMA_ADDR_LO        0
#define FW_CFG_DMA_ADDR_HI        4
#define FW_CFG_DMA_LENGTH         8
#define FW_CFG_DMA_CONTROL       12
#define FW_CFG_DMA_SIZE          16

/* FW_CFG_DMA_CONTROL bits */
#define FW_CFG_DMA_CTL_ERROR   0x01
#define FW_CFG_DMA_CTL_READ    0x02
#define FW_CFG_DMA_CTL_MASK    0x03

typedef struct FWCfgEntry {
    uint32_t len;
    uint8_t *data;
    void *callback_opaque;
    FWCfgReadCallback read_callback;
} FWCfgEntry;

struct FWCfgState {
    /*< private >*/
    SysBusDevice parent_obj;
    /*< public >*/

    FWCfgEntry entries[2][FW_CFG_MAX_ENTRY];
    FWCfgFiles *files;
    uint16_t cur_entry;
    uint32_t cur_offset;
    Notifier machine_ready;

    bool       dma_enabled;
    AddressSpace *dma_as;
    dma_addr_t dma_addr;
    uint32_t   dma_len;
    uint32_t   dma_ctl;
};

struct FWCfgIoState {
    /*< private >*/
    FWCfgState parent_obj;
    /*< public >*/

    MemoryRegion comb_iomem;
    uint32_t iobase;
};

struct FWCfgMemState {
    /*< private >*/
    FWCfgState parent_obj;
    /*< public >*/

    MemoryRegion ctl_iomem, data_iomem, dma_iomem;
    uint32_t data_width;
    MemoryRegionOps wide_data_ops;
};

#define JPG_FILE 0
#define BMP_FILE 1

static char *read_splashfile(char *filename, gsize *file_sizep,
                             int *file_typep)
{
    GError *err = NULL;
    gboolean res;
    gchar *content;
    int file_type;
    unsigned int filehead;
    int bmp_bpp;

    res = g_file_get_contents(filename, &content, file_sizep, &err);
    if (res == FALSE) {
        error_report("failed to read splash file '%s'", filename);
        g_error_free(err);
        return NULL;
    }

    /* check file size */
    if (*file_sizep < 30) {
        goto error;
    }

    /* check magic ID */
    filehead = ((content[0] & 0xff) + (content[1] << 8)) & 0xffff;
    if (filehead == 0xd8ff) {
        file_type = JPG_FILE;
    } else if (filehead == 0x4d42) {
        file_type = BMP_FILE;
    } else {
        goto error;
    }

    /* check BMP bpp */
    if (file_type == BMP_FILE) {
        bmp_bpp = (content[28] + (content[29] << 8)) & 0xffff;
        if (bmp_bpp != 24) {
            goto error;
        }
    }

    /* return values */
    *file_typep = file_type;

    return content;

error:
    error_report("splash file '%s' format not recognized; must be JPEG "
                 "or 24 bit BMP", filename);
    g_free(content);
    return NULL;
}

static void fw_cfg_bootsplash(FWCfgState *s)
{
    int boot_splash_time = -1;
    const char *boot_splash_filename = NULL;
    char *p;
    char *filename, *file_data;
    gsize file_size;
    int file_type;
    const char *temp;

    /* get user configuration */
    QemuOptsList *plist = qemu_find_opts("boot-opts");
    QemuOpts *opts = QTAILQ_FIRST(&plist->head);
    if (opts != NULL) {
        temp = qemu_opt_get(opts, "splash");
        if (temp != NULL) {
            boot_splash_filename = temp;
        }
        temp = qemu_opt_get(opts, "splash-time");
        if (temp != NULL) {
            p = (char *)temp;
            boot_splash_time = strtol(p, (char **)&p, 10);
        }
    }

    /* insert splash time if user configurated */
    if (boot_splash_time >= 0) {
        /* validate the input */
        if (boot_splash_time > 0xffff) {
            error_report("splash time is big than 65535, force it to 65535.");
            boot_splash_time = 0xffff;
        }
        /* use little endian format */
        qemu_extra_params_fw[0] = (uint8_t)(boot_splash_time & 0xff);
        qemu_extra_params_fw[1] = (uint8_t)((boot_splash_time >> 8) & 0xff);
        fw_cfg_add_file(s, "etc/boot-menu-wait", qemu_extra_params_fw, 2);
    }

    /* insert splash file if user configurated */
    if (boot_splash_filename != NULL) {
        filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, boot_splash_filename);
        if (filename == NULL) {
            error_report("failed to find file '%s'.", boot_splash_filename);
            return;
        }

        /* loading file data */
        file_data = read_splashfile(filename, &file_size, &file_type);
        if (file_data == NULL) {
            g_free(filename);
            return;
        }
        if (boot_splash_filedata != NULL) {
            g_free(boot_splash_filedata);
        }
        boot_splash_filedata = (uint8_t *)file_data;
        boot_splash_filedata_size = file_size;

        /* insert data */
        if (file_type == JPG_FILE) {
            fw_cfg_add_file(s, "bootsplash.jpg",
                    boot_splash_filedata, boot_splash_filedata_size);
        } else {
            fw_cfg_add_file(s, "bootsplash.bmp",
                    boot_splash_filedata, boot_splash_filedata_size);
        }
        g_free(filename);
    }
}

static void fw_cfg_reboot(FWCfgState *s)
{
    int reboot_timeout = -1;
    char *p;
    const char *temp;

    /* get user configuration */
    QemuOptsList *plist = qemu_find_opts("boot-opts");
    QemuOpts *opts = QTAILQ_FIRST(&plist->head);
    if (opts != NULL) {
        temp = qemu_opt_get(opts, "reboot-timeout");
        if (temp != NULL) {
            p = (char *)temp;
            reboot_timeout = strtol(p, (char **)&p, 10);
        }
    }
    /* validate the input */
    if (reboot_timeout > 0xffff) {
        error_report("reboot timeout is larger than 65535, force it to 65535.");
        reboot_timeout = 0xffff;
    }
    fw_cfg_add_file(s, "etc/boot-fail-wait", g_memdup(&reboot_timeout, 4), 4);
}

static void fw_cfg_write(FWCfgState *s, uint8_t value)
{
    /* nothing, write support removed in QEMU v2.4+ */
}

static int fw_cfg_select(FWCfgState *s, uint16_t key)
{
    int ret;

    s->cur_offset = 0;
    if ((key & FW_CFG_ENTRY_MASK) >= FW_CFG_MAX_ENTRY) {
        s->cur_entry = FW_CFG_INVALID;
        ret = 0;
    } else {
        s->cur_entry = key;
        ret = 1;
    }

    trace_fw_cfg_select(s, key, ret);
    return ret;
}

static uint8_t fw_cfg_read(FWCfgState *s)
{
    int arch = !!(s->cur_entry & FW_CFG_ARCH_LOCAL);
    FWCfgEntry *e = &s->entries[arch][s->cur_entry & FW_CFG_ENTRY_MASK];
    uint8_t ret;

    if (s->cur_entry == FW_CFG_INVALID || !e->data || s->cur_offset >= e->len)
        ret = 0;
    else {
        if (e->read_callback) {
            e->read_callback(e->callback_opaque, s->cur_offset);
        }
        ret = e->data[s->cur_offset++];
    }

    trace_fw_cfg_read(s, ret);
    return ret;
}

static uint64_t fw_cfg_data_mem_read(void *opaque, hwaddr addr,
                                     unsigned size)
{
    FWCfgState *s = opaque;
    uint64_t value = 0;
    unsigned i;

    for (i = 0; i < size; ++i) {
        value = (value << 8) | fw_cfg_read(s);
    }
    return value;
}

static void fw_cfg_data_mem_write(void *opaque, hwaddr addr,
                                  uint64_t value, unsigned size)
{
    FWCfgState *s = opaque;
    unsigned i = size;

    do {
        fw_cfg_write(s, value >> (8 * --i));
    } while (i);
}

static void fw_cfg_dma_transfer(FWCfgState *s)
{
    dma_addr_t len;
    uint8_t *ptr;
    uint32_t cnt;
    int arch = !!(s->cur_entry & FW_CFG_ARCH_LOCAL);
    FWCfgEntry *e = &s->entries[arch][s->cur_entry & FW_CFG_ENTRY_MASK];

    if (s->dma_ctl & FW_CFG_DMA_CTL_ERROR) {
        return;
    }

    if (!(s->dma_ctl & FW_CFG_DMA_CTL_READ)) {
        return;
    }

    if (s->cur_entry == FW_CFG_INVALID || !e->data || s->cur_offset >= e->len) {
        while (s->dma_len > 0) {
            len = s->dma_len;
            if (s->dma_addr) {
                ptr = dma_memory_map(s->dma_as, s->dma_addr, &len,
                                     DMA_DIRECTION_FROM_DEVICE);
                if (!ptr || !len) {
                    s->dma_ctl |= FW_CFG_DMA_CTL_ERROR;
                    return;
                }

                memset(ptr, 0, len);

                dma_memory_unmap(s->dma_as, ptr, len,
                                 DMA_DIRECTION_FROM_DEVICE, len);
            }

            s->dma_addr += len;
            s->dma_len  -= len;
        }
    } else {
        while (s->dma_len > 0) {
            len = s->dma_len;

            if (e->read_callback) {
                for (cnt = 0; cnt < len; cnt++) {
                     e->read_callback(e->callback_opaque, s->cur_offset + cnt);
                }
            }

            if (s->dma_addr) {
                ptr = dma_memory_map(s->dma_as, s->dma_addr, &len,
                                     DMA_DIRECTION_FROM_DEVICE);
                if (!ptr || !len) {
                    s->dma_ctl |= FW_CFG_DMA_CTL_ERROR;
                    return;
                }


                memcpy(ptr, &e->data[s->cur_offset], len);

                dma_memory_unmap(s->dma_as, ptr, len,
                                 DMA_DIRECTION_FROM_DEVICE, len);
            }

            s->cur_offset += len;

            s->dma_addr += len;
            s->dma_len  -= len;
        }

        s->dma_ctl = 0;
    }

    trace_fw_cfg_read(s, 0);
    return;

}

static uint64_t fw_cfg_dma_mem_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
    FWCfgState *s = opaque;
    uint64_t ret = 0;

    switch (addr) {
    case FW_CFG_DMA_ADDR_LO:
        ret = s->dma_addr & 0xffffffff;
        break;
    case FW_CFG_DMA_ADDR_HI:
        ret = (s->dma_addr >> 32) & 0xffffffff;
        break;
    case FW_CFG_DMA_LENGTH:
        ret = s->dma_len;
        break;
    case FW_CFG_DMA_CONTROL:
        ret = s->dma_ctl;
        break;
    }
    return ret;
}

static void fw_cfg_dma_mem_write(void *opaque, hwaddr addr,
                                 uint64_t value, unsigned size)
{
    FWCfgState *s = opaque;

    switch (addr) {
    case FW_CFG_DMA_ADDR_LO:
        s->dma_addr &= ~((dma_addr_t)0xffffffff);
        s->dma_addr |= value;
        break;
    case FW_CFG_DMA_ADDR_HI:
        s->dma_addr &= ~(((dma_addr_t)0xffffffff) << 32);
        s->dma_addr |= ((dma_addr_t)value) << 32;
        break;
    case FW_CFG_DMA_LENGTH:
        s->dma_len = value;
        break;
    case FW_CFG_DMA_CONTROL:
        value &= FW_CFG_DMA_CTL_MASK;
        s->dma_ctl = value;
        fw_cfg_dma_transfer(s);
        break;
    }
}

static bool fw_cfg_data_mem_valid(void *opaque, hwaddr addr,
                                  unsigned size, bool is_write)
{
    return addr == 0;
}

static void fw_cfg_ctl_mem_write(void *opaque, hwaddr addr,
                                 uint64_t value, unsigned size)
{
    fw_cfg_select(opaque, (uint16_t)value);
}

static bool fw_cfg_ctl_mem_valid(void *opaque, hwaddr addr,
                                 unsigned size, bool is_write)
{
    return is_write && size == 2;
}

static uint64_t fw_cfg_comb_read(void *opaque, hwaddr addr,
                                 unsigned size)
{
    return fw_cfg_read(opaque);
}

static void fw_cfg_comb_write(void *opaque, hwaddr addr,
                              uint64_t value, unsigned size)
{
    switch (size) {
    case 1:
        fw_cfg_write(opaque, (uint8_t)value);
        break;
    case 2:
        fw_cfg_select(opaque, (uint16_t)value);
        break;
    }
}

static bool fw_cfg_comb_valid(void *opaque, hwaddr addr,
                                  unsigned size, bool is_write)
{
    return (size == 1) || (is_write && size == 2);
}

static const MemoryRegionOps fw_cfg_ctl_mem_ops = {
    .write = fw_cfg_ctl_mem_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid.accepts = fw_cfg_ctl_mem_valid,
};

static const MemoryRegionOps fw_cfg_data_mem_ops = {
    .read = fw_cfg_data_mem_read,
    .write = fw_cfg_data_mem_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 1,
        .max_access_size = 1,
        .accepts = fw_cfg_data_mem_valid,
    },
};

static const MemoryRegionOps fw_cfg_comb_mem_ops = {
    .read = fw_cfg_comb_read,
    .write = fw_cfg_comb_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid.accepts = fw_cfg_comb_valid,
};

static const MemoryRegionOps fw_cfg_dma_mem_ops = {
    .read = fw_cfg_dma_mem_read,
    .write = fw_cfg_dma_mem_write,
    .endianness = DEVICE_BIG_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void fw_cfg_reset(DeviceState *d)
{
    FWCfgState *s = FW_CFG(d);

    fw_cfg_select(s, 0);
}

/* Save restore 32 bit int as uint16_t
   This is a Big hack, but it is how the old state did it.
   Or we broke compatibility in the state, or we can't use struct tm
 */

static int get_uint32_as_uint16(QEMUFile *f, void *pv, size_t size)
{
    uint32_t *v = pv;
    *v = qemu_get_be16(f);
    return 0;
}

static void put_unused(QEMUFile *f, void *pv, size_t size)
{
    fprintf(stderr, "uint32_as_uint16 is only used for backward compatibility.\n");
    fprintf(stderr, "This functions shouldn't be called.\n");
}

static const VMStateInfo vmstate_hack_uint32_as_uint16 = {
    .name = "int32_as_uint16",
    .get  = get_uint32_as_uint16,
    .put  = put_unused,
};

#define VMSTATE_UINT16_HACK(_f, _s, _t)                                    \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_hack_uint32_as_uint16, uint32_t)


static bool is_version_1(void *opaque, int version_id)
{
    return version_id == 1;
}

static bool fw_cfg_dma_enabled(void *opaque)
{
    FWCfgState *s = opaque;

    return s->dma_enabled;
}

static VMStateDescription vmstate_fw_cfg_dma = {
    .name = "fw_cfg/dma",
    .needed = fw_cfg_dma_enabled,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64(dma_addr, FWCfgState),
        VMSTATE_UINT32(dma_len, FWCfgState),
        VMSTATE_UINT32(dma_ctl, FWCfgState),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_fw_cfg = {
    .name = "fw_cfg",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT16(cur_entry, FWCfgState),
        VMSTATE_UINT16_HACK(cur_offset, FWCfgState, is_version_1),
        VMSTATE_UINT32_V(cur_offset, FWCfgState, 2),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_fw_cfg_dma,
        NULL,
    }
};

static void fw_cfg_add_bytes_read_callback(FWCfgState *s, uint16_t key,
                                           FWCfgReadCallback callback,
                                           void *callback_opaque,
                                           void *data, size_t len)
{
    int arch = !!(key & FW_CFG_ARCH_LOCAL);

    key &= FW_CFG_ENTRY_MASK;

    assert(key < FW_CFG_MAX_ENTRY && len < UINT32_MAX);
    assert(s->entries[arch][key].data == NULL); /* avoid key conflict */

    s->entries[arch][key].data = data;
    s->entries[arch][key].len = (uint32_t)len;
    s->entries[arch][key].read_callback = callback;
    s->entries[arch][key].callback_opaque = callback_opaque;
}

static void *fw_cfg_modify_bytes_read(FWCfgState *s, uint16_t key,
                                              void *data, size_t len)
{
    void *ptr;
    int arch = !!(key & FW_CFG_ARCH_LOCAL);

    key &= FW_CFG_ENTRY_MASK;

    assert(key < FW_CFG_MAX_ENTRY && len < UINT32_MAX);

    /* return the old data to the function caller, avoid memory leak */
    ptr = s->entries[arch][key].data;
    s->entries[arch][key].data = data;
    s->entries[arch][key].len = len;
    s->entries[arch][key].callback_opaque = NULL;

    return ptr;
}

void fw_cfg_add_bytes(FWCfgState *s, uint16_t key, void *data, size_t len)
{
    fw_cfg_add_bytes_read_callback(s, key, NULL, NULL, data, len);
}

void fw_cfg_add_string(FWCfgState *s, uint16_t key, const char *value)
{
    size_t sz = strlen(value) + 1;

    fw_cfg_add_bytes(s, key, g_memdup(value, sz), sz);
}

void fw_cfg_add_i16(FWCfgState *s, uint16_t key, uint16_t value)
{
    uint16_t *copy;

    copy = g_malloc(sizeof(value));
    *copy = cpu_to_le16(value);
    fw_cfg_add_bytes(s, key, copy, sizeof(value));
}

void fw_cfg_modify_i16(FWCfgState *s, uint16_t key, uint16_t value)
{
    uint16_t *copy, *old;

    copy = g_malloc(sizeof(value));
    *copy = cpu_to_le16(value);
    old = fw_cfg_modify_bytes_read(s, key, copy, sizeof(value));
    g_free(old);
}

void fw_cfg_add_i32(FWCfgState *s, uint16_t key, uint32_t value)
{
    uint32_t *copy;

    copy = g_malloc(sizeof(value));
    *copy = cpu_to_le32(value);
    fw_cfg_add_bytes(s, key, copy, sizeof(value));
}

void fw_cfg_add_i64(FWCfgState *s, uint16_t key, uint64_t value)
{
    uint64_t *copy;

    copy = g_malloc(sizeof(value));
    *copy = cpu_to_le64(value);
    fw_cfg_add_bytes(s, key, copy, sizeof(value));
}

void fw_cfg_add_file_callback(FWCfgState *s,  const char *filename,
                              FWCfgReadCallback callback, void *callback_opaque,
                              void *data, size_t len)
{
    int i, index, count;
    size_t dsize;

    if (!s->files) {
        dsize = sizeof(uint32_t) + sizeof(FWCfgFile) * FW_CFG_FILE_SLOTS;
        s->files = g_malloc0(dsize);
        fw_cfg_add_bytes(s, FW_CFG_FILE_DIR, s->files, dsize);
    }

    count = be32_to_cpu(s->files->count);
    assert(count < FW_CFG_FILE_SLOTS);

    index = count;
    if (1 /* sort entries */) {
        while (index > 0 && strcmp(filename, s->files->f[index-1].name) < 0) {
            s->files->f[index] =
                s->files->f[index - 1];
            s->files->f[index].select =
                cpu_to_be16(FW_CFG_FILE_FIRST + index);
            s->entries[0][FW_CFG_FILE_FIRST + index] =
                s->entries[0][FW_CFG_FILE_FIRST + index - 1];
            index--;
        }
        memset(&s->files->f[index],
               0, sizeof(FWCfgFile));
        memset(&s->entries[0][FW_CFG_FILE_FIRST + index],
               0, sizeof(FWCfgEntry));
    }

    pstrcpy(s->files->f[index].name, sizeof(s->files->f[index].name),
            filename);
    for (i = 0; i <= count; i++) {
        if (i != index &&
            strcmp(s->files->f[index].name, s->files->f[i].name) == 0) {
            error_report("duplicate fw_cfg file name: %s",
                         s->files->f[index].name);
            exit(1);
        }
    }

    fw_cfg_add_bytes_read_callback(s, FW_CFG_FILE_FIRST + index,
                                   callback, callback_opaque, data, len);

    s->files->f[index].size   = cpu_to_be32(len);
    s->files->f[index].select = cpu_to_be16(FW_CFG_FILE_FIRST + index);
    trace_fw_cfg_add_file(s, index, s->files->f[index].name, len);

    s->files->count = cpu_to_be32(count+1);
}

void fw_cfg_add_file(FWCfgState *s,  const char *filename,
                     void *data, size_t len)
{
    fw_cfg_add_file_callback(s, filename, NULL, NULL, data, len);
}

void *fw_cfg_modify_file(FWCfgState *s, const char *filename,
                        void *data, size_t len)
{
    int i, index;
    void *ptr = NULL;

    assert(s->files);

    index = be32_to_cpu(s->files->count);
    assert(index < FW_CFG_FILE_SLOTS);

    for (i = 0; i < index; i++) {
        if (strcmp(filename, s->files->f[i].name) == 0) {
            ptr = fw_cfg_modify_bytes_read(s, FW_CFG_FILE_FIRST + i,
                                           data, len);
            s->files->f[i].size   = cpu_to_be32(len);
            return ptr;
        }
    }
    /* add new one */
    fw_cfg_add_file_callback(s, filename, NULL, NULL, data, len);
    return NULL;
}

static void fw_cfg_machine_reset(void *opaque)
{
    void *ptr;
    size_t len;
    FWCfgState *s = opaque;
    char *bootindex = get_boot_devices_list(&len, false);

    ptr = fw_cfg_modify_file(s, "bootorder", (uint8_t *)bootindex, len);
    g_free(ptr);
}

static void fw_cfg_machine_ready(struct Notifier *n, void *data)
{
    FWCfgState *s = container_of(n, FWCfgState, machine_ready);
    qemu_register_reset(fw_cfg_machine_reset, s);
}



static void fw_cfg_init1(DeviceState *dev)
{
    FWCfgState *s = FW_CFG(dev);

    assert(!object_resolve_path(FW_CFG_PATH, NULL));

    object_property_add_child(qdev_get_machine(), FW_CFG_NAME, OBJECT(s), NULL);

    qdev_init_nofail(dev);

    fw_cfg_add_bytes(s, FW_CFG_SIGNATURE, (char *)"QEMU", 4);
    fw_cfg_add_i32(s, FW_CFG_ID, 1);
    fw_cfg_add_bytes(s, FW_CFG_UUID, qemu_uuid, 16);
    fw_cfg_add_i16(s, FW_CFG_NOGRAPHIC, (uint16_t)(display_type == DT_NOGRAPHIC));
    fw_cfg_add_i16(s, FW_CFG_NB_CPUS, (uint16_t)smp_cpus);
    fw_cfg_add_i16(s, FW_CFG_BOOT_MENU, (uint16_t)boot_menu);
    fw_cfg_bootsplash(s);
    fw_cfg_reboot(s);

    s->machine_ready.notify = fw_cfg_machine_ready;
    qemu_add_machine_init_done_notifier(&s->machine_ready);
}

FWCfgState *fw_cfg_init_io(uint32_t iobase)
{
    DeviceState *dev;

    dev = qdev_create(NULL, TYPE_FW_CFG_IO);
    qdev_prop_set_uint32(dev, "iobase", iobase);
    fw_cfg_init1(dev);

    return FW_CFG(dev);
}

FWCfgState *fw_cfg_init_mem_wide(hwaddr ctl_addr,
                                 hwaddr data_addr, uint32_t data_width,
                                 hwaddr dma_addr, AddressSpace *dma_as)
{
    DeviceState *dev;
    SysBusDevice *sbd;

    dev = qdev_create(NULL, TYPE_FW_CFG_MEM);
    qdev_prop_set_uint32(dev, "data_width", data_width);

    fw_cfg_init1(dev);

    sbd = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(sbd, 0, ctl_addr);
    sysbus_mmio_map(sbd, 1, data_addr);

    if (dma_addr && dma_as) {
        FW_CFG(dev)->dma_as = dma_as;
        FW_CFG(dev)->dma_enabled = true;
        sysbus_mmio_map(sbd, 2, dma_addr);
    }

    return FW_CFG(dev);
}

FWCfgState *fw_cfg_init_mem(hwaddr ctl_addr, hwaddr data_addr)
{
    return fw_cfg_init_mem_wide(ctl_addr, data_addr,
                                fw_cfg_data_mem_ops.valid.max_access_size,
                                0, NULL);
}


FWCfgState *fw_cfg_find(void)
{
    return FW_CFG(object_resolve_path(FW_CFG_PATH, NULL));
}

static void fw_cfg_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = fw_cfg_reset;
    dc->vmsd = &vmstate_fw_cfg;
}

static const TypeInfo fw_cfg_info = {
    .name          = TYPE_FW_CFG,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(FWCfgState),
    .class_init    = fw_cfg_class_init,
};


static Property fw_cfg_io_properties[] = {
    DEFINE_PROP_UINT32("iobase", FWCfgIoState, iobase, -1),
    DEFINE_PROP_END_OF_LIST(),
};

static void fw_cfg_io_realize(DeviceState *dev, Error **errp)
{
    FWCfgIoState *s = FW_CFG_IO(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    memory_region_init_io(&s->comb_iomem, OBJECT(s), &fw_cfg_comb_mem_ops,
                          FW_CFG(s), "fwcfg", FW_CFG_SIZE);
    sysbus_add_io(sbd, s->iobase, &s->comb_iomem);
}

static void fw_cfg_io_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = fw_cfg_io_realize;
    dc->props = fw_cfg_io_properties;
}

static const TypeInfo fw_cfg_io_info = {
    .name          = TYPE_FW_CFG_IO,
    .parent        = TYPE_FW_CFG,
    .instance_size = sizeof(FWCfgIoState),
    .class_init    = fw_cfg_io_class_init,
};


static Property fw_cfg_mem_properties[] = {
    DEFINE_PROP_UINT32("data_width", FWCfgMemState, data_width, -1),
    DEFINE_PROP_END_OF_LIST(),
};

static void fw_cfg_mem_realize(DeviceState *dev, Error **errp)
{
    FWCfgMemState *s = FW_CFG_MEM(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    const MemoryRegionOps *data_ops = &fw_cfg_data_mem_ops;

    memory_region_init_io(&s->ctl_iomem, OBJECT(s), &fw_cfg_ctl_mem_ops,
                          FW_CFG(s), "fwcfg.ctl", FW_CFG_SIZE);
    sysbus_init_mmio(sbd, &s->ctl_iomem);

    if (s->data_width > data_ops->valid.max_access_size) {
        /* memberwise copy because the "old_mmio" member is const */
        s->wide_data_ops.read       = data_ops->read;
        s->wide_data_ops.write      = data_ops->write;
        s->wide_data_ops.endianness = data_ops->endianness;
        s->wide_data_ops.valid      = data_ops->valid;
        s->wide_data_ops.impl       = data_ops->impl;

        s->wide_data_ops.valid.max_access_size = s->data_width;
        s->wide_data_ops.impl.max_access_size  = s->data_width;
        data_ops = &s->wide_data_ops;
    }
    memory_region_init_io(&s->data_iomem, OBJECT(s), data_ops, FW_CFG(s),
                          "fwcfg.data", data_ops->valid.max_access_size);
    sysbus_init_mmio(sbd, &s->data_iomem);

    memory_region_init_io(&s->dma_iomem, OBJECT(s), &fw_cfg_dma_mem_ops,
                          FW_CFG(s), "fwcfg.dma", FW_CFG_DMA_SIZE);
    sysbus_init_mmio(sbd, &s->dma_iomem);
}

static void fw_cfg_mem_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = fw_cfg_mem_realize;
    dc->props = fw_cfg_mem_properties;
}

static const TypeInfo fw_cfg_mem_info = {
    .name          = TYPE_FW_CFG_MEM,
    .parent        = TYPE_FW_CFG,
    .instance_size = sizeof(FWCfgMemState),
    .class_init    = fw_cfg_mem_class_init,
};


static void fw_cfg_register_types(void)
{
    type_register_static(&fw_cfg_info);
    type_register_static(&fw_cfg_io_info);
    type_register_static(&fw_cfg_mem_info);
}

type_init(fw_cfg_register_types)
