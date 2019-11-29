#ifndef FUZZ_FUZZ_H
#define FUZZ_FUZZ_H
#include "qemu/osdep.h"
#include "cpu.h"
#include "trace.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "qemu/atomic.h"
#include "sysemu/qtest.h"
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "qemu/rcu.h"
#include "exec/tb-hash.h"
#include "exec/log.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"
#include "elf.h"
#include "../../config.h"

#define LOG(fmt, ...) printf("[+] " fmt " [%s/%s:%d]\n", ## __VA_ARGS__, __func__, __FILE__, __LINE__)
#define QEMU_FD (FORKSRV_FD-1)

void vxAFL_notify_handler(void *ctx);
void vxAFL_init();
void vxAFL_run(CPUState *cpu, TranslationBlock *itb);

#endif