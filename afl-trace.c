#include "afl.h"
// #include "qemu/osdep.h"
// #include "qemu-common.h"
// #include "cpu.h"
// #include "exec/cpu_ldst.h"
// #include "qemu/typedefs.h"


// extern CPUState *current_cpu;
// void afl_trace_st(unsigned long host_addr, uint32_t guest_addr, uint32_t value, void *retaddr) {
//     if (aflStatus != AFL_DOING) {
//         return;
//     }
//     CPUArchState* env = current_cpu->env_ptr;
//     uint32_t cur_value = cpu_ldl_data_ra(env, guest_addr, NULL);
    
//     printf("afl_trace store in host:0x%x, guest:0x%x, value:0x%x, cur_value:0x%x\n", host_addr, guest_addr, value);
// }
// void afl_trace_tcg_st(unsigned long host_addr, unsigned int guest_addr, unsigned int value)
// {
//     afl_trace_st(host_addr, guest_addr, value, MTRACE_GETPC());
// }