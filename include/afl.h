// #include "qemu/osdep.h"
// #include "qemu-common.h"
// #include "exec/cpu-defs.h"


typedef enum AFL_STATUS{
  AFL_WAITTING = 1,
  AFL_START,
  AFL_DOING,
  AFL_RESTART,
  AFL_DONE,
  AFL_GETWORK
} AFL_STATUS;

extern const char *aflFile;
extern unsigned long aflPanicAddr;
extern unsigned long aflDmesgAddr;

extern AFL_STATUS aflStatus;
extern int aflChildrenStatus; /* 测试线程状态 */
extern int aflEnableTicks;
extern int aflStart;
extern int aflGotLog;
extern long afl_start_code, afl_end_code;
extern unsigned char afl_fork_child;
extern int afl_wants_cpu_to_stop;

// void StoreCPUState(CPUArchState* env);
// void LoadCPUState(CPUArchState* env);
// void afl_setup(void);
// void afl_forkserver(CPUArchState*);
// void LoadTestCase(CPUArchState*);

void afl_trace_st(unsigned long host_addr, unsigned int guest_addr, unsigned int value, void *retaddr);
void afl_trace_tcg_st(unsigned long host_addr, unsigned int guest_addr, unsigned int value);