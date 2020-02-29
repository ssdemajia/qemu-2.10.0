#include <sys/shm.h>

#include "../../config.h"
#include "qemu/osdep.h"
#include "exec/cpu_ldst.h"

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2(cpu, env, pc) do { \
    afl_check_pc(cpu, env, pc); \
    afl_maybe_log(pc); \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char *afl_area_ptr = 0;

/* Exported variables populated by the code patched into elfload.c: */

target_ulong  afl_entry_point = 0x30d4d0, /* ELF entry point (_start) */
      afl_start_code = 0,  /* .text start pointer      */
      afl_end_code = 0x30d54c;    /* .text end pointer        */

int aflChildrenStatus = 0; // 子线程执行的状态
int aflStart = 0;               /* we've started fuzzing */
int aflEnableTicks = 0;         /* re-enable ticks for each test */
int aflGotLog = 0;              /* we've seen dmesg logging */
typedef enum AFL_STATUS{
  AFL_WAITTING = 1,
  AFL_START,
  AFL_DOING,
  AFL_RESTART,
  AFL_DONE,
  AFL_GETWORK
} AFL_STATUS;

AFL_STATUS aflStatus = AFL_WAITTING;
GHashTable* aflMemHT = NULL;
/* from command line options */
const char *aflFile = "/tmp/work";
unsigned long aflPanicAddr = 0xffffffff8105615a;
unsigned long aflDmesgAddr = (unsigned long)-1;

/* Set in the child process in forkserver mode: */

unsigned char afl_fork_child = 0;
int afl_wants_cpu_to_stop = 0;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */
static void afl_check_pc(CPUState* cpu, CPUArchState* env, target_ulong pc);
static inline void afl_maybe_log(target_ulong);

static void afl_wait_tsl(CPUArchState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

static TranslationBlock *tb_find_slow(CPUArchState*, target_ulong,
                                      target_ulong, uint64_t);

CPUArchState backupCPUState; // 用于保持的cpu状态
CPUTLBEntry backupTLBTable[3][256];

void StoreCPUState(CPUArchState* env) {
  printf("[SSSS]Store CPU State\n");
  for (int i = 0; i < CPU_NB_REGS; i++) {
    backupCPUState.regs[i] = env->regs[i];
  }
  backupCPUState.eip = env->eip;
  backupCPUState.eflags = env->eflags;
  backupCPUState.cc_dst = env->cc_dst;
  backupCPUState.cc_src = env->cc_src;
  backupCPUState.cc_src2 = env->cc_src2;
  backupCPUState.cc_op = env->cc_op;
  backupCPUState.df = env->df;
  backupCPUState.hflags = env->hflags;
  backupCPUState.a20_mask = env->a20_mask;
  for (int i = 0; i < 6; i++) {
    backupCPUState.segs[i] = env->segs[i];
  }
  backupCPUState.ldt = env->ldt;
  backupCPUState.tr = env->tr;
  backupCPUState.gdt = env->gdt;
  backupCPUState.idt = env->idt;
  for (int i = 0; i < 5; i++) {
    backupCPUState.cr[i] = env->cr[i];
  }
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 256; j++) {
      backupTLBTable[i][j].addr_code = env->tlb_table[i][j].addr_code;
      backupTLBTable[i][j].addr_write = env->tlb_table[i][j].addr_write;
      backupTLBTable[i][j].addr_read = env->tlb_table[i][j].addr_read;
      backupTLBTable[i][j].addend = env->tlb_table[i][j].addend;
    }
  }

  backupCPUState.sysenter_cs = env->sysenter_cs;
  backupCPUState.sysenter_esp = env->sysenter_esp;
  backupCPUState.sysenter_eip = env->sysenter_eip;
  backupCPUState.star = env->star;
}
extern CPUState* restart_cpu;
static void
myIterator(gpointer key, gpointer value, gpointer env)
{
  CPUArchState* arch = (CPUArchState*)env;
  cpu_stl_data_ra(arch, *(target_long*)key, *(target_long*)value, NULL);
  // printf("[restore]key:%ld, value:%ld\n", *(target_long*)key, *(target_long*)value);
}

void LoadCPUState(CPUArchState* env) {
  for (int i = 0; i < CPU_NB_REGS; i++) {
    env->regs[i] = backupCPUState.regs[i];
  }
  env->eip = backupCPUState.eip;
  env->eflags = backupCPUState.eflags;
  env->cc_dst = backupCPUState.cc_dst;
  env->cc_src = backupCPUState.cc_src;
  env->cc_src2 = backupCPUState.cc_src2;
  env->cc_op = backupCPUState.cc_op;
  env->df = backupCPUState.df;
  env->hflags = backupCPUState.hflags;
  env->a20_mask = backupCPUState.a20_mask;
  for (int i = 0; i < 6; i++) {
    env->segs[i] = backupCPUState.segs[i];
  }
  env->ldt = backupCPUState.ldt;
  env->tr = backupCPUState.tr;
  env->gdt = backupCPUState.gdt;
  env->idt = backupCPUState.idt;
  for (int i = 0; i < 5; i++) {
    env->cr[i] = backupCPUState.cr[i];
  }
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 256; j++) {
      env->tlb_table[i][j].addr_code = backupTLBTable[i][j].addr_code;
      env->tlb_table[i][j].addr_write = backupTLBTable[i][j].addr_write;
      env->tlb_table[i][j].addr_read = backupTLBTable[i][j].addr_read;
      env->tlb_table[i][j].addend = backupTLBTable[i][j].addend;
    }
  }

  env->sysenter_cs = backupCPUState.sysenter_cs;
  env->sysenter_esp = backupCPUState.sysenter_esp;
  env->sysenter_eip = backupCPUState.sysenter_eip;
  env->star = backupCPUState.star;

  g_hash_table_foreach(aflMemHT, myIterator, env);
  // g_hash_table_remove_all(aflMemHT);
}

FILE *afl_fp = NULL;
void LoadTestCase(CPUArchState* env) {
  printf("[SSSS]load testcase\n");
  
  const char* filepath = "/home/ss/work/vxafl/test_input.txt";
  // uintptr_t ra = GETPC();
  printf("esp addr:%lx, eip addr:%lx\n", env->regs[R_ESP], env->eip);
  target_long ret_ptr = cpu_ldl_data(env, env->regs[R_ESP]);
  printf("ret addr:%lx\n", ret_ptr);

  target_ulong arg_ptr = cpu_ldl_data(env, env->regs[R_ESP]+4);
  // for (int i = 0; i < 10; i++) {
  //   target_long ptr = cpu_ldl_data(env, env->regs[R_ESP]+4*i);
  //   printf("x addr:0x%x, value%x\n", env->regs[R_ESP]+4*i, ptr);
  // }
  

  // // FILE *fp;
  if (!afl_fp)
    afl_fp = fopen(filepath, "rb");
  if (!afl_fp) {
    perror("Can't open file");
    exit(-1);
  }
  fseek(afl_fp, 0, SEEK_END);
  size_t sz = ftell(afl_fp); // 文件大小

  fseek(afl_fp, 0, SEEK_SET);
  char ch = 0;
  for (int i = 0; i < sz; i++) {
    // printf("%c", ch);
    if (fread(&ch, 1, 1, afl_fp) == 0) {
      break;
    }
    cpu_stb_data(env, arg_ptr+i, 'A');
  }
  printf("args inject %d\n", sz);
}

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

void afl_setup(void) {
  char *id_str = getenv(SHM_ENV_VAR),
       *inst_r = getenv("AFL_INST_RATIO");
  int shm_id;

  if (inst_r) {

    unsigned int r;
    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;
  }

  if (id_str) {
    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;


  }
}

static inline target_ulong aflHash(target_ulong cur_loc)
{
  if(!aflStart)
    return 0;

  /* Optimize for cur_loc > afl_end_code, which is the most likely case on
     Linux systems. */

  // if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
  //   return 0;

#ifdef DEBUG_EDGES
  if(1) {
    printf("exec %lx\n", cur_loc);
    fflush(stdout);
  }
#endif

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  target_ulong h = cur_loc;
#if TARGET_LONG_BITS == 32
  h ^= cur_loc >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
#else
  h ^= cur_loc >> 33;
  h *= 0xff51afd7ed558ccd;
  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53;
  h ^= h >> 33;
#endif

  h &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (h >= afl_inst_rms) return 0;
  return h;
}

/* todo: generate calls to helper_aflMaybeLog during translation */
static inline void helper_aflMaybeLog(target_ulong cur_loc) {
  static __thread target_ulong prev_loc;

  afl_area_ptr[cur_loc ^ prev_loc]++;
  prev_loc = cur_loc >> 1;
}

/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(target_ulong cur_loc) {
  return;
  if (aflStatus == AFL_START || aflStatus == AFL_DOING) {
    cur_loc = aflHash(cur_loc);
    if(cur_loc)
      helper_aflMaybeLog(cur_loc);
  }
}

static void afl_check_pc(CPUState* cpu, CPUArchState* env, target_ulong pc) {
  if(pc == afl_entry_point && pc && aflStatus == AFL_WAITTING) {
    // cpu_single_step(cpu, true); // 设置为单步执行
    aflStart = 1;
    aflStatus = AFL_START;
    // afl_wants_cpu_to_stop = 1;
    printf("[SSSS]AFLSTART pc is %lx\n", pc);
    aflMemHT = g_hash_table_new(g_int_hash, g_int_equal);
    // afl_setup();
    StoreCPUState(env);
    aflStatus = AFL_DOING;
    LoadTestCase(env);
    // cpu_breakpoint_insert(cpu, afl_entry_point, BP_GDB, NULL);
  }
  else if (aflStatus == AFL_DOING) {
    printf("[SSSS]DOING pc:0x%lx\n", pc);
    if (pc == 0x40a250) {
      printf("idleEnter\n");
      afl_wants_cpu_to_stop = 1;
      aflChildrenStatus = 0;
      aflStatus = AFL_DONE;
    }
    if (pc == 0x40cb30) {
      printf("reschedule\n");
      afl_wants_cpu_to_stop = 1;
      aflChildrenStatus = 0;
      aflStatus = AFL_DONE;
    }
    if (pc == 0x00425f40) {
      printf("Panic\n");
      afl_wants_cpu_to_stop = 1;
      aflChildrenStatus = 0;
      aflStatus = AFL_DONE;
    }
    if (pc == 0x412c40) {
      printf("Task Lock\n");
      afl_wants_cpu_to_stop = 1;
      aflChildrenStatus = 0;
      aflStatus = AFL_DONE;
    }
    // if (pc > afl_entry_point + 32) {
    //   printf("More \n");
    //   afl_wants_cpu_to_stop = 1;
    //   aflChildrenStatus = 0;
    //   aflStatus = AFL_DONE;
    // }
    if (pc == 0x3189e0) {
      printf("excStub0 \n");
      afl_wants_cpu_to_stop = 1;
      aflChildrenStatus = 23;
      aflStatus = AFL_DONE;
    }
    if (pc == 0xd41a) {
      exit(1);
    }
    // if (pc == aflPanicAddr) {
    //   printf("panic \n");
    //   afl_wants_cpu_to_stop = 1;
    //   aflChildrenStatus = 0;
    //   aflStatus = AFL_DONE; 
    // }
    // if (pc >= afl_entry_point + 73) {
    //   printf("procfs1 end \n");
    //   afl_wants_cpu_to_stop = 1;
    //   aflChildrenStatus = 0;
    //   aflStatus = AFL_DONE; 
    // }
    // if (pc >= 0xffffffff811d21bf) {
    //   printf("procfs1 ret \n");
    //   afl_wants_cpu_to_stop = 1;
    //   aflChildrenStatus = 0;
    //   aflStatus = AFL_DONE; 
    // }
    // if (pc == 0xffffffff8107f0c2) {
    //    printf("procfs1 idle \n");
    //   afl_wants_cpu_to_stop = 1;
    //   aflChildrenStatus = 0;
    //   aflStatus = AFL_DONE; 
    // }
    // if (pc == 0xffffffff81085f1b) {
    //    printf("procfs1 pick_next_entity \n");
    //   afl_wants_cpu_to_stop = 1;
    //   aflChildrenStatus = 0;
    //   aflStatus = AFL_DONE; 
    // }
    if (aflStatus == AFL_DONE) {
      printf("[SSSS]Done\n");
      LoadCPUState(env);
      aflStatus = AFL_DOING;
      LoadTestCase(env);
    }
  }
}

#define AFL_TRACE_GETPC() ((void *)((unsigned long)__builtin_return_address(0) - 1))

void afl_trace_st(CPUArchState* env, target_ulong host_addr, target_ulong guest_addr, target_ulong value, void *retaddr) {
    if (aflStatus == AFL_DOING || aflStatus == AFL_START) {
      if (g_hash_table_lookup(aflMemHT, &guest_addr)) {
        return;
      }
      // CPUArchState* env = current_cpu->env_ptr;
      target_ulong cur_value = cpu_ldl_data(env, guest_addr);
      // target_ulong cur_value = 0;
      target_ulong* value = (target_ulong*)malloc(sizeof(target_ulong));
      target_ulong* key = (target_ulong*)malloc(sizeof(target_ulong));
      *key = guest_addr;
      *value = cur_value;
      // printf("afl_trace store in host:0x%x, guest:0x%x, value:0x%x, cur_value:0x%x\n", host_addr, guest_addr, value, cur_value);
      // if (cur_value != value)  {
      //   printf("afl_trace store in host:0x%x, guest:0x%x, value:0x%x, cur_value:0x%x\n", host_addr, guest_addr, value, cur_value);
      //   // exit(10);
      // }
      g_hash_table_insert(aflMemHT, key, value);
    }
}

void afl_trace_tcg_st(CPUArchState *env, target_ulong guest_addr, target_ulong value)
{
  CPUArchState* eenv = current_cpu->env_ptr;
  afl_trace_st(eenv, NULL, guest_addr, value, AFL_TRACE_GETPC());
}