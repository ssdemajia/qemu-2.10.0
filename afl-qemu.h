#include <sys/shm.h>

#include "../../config.h"
#include "qemu/osdep.h"
#include "exec/cpu_ldst.h"
/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_QEMU_CPU_SNIPPET1 do { \
    afl_request_tsl(pc, cs_base, flags); \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2(env, pc) do { \
    afl_check_pc(env, pc); \
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
unsigned long aflPanicAddr = (unsigned long)-1;
unsigned long aflDmesgAddr = (unsigned long)-1;

/* Set in the child process in forkserver mode: */

unsigned char afl_fork_child = 0;
int afl_wants_cpu_to_stop = 0;
unsigned int afl_forksrv_pid;

/* Instrumentation ratio: */

static unsigned int afl_inst_rms = MAP_SIZE;

/* Function declarations. */
static void afl_check_pc(CPUArchState* env, target_ulong);
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
}
static void
myIterator(gpointer key, gpointer value, gpointer env)
{
    // cpu_stl_data_ra(current_cpu->env_ptr, *(uint32_t*)key, *(uint32_t*)value, NULL);
    // printf(user_data, *(gint*)key, value);
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
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 256; j++) {
      env->tlb_table[i][j].addr_code = backupTLBTable[i][j].addr_code;
      env->tlb_table[i][j].addr_write = backupTLBTable[i][j].addr_write;
      env->tlb_table[i][j].addr_read = backupTLBTable[i][j].addr_read;
      env->tlb_table[i][j].addend = backupTLBTable[i][j].addend;
    }
  }
  g_hash_table_foreach(aflMemHT, myIterator, env);
  // g_hash_table_remove_all(aflMemHT);
}

FILE *afl_fp = NULL;
void LoadTestCase(CPUArchState* env) {
  // printf("[SSSS]load testcase\n");
  const char* filepath = "/home/ss/work/vxafl/test_input.txt";
  // uintptr_t ra = GETPC();
  // printf("esp addr:%x, eip addr:%x\n", env->regs[R_ESP], env->eip);
  // target_long ret_ptr = cpu_ldl_data_ra(env, env->regs[R_ESP], NULL);
  // printf("ret addr:%x\n", ret_ptr);
  // target_long ptr = cpu_ldl_data_ra(env, env->regs[R_ESP+4], NULL);
  // printf("arg addr:%x\n", ret_ptr);

  // // FILE *fp;
  // if (!afl_fp)
  //   afl_fp = fopen(filepath, "rb");
  // if (!afl_fp) {
  //   perror("Can't open file");
  //   exit(-1);
  // }
  // fseek(afl_fp, 0, SEEK_END);
  // size_t sz = ftell(afl_fp);
  // fseek(afl_fp, 0, SEEK_SET);
  // char ch = 0;
  // for (int i = 0; i < sz; i++) {
  //   printf("%c", ch);
  //   if (fread(&ch, 1, 1, afl_fp) == 0) {
  //     break;
  //   }
  //   cpu_stb_data_ra(env, ptr, ch, ra);
  // }
  // printf("\n");
}
/* Data structure passed around by the translate handlers: */

struct afl_tsl {
  target_ulong pc;
  target_ulong cs_base;
  uint64_t flags;
};



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

static ssize_t uninterrupted_read(int fd, void *buf, size_t cnt)
{
    ssize_t n;
    while((n = read(fd, buf, cnt)) == -1 && errno == EINTR)
        continue;
    return n;
}

/* Fork server logic, invoked once we hit _start. */

void afl_forkserver(CPUArchState *env) {

  static unsigned char tmp[4];

  //if (!afl_area_ptr) return;

  /* 通知afl，当前进程仍然存活 */
  // if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int status, t_fd[2];

    /* Whoops, parent dead? */

    // if (uninterrupted_read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll 
       read from t_fd[0], child will write to TSL_FD. */

    // if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    // close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) {
      printf("[SSSS]forkserver want to fork children failed\n");
      exit(4);
    }

    if (!child_pid) {

      /* 子进程. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    // close(TSL_FD);

    // if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    //afl_wait_tsl(env, t_fd[0]);

    /* Get and relay exit status to parent. */
    printf("[SSSS]parent waitpid\n");
    if (waitpid(child_pid, &status, 0) < 0) {
      printf("[SSSS]forkserver wait children pid failed\n");
      exit(6);
    }
    // if (write(FORKSRV_FD + 1, &status, 4) != 4) {
    //   printf("[SSSS]forkserver want to communicate afl failed\n");
    //   exit(7);
    // }
    if (WIFSIGNALED(status)) {
      printf("[SSSS] child exited via signal %d\n", WTERMSIG(status));
    }
    printf("[SSSS]forkserver get children status: %x %x\n", status, WEXITSTATUS(status));
    sleep(1);
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
  // return;
  if (aflStatus == AFL_START || aflStatus == AFL_DOING) {
    cur_loc = aflHash(cur_loc);
    if(cur_loc)
      helper_aflMaybeLog(cur_loc);
  }
}

static void afl_check_pc(CPUArchState* env, target_ulong pc) {
  if(pc == afl_entry_point && pc && aflStatus == AFL_WAITTING) {
    aflStart = 1;
    aflStatus = AFL_START;
    afl_wants_cpu_to_stop = 1;
    // printf("[SSSS]AFLSTART pc is %x\n", pc);
    aflMemHT = g_hash_table_new(g_int_hash, g_int_equal);
    afl_setup();
    StoreCPUState(env);
    LoadTestCase(env);
  }
  else if (aflStatus == AFL_DOING) {
    if (pc == 0x40a250) {
      // printf("idleEnter\n");
      afl_wants_cpu_to_stop = 1;
      aflChildrenStatus = 0;
      aflStatus = AFL_DONE;
    }
    if (pc == 0x40cb30) {
      // printf("reschedule\n");
      afl_wants_cpu_to_stop = 1;
      aflChildrenStatus = 0;
      aflStatus = AFL_DONE;
    }
  }
}
/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc      = pc;
  t.cs_base = cb;
  t.flags   = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}


/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUArchState *env, int fd) {

  struct afl_tsl t;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
      break;

    if(0 && env) {
#ifdef CONFIG_USER_ONLY
        tb_find_slow(env, t.pc, t.cs_base, t.flags);
#else
        /* if the child system emulator pages in new code and then JITs it, 
        and sends its address to the server, the server cannot also JIT it 
        without having it's guest's kernel page the data in !  
        so we will only JIT kernel code segment which shouldnt page.
        */
        // XXX this monstrosity must go!
        if(t.pc >= 0xffffffff81000000 && t.pc <= 0xffffffff81ffffff) {
            //printf("wait_tsl %lx -- jit\n", t.pc); fflush(stdout);
            tb_find_slow(env, t.pc, t.cs_base, t.flags);
        } else {
            //printf("wait_tsl %lx -- ignore nonkernel\n", t.pc); fflush(stdout);
        }
#endif
    } else {
        //printf("wait_tsl %lx -- ignore\n", t.pc); fflush(stdout);
    }

  }

  close(fd);

}

#define AFL_TRACE_GETPC() ((void *)((unsigned long)__builtin_return_address(0) - 1))

void afl_trace_st(unsigned long host_addr, uint32_t guest_addr, uint32_t value, void *retaddr) {
    // if (aflStatus == AFL_DOING || aflStatus == AFL_START) {
    //   if (g_hash_table_lookup(aflMemHT, &guest_addr)) {
    //     return;
    //   }
    //   CPUArchState* env = current_cpu->env_ptr;
    //   uint32_t cur_value = cpu_ldl_data_ra(env, guest_addr, AFL_TRACE_GETPC());
    //   // printf("afl_trace store in host:0x%x, guest:0x%x, value:0x%x, cur_value:0x%x\n", host_addr, guest_addr, value, cur_value);
    //   g_hash_table_insert(aflMemHT, &guest_addr, &cur_value);
    // }
}

void afl_trace_tcg_st(unsigned long host_addr, unsigned int guest_addr, unsigned int value)
{
    afl_trace_st(host_addr, guest_addr, value, AFL_TRACE_GETPC());
}