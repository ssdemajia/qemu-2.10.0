#include "fuzz.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>

int vxAFL_notify_pipe[2];
int vxAFL_wants_cpu_to_stop;
CPUState * vxAFL_last_cpu; // 保存结束前的cpu状态

static pthread_t monitor_tid;
static pid_t vxAFL_forkserv_pid;
static pid_t vxAFL_child_pid;
static unsigned char vxAFL_fork_child;

static bool has_setup = false;

static unsigned char *afl_area_ptr;
static unsigned int afl_inst_rms = MAP_SIZE;
unsigned long afl_entry_point, /* ELF entry point (_start) */
             afl_start_code,  /* .text start pointer      */
             afl_end_code;    /* .text end pointer        */
static unsigned long entry_point;
static int vms_fd;

extern const char * vxWorks_path;   // vxWorks内核文件地址
extern const char * fuzz_entry;     // 模糊测试入口
extern QemuThread *single_tcg_cpu_thread;  // 在cpus.c中
static void read_symbol();
static void setup();
static void forkserver();
static void log(target_ulong pc);
/*
    初始化
*/
void vxAFL_init()
{
    printf("[+] vxAFL init\n");
    read_symbol();
    setup();
    printf("[+] Say hello to fuzzer\n");
    write(FORKSRV_FD + 1, "hello", 4);
}

void vxAFL_run(CPUState *cpu, TranslationBlock *itb)
{
    if (itb->pc == entry_point && !has_setup)
    {
        LOG("found entry point");
        has_setup = true; 
        vxAFL_wants_cpu_to_stop = 1; // 退出所有cpu的执行
        cpu->exit_request = 1; // 退出当前cpu的执行
    } 
    // if (has_setup) log(itb->pc);
}

void vxAFL_notify_handler(void *ctx) {
    printf("[+] I get!\n");
    qemu_set_fd_handler (vxAFL_notify_pipe[0], NULL, NULL, NULL); // 不再需要注册
    close(vxAFL_notify_pipe);

    forkserver(); // 子进程从forkserver函数中返回，需要恢复它的cpu
    first_cpu = vxAFL_last_cpu;
    single_tcg_cpu_thread = NULL;
    qemu_tcg_init_vcpu(vxAFL_last_cpu);

    LOG("I'm child!");
}

/*
    当运行到目标函数时进行模糊测试
*/
static void forkserver()
{
    LOG("start forkserver");
    static unsigned char tmp[4];
    vxAFL_forkserv_pid = getpid();
    
    while (1)
    {
        pid_t child_pid;
        int status, t_fd[2];

        // 查看fuzzer是否已经退出
        if (read(FORKSRV_FD, tmp, 4) != 4) {
            LOG("Fuzzer has been exist");
            exit(2);
        }
        child_pid = fork();
        if (child_pid < 0) {
            LOG("Fuzzer fork error");
            exit(3);
        }
            
        if (!child_pid)
        { // 子进程
            close(FORKSRV_FD);
            close(FORKSRV_FD + 1);
            return;
        }
        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
            LOG("Write child pid error");
            exit(5);
        }
        if (waitpid(child_pid, &status, 0) < 0) {
            LOG("Wait child error");
            exit(6);
        }
        if (write(FORKSRV_FD + 1, &status, 4) != 4) {
            LOG("Write child status error");
            exit(7);
        }
    }
}
/*
*   读取vxWorks文件内核
*/
static void read_symbol()
{
    printf("[*] Read Symbol from vxWorks kernel path:%s\n", vxWorks_path);
    if (!vxWorks_path) {
        printf("[-] Can't open vxWorks kernel path:%s\n");
        exit(1);
    }
    if (!fuzz_entry) {
        printf("[-] Can't fuzz entry\n");
        exit(-1);
    }
    int file = open(vxWorks_path, O_RDONLY);
    if (!file) {
        printf("[-] Can't open %s to read symbol\n", vxWorks_path);
        exit(-1);
    }
    struct elf32_hdr *ehdr;
    struct elf32_shdr *shdr;

    struct stat st;
    fstat(file, &st);
    char* mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, file, 0);
    if (mem == MAP_FAILED) {
        printf("[-] mmap failed at %s:%d\n", __FILE__, __LINE__);
        exit(-1);
    }

    ehdr = (struct elf32_hdr*)mem;
    shdr = (struct elf32_shdr*)&mem[ehdr->e_shoff];
    if (mem[0] != 0x7f && strcmp(ehdr->e_ident, "ELF") && ehdr->e_type != ET_EXEC) {
        printf("[-] Target isn't elf file at %s:%d\n", __FILE__, __LINE__);
        exit(-1);
    }
    char *section_str = &mem[shdr[ehdr->e_shstrndx].sh_offset];
    Elf32_Sym* sym_tab;
    int sym_tab_size;
    char* sym_str;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        printf("  [%2d]section:%12s\toffset: 0x%08x\taddr:%12d\n", i, &section_str[shdr[i].sh_name], shdr[i].sh_offset, shdr[i].sh_addr); 
        if (strcmp(".symtab", &section_str[shdr[i].sh_name]) == 0) { // .symtab section
            sym_tab = &mem[shdr[i].sh_offset];
            sym_tab_size = shdr[i].sh_size;
        }
        if (strcmp(".strtab", &section_str[shdr[i].sh_name]) == 0) {
            sym_str = &mem[shdr[i].sh_offset];
        }
    }

    for (int i = 0; i < sym_tab_size/sizeof(Elf32_Sym); i++) {
        if (strcmp(fuzz_entry, sym_str + sym_tab[i].st_name) == 0) {
            entry_point = sym_tab[i].st_value;
        }
    }
    if (!entry_point) {
        printf("[-] Can't found this symbol[%s] in VxWorks kernel\n", fuzz_entry);
        exit(-1);
    }
    printf("[+] Fuzz entry symbol is %s, addr: %x\n", fuzz_entry, entry_point);
    printf("[+] Read Symbol complete\n");
}

/* 设置share memory */
static void setup()
{
    printf("[*] set up share memory\n");

    char *id_str = getenv(SHM_ENV_VAR),
         *inst_r = getenv("AFL_INST_RATIO");

    int shm_id;

    if (inst_r)
    {

        unsigned int r;

        r = atoi(inst_r);

        if (r > 100)
            r = 100;
        if (!r)
            r = 1;

        afl_inst_rms = MAP_SIZE * r / 100;
    }

    if (id_str)
    {

        shm_id = atoi(id_str);
        afl_area_ptr = shmat(shm_id, NULL, 0);

        if (afl_area_ptr == (void *)-1)
            exit(1);


        if (inst_r)
            afl_area_ptr[0] = 1;
    }

    if (getenv("AFL_INST_LIBS"))
    {

        afl_start_code = 0;
        afl_end_code = (unsigned long)-1;
    }
    printf("[+] share memory at 0x%p\n", afl_area_ptr);
}

static void log(target_ulong cur_loc) {
    if (!afl_area_ptr) return;
    static __thread unsigned long prev_loc; // 上一次的pc
    afl_area_ptr[cur_loc ^ prev_loc]++;
    prev_loc = cur_loc >> 1;
}