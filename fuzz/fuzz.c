#include "fuzz.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>

extern const char * vxWorks_path;   // vxWorks内核文件地址
extern const char * fuzz_entry;     // 模糊测试入口

static void read_symbol();
/*
    初始化
*/
void vxAFL_init()
{
    printf("[+] vxAFL init\n");
    read_symbol();
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
            vxAFL_entrypoint = sym_tab[i].st_value;
        }
        if (strcmp("idleEnter", sym_str + sym_tab[i].st_name) == 0) {
            vxAFL_idleEnter = sym_tab[i].st_value;
        }
        if (strcmp("excStub0", sym_str + sym_tab[i].st_name) == 0) {
            vxAFL_excStub0 = sym_tab[i].st_value;
        }
        if (strcmp("excStub", sym_str + sym_tab[i].st_name) == 0) {
            vxAFL_excStub = sym_tab[i].st_value;
        }
        if (strcmp("excPanicShow", sym_str + sym_tab[i].st_name) == 0) {
            vxAFL_excPanicShow = sym_tab[i].st_value;
        }
        if (strcmp("reschedule", sym_str + sym_tab[i].st_name) == 0) {
            vxAFL_reschedule = sym_tab[i].st_value;
        }
    }
    if (!vxAFL_entrypoint) {
        printf("[-] Can't found this symbol[%s] in VxWorks kernel\n", fuzz_entry);
        exit(-1);
    }
    printf("[+] Fuzz entry symbol is %s, entryaddr: 0x%x, "
        "vxAFL_idleEnter: 0x%x,"
        "vxAFL_excStub0: 0x%x," "vxAFL_excStub: 0x%x,"
        "vxAFL_excPanicShow: 0x%x,\n", 
        fuzz_entry, vxAFL_entrypoint, vxAFL_idleEnter, vxAFL_excStub0,
        vxAFL_excStub, vxAFL_excPanicShow);
    printf("[+] Read Symbol complete\n");
}
