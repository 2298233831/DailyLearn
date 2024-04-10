#include <jni.h>
#include <cstdlib>
#include <pthread.h>
#include <vector>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <unistd.h>
#include <mntent.h>
#include <android/log.h>
#include <atomic>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <asm-generic/mman-common.h>
#include <sys/mman.h>

#define KEY_VALID_FLAG (1 << 31)
#define TLS_SLOT_BIONIC_TLS  (9)

#define BIONIC_PTHREAD_KEY_COUNT 130

#if defined(__aarch64__)
# define __get_tls() ({ void** __val; __asm__("mrs %0, tpidr_el0" : "=r"(__val)); __val; })
#elif defined(__arm__)
# define __get_tls() ({ void** __val; __asm__("mrc p15, 0, %0, c13, c0, 3" : "=r"(__val)); __val; })
#endif
class pthread_key_data_t {
public:
    uintptr_t seq; // Use uintptr_t just for alignment, as we use pointer below.
    int* data;
};

struct pthread_key_internal_t {
    void* seq;
    void* key_destructor;
};
struct bionic_tls {
    pthread_key_data_t key_data[BIONIC_PTHREAD_KEY_COUNT];
    char buf[10120];
};

#if defined(__aarch64__)
# define __get_tls() ({ void** __val; __asm__("mrs %0, tpidr_el0" : "=r"(__val)); __val; })
#endif

static inline bionic_tls& __get_bionic_tls() {
    return *static_cast<bionic_tls*>(__get_tls()[TLS_SLOT_BIONIC_TLS]);
}

static inline pthread_key_data_t* get_thread_key_data() {
    return __get_bionic_tls().key_data;
}


// Bellow is Android 9

class Lock {
private:
    enum LockState {
        Unlocked = 0,
        LockedWithoutWaiter,
        LockedWithWaiter,
    };
    _Atomic(LockState) state;
    bool process_shared;
};

enum ThreadJoinState {
    THREAD_NOT_JOINED,
    THREAD_EXITED_NOT_JOINED,
    THREAD_JOINED,
    THREAD_DETACHED
};

#if defined(__arm__) || defined(__aarch64__)

#define MIN_TLS_SLOT            (-1) // update this value when reserving a slot
#define TLS_SLOT_BIONIC_TLS     (-1)
#define TLS_SLOT_THREAD_ID        1
// The maximum slot is fixed by the minimum TLS alignment in Bionic executables.
#define MAX_TLS_SLOT              7
#endif

#define BIONIC_TLS_SLOTS (MAX_TLS_SLOT - MIN_TLS_SLOT + 1)


class pthread_internal_t {
 public:
  class pthread_internal_t* next;
  class pthread_internal_t* prev;

  pid_t tid;

 private:
  pid_t cached_pid_;

 public:
  pid_t invalidate_cached_pid() {
    pid_t old_value;
    get_cached_pid(&old_value);
    set_cached_pid(0);
    return old_value;
  }

  void set_cached_pid(pid_t value) {
    cached_pid_ = value;
  }

  bool get_cached_pid(pid_t* cached_pid) {
    *cached_pid = cached_pid_;
    return (*cached_pid != 0);
  }

  pthread_attr_t attr;

  _Atomic(ThreadJoinState) join_state;

  __pthread_cleanup_t* cleanup_stack;

  void* (*start_routine)(void*);
  void* start_routine_arg;
  void* return_value;

  void* alternate_signal_stack;

  Lock startup_handshake_lock;

  size_t mmap_size;

  thread_local_dtor* thread_local_dtors;

  void* tls[BIONIC_TLS_SLOTS];

  pthread_key_data_t key_data[BIONIC_PTHREAD_KEY_COUNT];

#define __BIONIC_DLERROR_BUFFER_SIZE 512
  char dlerror_buffer[__BIONIC_DLERROR_BUFFER_SIZE];

  bionic_tls* bionic_tls;
}; // Android 8

#if defined(__arm__)

#elif defined(__aarch64__)


class thread_local_dtor {
public:
    thread_local_dtor* next;
};

#define KEY_DATA_OFF 16
#define KEY_MAP_CODE 0xa90157f6a9bd7bfd
#endif

#define MIN_TLS_SLOT            (-1) // update this value when reserving a slot
#define TLS_SLOT_BIONIC_TLS     (-1)
#define TLS_SLOT_THREAD_ID        1
#define MAX_TLS_SLOT              7

#define BIONIC_TLS_SLOTS (MAX_TLS_SLOT - MIN_TLS_SLOT + 1)

#define SEQ_KEY_IN_USE_BIT     0


static inline __always_inline pthread_internal_t* __get_thread() {
    return reinterpret_cast<pthread_internal_t *>(__get_tls()[TLS_SLOT_THREAD_ID]);
}

static inline bool SeqOfKeyInUse(uintptr_t seq) {
    return seq & (1 << SEQ_KEY_IN_USE_BIT);
}

static inline unsigned long MakeKeyInUse(unsigned long key) {
    return key | (1 << 31);
}

size_t get_module_base(const char* name){
    std::ifstream mapsFile("/proc/self/maps");
    std::string line;

    while (std::getline(mapsFile, line)) {
        std::istringstream iss(line);
        std::string range;
        std::string permissions;
        std::string offset;
        std::string device;
        std::string inode;
        std::string pathname;

        if (!(iss >> range >> permissions >> offset >> device >> inode >> pathname)) {
            continue;
        }
        // Check if the line contains the desired module
        if (pathname.find(name) != std::string::npos) {
            // Extract the start address from the range string
            std::string startAddressStr = range.substr(0, range.find('-'));
            std::stringstream ss;
            ss << std::hex << startAddressStr;
            uintptr_t startAddress;
            ss >> startAddress;

            return startAddress;
        }
    }
    return 0;  // Module not found
}

unsigned long get_symbol_value64(const char* filename, const char* target_name) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("File open error");
        return 0;
    }

    Elf64_Ehdr header;
    fread(&header, sizeof(header), 1, file);
    fseek(file, header.e_shoff, SEEK_SET);
    Elf64_Shdr* section_headers = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr) * header.e_shnum);
    fread(section_headers, sizeof(Elf64_Shdr), header.e_shnum, file);
    Elf64_Shdr* symtab_section = NULL;
    char* strtab = NULL;

    for (int i = 0; i < header.e_shnum; i++) {
        if (section_headers[i].sh_type == SHT_SYMTAB) {
            symtab_section = &section_headers[i];
            break;
        }
    }
    if (symtab_section) {
        int sym_count = symtab_section->sh_size / symtab_section->sh_entsize;
        Elf64_Sym* symtab = (Elf64_Sym*)malloc(sizeof(Elf64_Sym) * sym_count);
        fseek(file, symtab_section->sh_offset, SEEK_SET);
        fread(symtab, sizeof(Elf64_Sym), sym_count, file);

        if (symtab_section->sh_link != SHN_UNDEF) {
            Elf64_Shdr* strtab_section = &section_headers[symtab_section->sh_link];
            strtab = (char*)malloc(strtab_section->sh_size);
            fseek(file, strtab_section->sh_offset, SEEK_SET);
            fread(strtab, strtab_section->sh_size, 1, file);
        }
        unsigned long symbol_value = 0;
        for (int i = 0; i < sym_count; i++) {
            const char* symbol_name = strtab + symtab[i].st_name;
            if (strstr(symbol_name, target_name) != NULL) {
                symbol_value = symtab[i].st_value;
                break;
            }
        }
        free(symtab);
        free(strtab);
        fclose(file);
        return symbol_value;
    }
    free(section_headers);
    fclose(file);

    return 0;
}

pthread_key_internal_t* get_key_map(){
    const char* libname = "/system/lib64/libc.so";
    int key_map_offset = get_symbol_value64(libname,"key_map");
    return (pthread_key_internal_t *)(get_module_base("libc.so") + key_map_offset);
}

pthread_key_internal_t* get_thread_list() {
    const char* libname = "/system/lib64/libc.so";
    int thread_list_offset = get_symbol_value64(libname,"_ZL13g_thread_list");
    return (pthread_key_internal_t *)(get_module_base("libc.so") + thread_list_offset);
}

void Trap_key_data(pthread_key_data_t* keydata){
    // in android 11 , is 'auto keydata = get_thread_key_data();`
    for (int i = 0; i < BIONIC_PTHREAD_KEY_COUNT; ++i) {
        uintptr_t seq = keydata[i].seq;
        size_t *data = reinterpret_cast<size_t *>(keydata[i].data);
        if (SeqOfKeyInUse(seq) && data != nullptr) {
            if ((size_t)data > 0x7000000000) {
                if (mprotect((void*)((size_t)data & 0xFFFFFFFFFFFFF000),0x1000,PROT_READ|PROT_WRITE|PROT_EXEC) != 0) {
                    __android_log_print(ANDROID_LOG_ERROR, "Keydata", "Error index%d: %s",i, strerror(errno));
                } else {
                    size_t * double_data = (size_t*)keydata[i].data;
                    if( *(double_data + 1) == *(double_data + 10)
                            && *(double_data + 2) == *(double_data + 11)
                            && *(double_data + 1) - *(double_data + 0) == KEY_DATA_OFF){
                        __android_log_print(ANDROID_LOG_INFO, "TLS_DETCT", "key_data FINDDDDDDDDDDDDDDDDD\n");
                    }
                }
            }
        }
    }
}

void Trap_now_key_data(){
    auto keydata = __get_thread()->key_data;
    Trap_key_data(keydata);
}

void Trav_key_map(){
    pthread_key_internal_t* key_map_addr = get_key_map();
    for (int i = 0; i < BIONIC_PTHREAD_KEY_COUNT; ++i) {
        if(SeqOfKeyInUse((uintptr_t)key_map_addr[i].seq)
            && key_map_addr[i].key_destructor != nullptr) {
            uint64_t data = *(size_t*)key_map_addr[i].key_destructor;
            if (data == KEY_MAP_CODE){
                __android_log_print(ANDROID_LOG_INFO, "TLS_DETCT", "key_map FINDDDDDDDDDDDDDDDDD\n");
            }
        }
    }
}

void Trap_All_key_data() {
    pthread_key_internal_t* g_thread_list = get_thread_list();
    for (pthread_internal_t* t = reinterpret_cast<pthread_internal_t *>(g_thread_list)->next; t != nullptr; t = t->next) {
        __android_log_print(ANDROID_LOG_INFO, "Keydata", "thread_bionic:%p", t->key_data);
        auto keydata = t->key_data;
        Trap_key_data(keydata);
    }
}

extern "C" JNIEXPORT jint JNICALL
Java_com_sctf_tls_MainActivity_tlsfunc(
        JNIEnv* env,
        jobject /* this */) {
    __android_log_print(ANDROID_LOG_INFO, "Keydata", "begin");
    Trav_key_map();
    Trap_All_key_data();
    return 1;
}
