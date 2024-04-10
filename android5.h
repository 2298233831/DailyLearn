//test
# define __get_tls() ({ void** __val; __asm__("mrs %0, tpidr_el0" : "=r"(__val)); __val; })

#define BIONIC_ALIGN(value, alignment) \
(((value) + (alignment) - 1) & ~((alignment) - 1))

#define GLOBAL_INIT_THREAD_LOCAL_BUFFER_COUNT 5

#if defined(USE_JEMALLOC)
/* jemalloc uses 5 keys for itself. */
#define BIONIC_TLS_RESERVED_SLOTS (GLOBAL_INIT_THREAD_LOCAL_BUFFER_COUNT + 5)
#else
#define BIONIC_TLS_RESERVED_SLOTS GLOBAL_INIT_THREAD_LOCAL_BUFFER_COUNT
#endif

#define _POSIX_THREAD_KEYS_MAX 128
#define PTHREAD_KEYS_MAX _POSIX_THREAD_KEYS_MAX
#define BIONIC_TLS_SLOTS BIONIC_ALIGN(PTHREAD_KEYS_MAX + TLS_SLOT_FIRST_USER_SLOT + BIONIC_TLS_RESERVED_SLOTS, 4)
#define TLSMAP_BITS       32
#define TLSMAP_WORDS      ((BIONIC_TLS_SLOTS+TLSMAP_BITS-1)/TLSMAP_BITS)
#define TLSMAP_WORD(m,k)  (m).map[(k)/TLSMAP_BITS]
#define TLSMAP_MASK(k)    (1U << ((k)&(TLSMAP_BITS-1)))
#define LIB_NAME "/system/lib64/libc.so"

enum {
    TLS_SLOT_SELF = 0, // The kernel requires this specific slot for x86.
    TLS_SLOT_THREAD_ID,
    TLS_SLOT_ERRNO,

    // These two aren't used by bionic itself, but allow the graphics code to
    // access TLS directly rather than using the pthread API.
    TLS_SLOT_OPENGL_API = 3,
    TLS_SLOT_OPENGL = 4,

    // This slot is only used to pass information from the dynamic linker to
    // libc.so when the C library is loaded in to memory. The C runtime init
    // function will then clear it. Since its use is extremely temporary,
    // we reuse an existing location that isn't needed during libc startup.
    TLS_SLOT_BIONIC_PREINIT = TLS_SLOT_OPENGL_API,

    TLS_SLOT_STACK_GUARD = 5, // GCC requires this specific slot for x86.
    TLS_SLOT_DLERROR,

    TLS_SLOT_FIRST_USER_SLOT // Must come last!
};


typedef void (*key_destructor_t)(void*);

struct tls_map_t {
    bool is_initialized;
    /* bitmap of allocated keys */
    uint32_t map[TLSMAP_WORDS];
    key_destructor_t key_destructors[BIONIC_TLS_SLOTS];
};

class ScopedTlsMapAccess {
public:
    ScopedTlsMapAccess() {
        Lock();

        // If this is the first time the TLS map has been accessed,
        // mark the slots belonging to well-known keys as being in use.
        // This isn't currently necessary because the well-known keys
        // can only be accessed directly by bionic itself, do not have
        // destructors, and all the functions that touch the TLS map
        // start after the maximum well-known slot.
        if (!s_tls_map_.is_initialized) {
            for (pthread_key_t key = 0; key < TLS_SLOT_FIRST_USER_SLOT; ++key) {
                SetInUse(key, NULL);
            }
            s_tls_map_.is_initialized = true;
        }
    }

    ~ScopedTlsMapAccess() {
        Unlock();
    }

    int CreateKey(pthread_key_t* result, void (*key_destructor)(void*)) {
        // Take the first unallocated key.
        for (int key = 0; key < BIONIC_TLS_SLOTS; ++key) {
            if (!IsInUse(key)) {
                SetInUse(key, key_destructor);
                *result = key;
                return 0;
            }
        }

        // We hit PTHREAD_KEYS_MAX. POSIX says EAGAIN for this case.
        return EAGAIN;
    }

    void DeleteKey(pthread_key_t key) {
        TLSMAP_WORD(s_tls_map_, key) &= ~TLSMAP_MASK(key);
        s_tls_map_.key_destructors[key] = NULL;
    }

    bool IsInUse(pthread_key_t key) {
        return (TLSMAP_WORD(s_tls_map_, key) & TLSMAP_MASK(key)) != 0;
    }

    void SetInUse(pthread_key_t key, void (*key_destructor)(void*)) {
        TLSMAP_WORD(s_tls_map_, key) |= TLSMAP_MASK(key);
        s_tls_map_.key_destructors[key] = key_destructor;
    }

    // Called from pthread_exit() to remove all TLS key data
    // from this thread's TLS area. This must call the destructor of all keys
    // that have a non-NULL data value and a non-NULL destructor.
    void CleanAll() {
        void** tls = __get_tls();

        // Because destructors can do funky things like deleting/creating other
        // keys, we need to implement this in a loop.
        for (int rounds = PTHREAD_DESTRUCTOR_ITERATIONS; rounds > 0; --rounds) {
            size_t called_destructor_count = 0;
            for (int key = 0; key < BIONIC_TLS_SLOTS; ++key) {
                if (IsInUse(key)) {
                    void* data = tls[key];
                    void (*key_destructor)(void*) = s_tls_map_.key_destructors[key];

                    if (data != NULL && key_destructor != NULL) {
                        // we need to clear the key data now, this will prevent the
                        // destructor (or a later one) from seeing the old value if
                        // it calls pthread_getspecific() for some odd reason

                        // we do not do this if 'key_destructor == NULL' just in case another
                        // destructor function might be responsible for manually
                        // releasing the corresponding data.
                        tls[key] = NULL;

                        // because the destructor is free to call pthread_key_create
                        // and/or pthread_key_delete, we need to temporarily unlock
                        // the TLS map
                        Unlock();
                        (*key_destructor)(data);
                        Lock();
                        ++called_destructor_count;
                    }
                }
            }

            // If we didn't call any destructors, there is no need to check the TLS data again.
            if (called_destructor_count == 0) {
                break;
            }
        }
    }

private:
    static tls_map_t s_tls_map_;
    static pthread_mutex_t s_tls_map_lock_;

    void Lock() {
        pthread_mutex_lock(&s_tls_map_lock_);
    }

    void Unlock() {
        pthread_mutex_unlock(&s_tls_map_lock_);
    }
};

unsigned long get_symbol_value(const char* filename,const char* target_name,int len) {
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
            if (strstr(symbol_name, target_name) != NULL && strlen(symbol_name) == len) {
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

// size_t get_module_base(){
//     int offset = get_symbol_value(LIB_NAME,"puts",4);
//     //__android_log_print(ANDROID_LOG_INFO, "Keydata", "offset: %p", offset);
//     return (size_t) puts - offset;
// }

size_t get_module_base0(const char* name){
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

//static tls_map_t s_tls_map_;

tls_map_t* get_tls_map(){
    const char* libname = LIB_NAME;
    int tls_map_offset = get_symbol_value(libname,"_ZN18ScopedTlsMapAccess10s_tls_map_E",36);
    return (tls_map_t *)(get_module_base() + tls_map_offset);
}

void tryGet(){
    void** tls = __get_tls();
    tls_map_t* tls_map_off = get_tls_map();
    __android_log_print(ANDROID_LOG_INFO, "tls_map", "tls_map_addr %p", get_tls_map());

}
