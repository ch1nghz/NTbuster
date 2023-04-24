#include <iostream>
#include <dlfcn.h>
#include <sys/utsname.h>

const char* gen_ntlm(const std::string& data) {
    // Determine the name of the operating system
    struct utsname os_info;
    uname(&os_info);

    // Load the Rust library dynamically
    std::string lib_name;
    std::string os_name(os_info.sysname);
    if (os_name.compare("Linux") == 0) {
        lib_name = "./lib/libntlmhash.so";
    } else if (os_name.compare("Darwin") == 0) {
        lib_name = "./lib/libntlmhash.dylib";
    } else {
        std::cerr << "Unsupported operating system: " << os_info.sysname << std::endl;
        return nullptr;
    }

    void *lib = dlopen(lib_name.c_str(), RTLD_LAZY);
    if (!lib) {
        std::cerr << "Error loading Rust library: " << dlerror() << std::endl;
        return nullptr;
    }

    // Get a pointer to the gen() function
    typedef const char* (*gen)(const char*);
    gen generate_ntlm = reinterpret_cast<gen>(dlsym(lib, "gen"));
    if (!generate_ntlm) {
        std::cerr << "Error getting symbol: " << dlerror() << std::endl;
        dlclose(lib);
        return nullptr;
    }

    // Call the gen() function
    const char* hash_cstr = generate_ntlm(data.c_str());
    if (!hash_cstr) {
        std::cerr << "Error generating hash" << std::endl;
        dlclose(lib);
        return nullptr;
    }

    // Unload the Rust library
    dlclose(lib);

    return hash_cstr;
}
