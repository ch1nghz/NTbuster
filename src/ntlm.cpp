#include <iostream>
#include <dlfcn.h>

const char* gen_ntlm(const std::string& data) {
    // Load the Rust library dynamically
    void *lib = dlopen("./lib/newlib.dylib", RTLD_LAZY);
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

