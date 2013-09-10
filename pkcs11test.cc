// C headers
#include <unistd.h>
#include <dlfcn.h>

// C++ headers
#include <cstdlib>
#include <iostream>
#include <string>

// Local headers
#include "gtest/gtest.h"
#include "globals.h"

using namespace std;  // So sue me

namespace {

void usage() {
  cerr << "  -m name : name of PKCS#11 library" << endl;
  cerr << "  -l path : path to PKCS#11 library" << endl;
  cerr << "  -s id   : slot ID to perform tests against" << endl;
  exit(1);
}

CK_C_GetFunctionList load_pkcs11_library(const char* libpath, const char* libname) {
  if (libname == nullptr) {
    cerr << "No library name provided" << endl;
    exit(1);
  }
  string fullname;
  if (libpath != nullptr) {
    fullname = libpath;
    if (fullname.at(fullname.size() - 1) != '/') {
      fullname += '/';
    }
  }
  fullname += libname;
  if (fullname.empty()) {
    cerr << "No library name provided" << endl;
    exit(1);
  }

  void* lib = dlopen(fullname.c_str(), RTLD_NOW);
  if (lib == nullptr) {
    cerr << "Failed to dlopen(" << fullname << ")" << endl;
    exit(1);
  }

  void* fn = dlsym(lib, "C_GetFunctionList");
  if (fn == nullptr) {
    cerr<< "Failed to dlsym(\"C_GetFunctionList\")" << endl;
    exit(1);
  }
  return (CK_C_GetFunctionList)fn;
}

}  // namespace


int main(int argc, char* argv[]) {
  // Let gTest have first crack at the arguments.
  ::testing::InitGoogleTest(&argc, argv);

  // Retrieve PKCS module location.
  int opt;
  const char* module_name = nullptr;
  const char* module_path = nullptr;
  while ((opt = getopt(argc, argv, "l:m:s:h")) != -1) {
    switch (opt) {
      case 'l':
        module_path = optarg;
        break;
      case 'm':
        module_name = optarg;
        break;
      case 's':
        g_slot_id = atoi(optarg);
        break;
      case 'h':
      default:
        usage();
        break;
    }
  }

  // Load the module.
  CK_C_GetFunctionList get_fn_list = load_pkcs11_library(module_path, module_name);

  // Retrieve the set of function pointers (C_GetFunctionList is the only function it's OK to call before C_Initialize).
  if (get_fn_list(&g_fns) != CKR_OK) {
    cerr << "Failed to retrieve list of functions" << endl;
    exit(1);
  }

  return RUN_ALL_TESTS();
}
