// C headers
#include <unistd.h>
#include <dlfcn.h>

// C++ headers
#include <cstdlib>
#include <iostream>
#include <string>

// Local headers
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace {

void usage() {
  cerr << "  -v      : verbose output" << endl;
  cerr << "  -m name : name of PKCS#11 library" << endl;
  cerr << "  -l path : path to PKCS#11 library" << endl;
  cerr << "  -s id   : slot ID to perform tests against" << endl;
  cerr << "  -u pwd  : user PIN/password" << endl;
  cerr << "  -o pwd  : security officer PIN/password" << endl;
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
  while ((opt = getopt(argc, argv, "vl:m:s:u:o:h")) != -1) {
    switch (opt) {
      case 'v':
        g_verbose = true;
        break;
      case 'l':
        module_path = optarg;
        break;
      case 'm':
        module_name = optarg;
        break;
      case 's':
        g_slot_id = atoi(optarg);
        break;
      case 'u':
        g_user_pin = optarg;
        break;
      case 'o':
        g_so_pin = optarg;
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

  // Determine the characteristics of the specified token/slot.
  CK_RV rv;
  rv = g_fns->C_Initialize(NULL_PTR);
  if (rv != CKR_OK) {
    cerr << "Failed to C_Initialize (" << rv_name(rv) << ")" << endl;
    exit(1);
  }
  CK_SLOT_INFO slot_info = {0};
  rv = g_fns->C_GetSlotInfo(g_slot_id, &slot_info);
  if (rv != CKR_OK) {
    cerr << "Failed to get slot info (" << rv_name(rv) << ") for slot " << g_slot_id << endl;
    exit(1);
  }
  if (!(slot_info.flags & CKF_TOKEN_PRESENT)) {
    cerr << "Slot " << g_slot_id << " has no token present." << endl;
    exit(1);
  }
  CK_TOKEN_INFO token = {0};
  rv = g_fns->C_GetTokenInfo(g_slot_id, &token);
  if (rv != CKR_OK) {
    cerr << "Failed to get token info (" << rv_name(rv) << ") for token in slot " << g_slot_id << endl;
    exit(1);
  }
  rv = g_fns->C_Finalize(NULL_PTR);
  if (rv != CKR_OK) {
    cerr << "Failed to C_Finalize (" << rv_name(rv) << ")" << endl;
    exit(1);
  }
  g_token_flags = token.flags;

  if (!(g_token_flags & CKF_LOGIN_REQUIRED)) {
    // Disable all tests that require login in their fixture.
    // This unfortunately relies on some gTest innards.
    string filter(testing::GTEST_FLAG(filter).c_str());
    if (!filter.empty()) filter += ":";
    filter += "-*UserSessionTest.*:*SOSessionTest.*";
    testing::GTEST_FLAG(filter) = filter;
  }

  return RUN_ALL_TESTS();
}
