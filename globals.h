#ifndef GLOBALS_H
#define GLOBALS_H

#include "pkcs11-env.h"
#include <pkcs11.h>

// Set of function pointers holding PKCS#11 implementation.
extern CK_FUNCTION_LIST_PTR g_fns;
// Slot to perform tests against.
extern CK_SLOT_ID g_slot_id;
// Whether the token needs the user to login.
extern bool g_login_required;
// User PIN.  Only used if g_login_required.
extern const char* g_user_pin;
// Security Officer PIN.  Only used if g_login_required.
extern const char* g_so_pin;

#endif  // GLOBALS_H
