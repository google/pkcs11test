#ifndef GLOBALS_H
#define GLOBALS_H

#include "pkcs11-env.h"
#include <pkcs11.h>

// Set of function pointers holding PKCS#11 implementation.
extern CK_FUNCTION_LIST_PTR g_fns;
// Slot to perform tests against.
extern CK_SLOT_ID g_slot_id;
// User PIN.
extern const char* g_user_pin;

#endif  // GLOBALS_H
