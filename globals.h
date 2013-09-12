/* -*- c++ -*- */
#ifndef GLOBALS_H
#define GLOBALS_H

#include "pkcs11-env.h"
#include <pkcs11.h>

#include <set>

// Set of function pointers holding PKCS#11 implementation.
extern CK_FUNCTION_LIST_PTR g_fns;
// Slot to perform tests against.
extern CK_SLOT_ID g_slot_id;
// Whether to emit verbose information.
extern bool g_verbose;
// Whether the token needs the user to login.
extern bool g_login_required;
// User PIN.  Only used if g_login_required.
extern const char* g_user_pin;
// Security Officer PIN.  Only used if g_login_required.
extern const char* g_so_pin;
// Whether the token has a random number generator.
extern bool g_rng;

// PKCS#11 mechanisms for encrypt/decrypt.
extern std::set<CK_MECHANISM_TYPE> encrypt_decrypt_mechanisms;
// PKCS#11 mechanisms for sign/verify.
extern std::set<CK_MECHANISM_TYPE> sign_verify_mechanisms;
// PKCS#11 mechanisms for sign/verify-recover.
extern std::set<CK_MECHANISM_TYPE> sign_verify_recover_mechanisms;
// PKCS#11 mechanisms for digest generation.
extern std::set<CK_MECHANISM_TYPE> digest_mechanisms;
// PKCS#11 mechanisms for key generation.
extern std::set<CK_MECHANISM_TYPE> generate_mechanisms;
// PKCS#11 mechanisms for wrap/unwrap.
extern std::set<CK_MECHANISM_TYPE> wrap_unwrap_mechanisms;
// PKCS#11 mechanisms for derive.
extern std::set<CK_MECHANISM_TYPE> derive_mechanisms;


#endif  // GLOBALS_H
