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
// Whether to perform tests that initialize the token.  These wipe any existing
// token contents, so need to be explicitly enabled.
extern bool g_init_token;
// The flags describing the capabilities of the token.
extern CK_FLAGS g_token_flags;
// The token label.
extern CK_UTF8CHAR g_token_label[32];  // blank padded
// User PIN.  Only used if (g_token_flags & CKF_LOGIN_REQUIRED).
extern const char* g_user_pin;
// Security Officer PIN.  Only used if (g_token_flags & CKF_LOGIN_REQUIRED).
extern const char* g_so_pin;
// User PIN after token reset.  Only used if (g_token_flags & CKF_LOGIN_REQUIRED).
extern const char* g_reset_user_pin;
// Security Officer PIN after token reset.  Only used if (g_token_flags & CKF_LOGIN_REQUIRED).
extern const char* g_reset_so_pin;

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

// Global variables for boolean values.  These are useful in object
// attribute lists.
extern CK_BBOOL g_ck_false;
extern CK_BBOOL g_ck_true;

#endif  // GLOBALS_H
