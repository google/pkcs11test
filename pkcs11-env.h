#ifndef PKCS11_ENV_H
#define PKCS11_ENV_H
// Copyright 2013-2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/* From 2.1 of [PKCS11-base-v2.40]: Cryptoki structures SHALL be packed with 1-byte alignment. */
#if defined(STRICT_P11)
#  pragma pack(push, 1)
#endif

/* The following definitions need to be provided to the preprocessor before the PKCS#11 header file can be included */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#ifdef PKCS11_LONG_SIZE
 #include <stdint.h>
 #if PKCS11_LONG_SIZE==32
 typedef uint32_t PKCS11_ULONG_TYPE;
 typedef int32_t PKCS11_LONG_TYPE;
 #elif PKCS11_LONG_SIZE==64
 typedef uint64_t PKCS11_ULONG_TYPE;
 typedef int64_t PKCS11_LONG_TYPE;
 #else
 #error "Invalid value for PKCS11_LONG_SIZE, defaulting to long"
 typedef unsigned long int PKCS11_ULONG_TYPE;
 typedef long int PKCS11_LONG_TYPE;
 #endif
#else
 typedef unsigned long int PKCS11_ULONG_TYPE;
 typedef long int PKCS11_LONG_TYPE;
#endif
#include <pkcs11.h>

#if defined(STRICT_P11)
#  pragma pack(pop)
#endif

#endif  // PKCS11_ENV_H
