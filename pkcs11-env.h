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



#ifdef _WIN32

/* Specifies that the function is a DLL entry point. */
#define CK_IMPORT_SPEC __declspec(dllimport)

#ifdef CRYPTOKI_EXPORTS
 /* Specified that the function is an exported DLL entry point. */
#define CK_EXPORT_SPEC __declspec(dllexport) 
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC 
#endif

 /* Ensures the calling convention for Win32 builds */
#define CK_CALL_SPEC __cdecl

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_EXPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (CK_CALL_SPEC CK_PTR name)



#else  //_WIN32

/* UNIX version */
/* The following definitions need to be provided to the preprocessor before the PKCS#11 header file can be included */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)


#endif //_WIN32

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <pkcs11.h>

#if defined(STRICT_P11)
#  pragma pack(pop)
#endif

#endif  // PKCS11_ENV_H
