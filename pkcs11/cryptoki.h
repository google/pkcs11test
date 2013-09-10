// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_PKCS11_CRYPTOKI_H_
#define CHAPS_PKCS11_CRYPTOKI_H_

#define EXPORT_SPEC __attribute__ ((visibility ("default")))

// The following defines are required by pkcs11.h.
#define CK_PTR *
#define CK_DEFINE_FUNCTION(return_type, function_name) \
    EXPORT_SPEC return_type function_name
#define CK_DECLARE_FUNCTION(return_type, function_name) \
    EXPORT_SPEC return_type function_name
#define CK_DECLARE_FUNCTION_POINTER(return_type, function_name) \
    return_type (CK_PTR function_name)
#define CK_CALLBACK_FUNCTION(return_type, function_name) \
    return_type (CK_PTR function_name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#endif  // CHAPS_PKCS11_CRYPTOKI_H_
