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

#include "pkcs11-describe.h"

#include <cassert>
#include <cstdarg>
#include <sstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <map>

using namespace std;  // So sue me.

namespace pkcs11 {

namespace {
  char hex_nibble[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                       'a', 'b', 'c', 'd', 'e', 'f'};
}  // namespace

string hex_data(CK_BYTE_PTR p, int len) {
  stringstream ss;
  for (int ii = 0; ii < len; ii++) {
    unsigned char b = p[ii];
    ss << hex_nibble[b >> 4] << hex_nibble[b & 0xF];
  }
  return ss.str();
}

string hex_decode(string hex_value) {
  bool high_nibble = true;
  stringstream ss;
  int value = 0;
  for (char c : hex_value) {
    int nibble;
    if (c >= '0' && c <= '9') {
      nibble = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      nibble = 10 + (c - 'a');
    } else if (c >= 'A' && c <= 'F') {
      nibble = 10 + (c - 'A');
    } else {
      exit(1);
    }
    if (high_nibble) {
      value = (nibble << 4);
    } else {
      value |= nibble;
      ss << static_cast<char>(value);
    }
    high_nibble = !high_nibble;
  }
  return ss.str();
}

string rv_name(CK_RV val) {
  // PKCS#11 s11.1: Function return values
  switch (val) {
    case CKR_OK: return "CKR_OK";
    case CKR_CANCEL: return "CKR_CANCEL";
    case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
    case CKR_NO_EVENT: return "CKR_NO_EVENT";
    case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
    case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
    case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
    case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
    case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
    case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
    case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
    case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
    case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
    case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
    case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
    case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
    case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
    case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
    case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
    case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
    case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
    case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
    case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
    case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
    case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
    case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
    case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
    case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
    case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
    case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
    case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
    case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
    case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
    case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
    case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
    case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
    case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
    case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
    case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
    case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
    case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
    case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
    case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
    case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
    case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
    case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
    case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
    case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
    case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
    case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
    case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
    case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
    case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
    case CKR_NEW_PIN_MODE: return "CKR_NEW_PIN_MODE";
    case CKR_NEXT_OTP: return "CKR_NEXT_OTP";
    case CKR_FUNCTION_REJECTED: return "CKR_FUNCTION_REJECTED";
    case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
    default: return "UNKNOWN";
  }
}

string user_type_name(CK_USER_TYPE val) {
  switch (val) {
    case CKU_SO: return "CKU_SO";
    case CKU_USER: return "CKU_USER";
    case CKU_CONTEXT_SPECIFIC: return "CKU_CONTEXT_SPECIFIC";
    default: return "UNKNOWN";
  }
}

string key_type_name(CK_KEY_TYPE val) {
  switch (val) {
    case CKK_RSA: return "CKK_RSA";
    case CKK_DSA: return "CKK_DSA";
    case CKK_DH: return "CKK_DH";
    case CKK_EC: return "CKK_EC";
    case CKK_X9_42_DH: return "CKK_X9_42_DH";
    case CKK_KEA: return "CKK_KEA";
    case CKK_GENERIC_SECRET: return "CKK_GENERIC_SECRET";
    case CKK_RC2: return "CKK_RC2";
    case CKK_RC4: return "CKK_RC4";
    case CKK_DES: return "CKK_DES";
    case CKK_DES2: return "CKK_DES2";
    case CKK_DES3: return "CKK_DES3";
    case CKK_CAST: return "CKK_CAST";
    case CKK_CAST3: return "CKK_CAST3";
    case CKK_CAST128: return "CKK_CAST128";
    case CKK_RC5: return "CKK_RC5";
    case CKK_IDEA: return "CKK_IDEA";
    case CKK_SKIPJACK: return "CKK_SKIPJACK";
    case CKK_BATON: return "CKK_BATON";
    case CKK_JUNIPER: return "CKK_JUNIPER";
    case CKK_CDMF: return "CKK_CDMF";
    case CKK_AES: return "CKK_AES";
    case CKK_BLOWFISH: return "CKK_BLOWFISH";
    case CKK_TWOFISH: return "CKK_TWOFISH";
    case CKK_SECURID: return "CKK_SECURID";
    case CKK_HOTP: return "CKK_HOTP";
    case CKK_ACTI: return "CKK_ACTI";
    case CKK_CAMELLIA: return "CKK_CAMELLIA";
    case CKK_ARIA: return "CKK_ARIA";
    case CKK_VENDOR_DEFINED: return "CKK_VENDOR_DEFINED";
    default: return "UNKNOWN";
  }
}

string mechanism_type_name(CK_MECHANISM_TYPE val) {
  switch (val) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN";
    case CKM_RSA_PKCS: return "CKM_RSA_PKCS";
    case CKM_RSA_9796: return "CKM_RSA_9796";
    case CKM_RSA_X_509: return "CKM_RSA_X_509";
    case CKM_MD2_RSA_PKCS: return "CKM_MD2_RSA_PKCS";
    case CKM_MD5_RSA_PKCS: return "CKM_MD5_RSA_PKCS";
    case CKM_SHA1_RSA_PKCS: return "CKM_SHA1_RSA_PKCS";
    case CKM_RIPEMD128_RSA_PKCS: return "CKM_RIPEMD128_RSA_PKCS";
    case CKM_RIPEMD160_RSA_PKCS: return "CKM_RIPEMD160_RSA_PKCS";
    case CKM_RSA_PKCS_OAEP: return "CKM_RSA_PKCS_OAEP";
    case CKM_RSA_X9_31_KEY_PAIR_GEN: return "CKM_RSA_X9_31_KEY_PAIR_GEN";
    case CKM_RSA_X9_31: return "CKM_RSA_X9_31";
    case CKM_SHA1_RSA_X9_31: return "CKM_SHA1_RSA_X9_31";
    case CKM_RSA_PKCS_PSS: return "CKM_RSA_PKCS_PSS";
    case CKM_SHA1_RSA_PKCS_PSS: return "CKM_SHA1_RSA_PKCS_PSS";
    case CKM_DSA_KEY_PAIR_GEN: return "CKM_DSA_KEY_PAIR_GEN";
    case CKM_DSA: return "CKM_DSA";
    case CKM_DSA_SHA1: return "CKM_DSA_SHA1";
    case CKM_DH_PKCS_KEY_PAIR_GEN: return "CKM_DH_PKCS_KEY_PAIR_GEN";
    case CKM_DH_PKCS_DERIVE: return "CKM_DH_PKCS_DERIVE";
    case CKM_X9_42_DH_KEY_PAIR_GEN: return "CKM_X9_42_DH_KEY_PAIR_GEN";
    case CKM_X9_42_DH_DERIVE: return "CKM_X9_42_DH_DERIVE";
    case CKM_X9_42_DH_HYBRID_DERIVE: return "CKM_X9_42_DH_HYBRID_DERIVE";
    case CKM_X9_42_MQV_DERIVE: return "CKM_X9_42_MQV_DERIVE";
    case CKM_SHA256_RSA_PKCS: return "CKM_SHA256_RSA_PKCS";
    case CKM_SHA384_RSA_PKCS: return "CKM_SHA384_RSA_PKCS";
    case CKM_SHA512_RSA_PKCS: return "CKM_SHA512_RSA_PKCS";
    case CKM_SHA256_RSA_PKCS_PSS: return "CKM_SHA256_RSA_PKCS_PSS";
    case CKM_SHA384_RSA_PKCS_PSS: return "CKM_SHA384_RSA_PKCS_PSS";
    case CKM_SHA512_RSA_PKCS_PSS: return "CKM_SHA512_RSA_PKCS_PSS";
    case CKM_SHA224_RSA_PKCS: return "CKM_SHA224_RSA_PKCS";
    case CKM_SHA224_RSA_PKCS_PSS: return "CKM_SHA224_RSA_PKCS_PSS";
    case CKM_RC2_KEY_GEN: return "CKM_RC2_KEY_GEN";
    case CKM_RC2_ECB: return "CKM_RC2_ECB";
    case CKM_RC2_CBC: return "CKM_RC2_CBC";
    case CKM_RC2_MAC: return "CKM_RC2_MAC";
    case CKM_RC2_MAC_GENERAL: return "CKM_RC2_MAC_GENERAL";
    case CKM_RC2_CBC_PAD: return "CKM_RC2_CBC_PAD";
    case CKM_RC4_KEY_GEN: return "CKM_RC4_KEY_GEN";
    case CKM_RC4: return "CKM_RC4";
    case CKM_DES_KEY_GEN: return "CKM_DES_KEY_GEN";
    case CKM_DES_ECB: return "CKM_DES_ECB";
    case CKM_DES_CBC: return "CKM_DES_CBC";
    case CKM_DES_MAC: return "CKM_DES_MAC";
    case CKM_DES_MAC_GENERAL: return "CKM_DES_MAC_GENERAL";
    case CKM_DES_CBC_PAD: return "CKM_DES_CBC_PAD";
    case CKM_DES2_KEY_GEN: return "CKM_DES2_KEY_GEN";
    case CKM_DES3_KEY_GEN: return "CKM_DES3_KEY_GEN";
    case CKM_DES3_ECB: return "CKM_DES3_ECB";
    case CKM_DES3_CBC: return "CKM_DES3_CBC";
    case CKM_DES3_MAC: return "CKM_DES3_MAC";
    case CKM_DES3_MAC_GENERAL: return "CKM_DES3_MAC_GENERAL";
    case CKM_DES3_CBC_PAD: return "CKM_DES3_CBC_PAD";
    case CKM_CDMF_KEY_GEN: return "CKM_CDMF_KEY_GEN";
    case CKM_CDMF_ECB: return "CKM_CDMF_ECB";
    case CKM_CDMF_CBC: return "CKM_CDMF_CBC";
    case CKM_CDMF_MAC: return "CKM_CDMF_MAC";
    case CKM_CDMF_MAC_GENERAL: return "CKM_CDMF_MAC_GENERAL";
    case CKM_CDMF_CBC_PAD: return "CKM_CDMF_CBC_PAD";
    case CKM_DES_OFB64: return "CKM_DES_OFB64";
    case CKM_DES_OFB8: return "CKM_DES_OFB8";
    case CKM_DES_CFB64: return "CKM_DES_CFB64";
    case CKM_DES_CFB8: return "CKM_DES_CFB8";
    case CKM_MD2: return "CKM_MD2";
    case CKM_MD2_HMAC: return "CKM_MD2_HMAC";
    case CKM_MD2_HMAC_GENERAL: return "CKM_MD2_HMAC_GENERAL";
    case CKM_MD5: return "CKM_MD5";
    case CKM_MD5_HMAC: return "CKM_MD5_HMAC";
    case CKM_MD5_HMAC_GENERAL: return "CKM_MD5_HMAC_GENERAL";
    case CKM_SHA_1: return "CKM_SHA_1";
    case CKM_SHA_1_HMAC: return "CKM_SHA_1_HMAC";
    case CKM_SHA_1_HMAC_GENERAL: return "CKM_SHA_1_HMAC_GENERAL";
    case CKM_RIPEMD128: return "CKM_RIPEMD128";
    case CKM_RIPEMD128_HMAC: return "CKM_RIPEMD128_HMAC";
    case CKM_RIPEMD128_HMAC_GENERAL: return "CKM_RIPEMD128_HMAC_GENERAL";
    case CKM_RIPEMD160: return "CKM_RIPEMD160";
    case CKM_RIPEMD160_HMAC: return "CKM_RIPEMD160_HMAC";
    case CKM_RIPEMD160_HMAC_GENERAL: return "CKM_RIPEMD160_HMAC_GENERAL";
    case CKM_SHA256: return "CKM_SHA256";
    case CKM_SHA256_HMAC: return "CKM_SHA256_HMAC";
    case CKM_SHA256_HMAC_GENERAL: return "CKM_SHA256_HMAC_GENERAL";
    case CKM_SHA224: return "CKM_SHA224";
    case CKM_SHA224_HMAC: return "CKM_SHA224_HMAC";
    case CKM_SHA224_HMAC_GENERAL: return "CKM_SHA224_HMAC_GENERAL";
    case CKM_SHA384: return "CKM_SHA384";
    case CKM_SHA384_HMAC: return "CKM_SHA384_HMAC";
    case CKM_SHA384_HMAC_GENERAL: return "CKM_SHA384_HMAC_GENERAL";
    case CKM_SHA512: return "CKM_SHA512";
    case CKM_SHA512_HMAC: return "CKM_SHA512_HMAC";
    case CKM_SHA512_HMAC_GENERAL: return "CKM_SHA512_HMAC_GENERAL";
    case CKM_SECURID_KEY_GEN: return "CKM_SECURID_KEY_GEN";
    case CKM_SECURID: return "CKM_SECURID";
    case CKM_HOTP_KEY_GEN: return "CKM_HOTP_KEY_GEN";
    case CKM_HOTP: return "CKM_HOTP";
    case CKM_ACTI: return "CKM_ACTI";
    case CKM_ACTI_KEY_GEN: return "CKM_ACTI_KEY_GEN";
    case CKM_CAST_KEY_GEN: return "CKM_CAST_KEY_GEN";
    case CKM_CAST_ECB: return "CKM_CAST_ECB";
    case CKM_CAST_CBC: return "CKM_CAST_CBC";
    case CKM_CAST_MAC: return "CKM_CAST_MAC";
    case CKM_CAST_MAC_GENERAL: return "CKM_CAST_MAC_GENERAL";
    case CKM_CAST_CBC_PAD: return "CKM_CAST_CBC_PAD";
    case CKM_CAST3_KEY_GEN: return "CKM_CAST3_KEY_GEN";
    case CKM_CAST3_ECB: return "CKM_CAST3_ECB";
    case CKM_CAST3_CBC: return "CKM_CAST3_CBC";
    case CKM_CAST3_MAC: return "CKM_CAST3_MAC";
    case CKM_CAST3_MAC_GENERAL: return "CKM_CAST3_MAC_GENERAL";
    case CKM_CAST3_CBC_PAD: return "CKM_CAST3_CBC_PAD";
    case CKM_CAST128_KEY_GEN: return "CKM_CAST128_KEY_GEN";
    case CKM_CAST128_ECB: return "CKM_CAST128_ECB";
    case CKM_CAST128_CBC: return "CKM_CAST128_CBC";
    case CKM_CAST128_MAC: return "CKM_CAST128_MAC";
    case CKM_CAST128_MAC_GENERAL: return "CKM_CAST128_MAC_GENERAL";
    case CKM_CAST128_CBC_PAD: return "CKM_CAST128_CBC_PAD";
    case CKM_RC5_KEY_GEN: return "CKM_RC5_KEY_GEN";
    case CKM_RC5_ECB: return "CKM_RC5_ECB";
    case CKM_RC5_CBC: return "CKM_RC5_CBC";
    case CKM_RC5_MAC: return "CKM_RC5_MAC";
    case CKM_RC5_MAC_GENERAL: return "CKM_RC5_MAC_GENERAL";
    case CKM_RC5_CBC_PAD: return "CKM_RC5_CBC_PAD";
    case CKM_IDEA_KEY_GEN: return "CKM_IDEA_KEY_GEN";
    case CKM_IDEA_ECB: return "CKM_IDEA_ECB";
    case CKM_IDEA_CBC: return "CKM_IDEA_CBC";
    case CKM_IDEA_MAC: return "CKM_IDEA_MAC";
    case CKM_IDEA_MAC_GENERAL: return "CKM_IDEA_MAC_GENERAL";
    case CKM_IDEA_CBC_PAD: return "CKM_IDEA_CBC_PAD";
    case CKM_GENERIC_SECRET_KEY_GEN: return "CKM_GENERIC_SECRET_KEY_GEN";
    case CKM_CONCATENATE_BASE_AND_KEY: return "CKM_CONCATENATE_BASE_AND_KEY";
    case CKM_CONCATENATE_BASE_AND_DATA: return "CKM_CONCATENATE_BASE_AND_DATA";
    case CKM_CONCATENATE_DATA_AND_BASE: return "CKM_CONCATENATE_DATA_AND_BASE";
    case CKM_XOR_BASE_AND_DATA: return "CKM_XOR_BASE_AND_DATA";
    case CKM_EXTRACT_KEY_FROM_KEY: return "CKM_EXTRACT_KEY_FROM_KEY";
    case CKM_SSL3_PRE_MASTER_KEY_GEN: return "CKM_SSL3_PRE_MASTER_KEY_GEN";
    case CKM_SSL3_MASTER_KEY_DERIVE: return "CKM_SSL3_MASTER_KEY_DERIVE";
    case CKM_SSL3_KEY_AND_MAC_DERIVE: return "CKM_SSL3_KEY_AND_MAC_DERIVE";
    case CKM_SSL3_MASTER_KEY_DERIVE_DH: return "CKM_SSL3_MASTER_KEY_DERIVE_DH";
    case CKM_TLS_PRE_MASTER_KEY_GEN: return "CKM_TLS_PRE_MASTER_KEY_GEN";
    case CKM_TLS_MASTER_KEY_DERIVE: return "CKM_TLS_MASTER_KEY_DERIVE";
    case CKM_TLS_KEY_AND_MAC_DERIVE: return "CKM_TLS_KEY_AND_MAC_DERIVE";
    case CKM_TLS_MASTER_KEY_DERIVE_DH: return "CKM_TLS_MASTER_KEY_DERIVE_DH";
    case CKM_TLS_PRF: return "CKM_TLS_PRF";
    case CKM_SSL3_MD5_MAC: return "CKM_SSL3_MD5_MAC";
    case CKM_SSL3_SHA1_MAC: return "CKM_SSL3_SHA1_MAC";
    case CKM_MD5_KEY_DERIVATION: return "CKM_MD5_KEY_DERIVATION";
    case CKM_MD2_KEY_DERIVATION: return "CKM_MD2_KEY_DERIVATION";
    case CKM_SHA1_KEY_DERIVATION: return "CKM_SHA1_KEY_DERIVATION";
    case CKM_SHA256_KEY_DERIVATION: return "CKM_SHA256_KEY_DERIVATION";
    case CKM_SHA384_KEY_DERIVATION: return "CKM_SHA384_KEY_DERIVATION";
    case CKM_SHA512_KEY_DERIVATION: return "CKM_SHA512_KEY_DERIVATION";
    case CKM_SHA224_KEY_DERIVATION: return "CKM_SHA224_KEY_DERIVATION";
    case CKM_PBE_MD2_DES_CBC: return "CKM_PBE_MD2_DES_CBC";
    case CKM_PBE_MD5_DES_CBC: return "CKM_PBE_MD5_DES_CBC";
    case CKM_PBE_MD5_CAST_CBC: return "CKM_PBE_MD5_CAST_CBC";
    case CKM_PBE_MD5_CAST3_CBC: return "CKM_PBE_MD5_CAST3_CBC";
    case CKM_PBE_MD5_CAST128_CBC: return "CKM_PBE_MD5_CAST128_CBC";
    case CKM_PBE_SHA1_CAST128_CBC: return "CKM_PBE_SHA1_CAST128_CBC";
    case CKM_PBE_SHA1_RC4_128: return "CKM_PBE_SHA1_RC4_128";
    case CKM_PBE_SHA1_RC4_40: return "CKM_PBE_SHA1_RC4_40";
    case CKM_PBE_SHA1_DES3_EDE_CBC: return "CKM_PBE_SHA1_DES3_EDE_CBC";
    case CKM_PBE_SHA1_DES2_EDE_CBC: return "CKM_PBE_SHA1_DES2_EDE_CBC";
    case CKM_PBE_SHA1_RC2_128_CBC: return "CKM_PBE_SHA1_RC2_128_CBC";
    case CKM_PBE_SHA1_RC2_40_CBC: return "CKM_PBE_SHA1_RC2_40_CBC";
    case CKM_PKCS5_PBKD2: return "CKM_PKCS5_PBKD2";
    case CKM_PBA_SHA1_WITH_SHA1_HMAC: return "CKM_PBA_SHA1_WITH_SHA1_HMAC";
    case CKM_WTLS_PRE_MASTER_KEY_GEN: return "CKM_WTLS_PRE_MASTER_KEY_GEN";
    case CKM_WTLS_MASTER_KEY_DERIVE: return "CKM_WTLS_MASTER_KEY_DERIVE";
    case CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC: return "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC";
    case CKM_WTLS_PRF: return "CKM_WTLS_PRF";
    case CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: return "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE";
    case CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE: return "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE";
    case CKM_KEY_WRAP_LYNKS: return "CKM_KEY_WRAP_LYNKS";
    case CKM_KEY_WRAP_SET_OAEP: return "CKM_KEY_WRAP_SET_OAEP";
    case CKM_CMS_SIG: return "CKM_CMS_SIG";
    case CKM_KIP_DERIVE: return "CKM_KIP_DERIVE";
    case CKM_KIP_WRAP: return "CKM_KIP_WRAP";
    case CKM_KIP_MAC: return "CKM_KIP_MAC";
    case CKM_CAMELLIA_KEY_GEN: return "CKM_CAMELLIA_KEY_GEN";
    case CKM_CAMELLIA_ECB: return "CKM_CAMELLIA_ECB";
    case CKM_CAMELLIA_CBC: return "CKM_CAMELLIA_CBC";
    case CKM_CAMELLIA_MAC: return "CKM_CAMELLIA_MAC";
    case CKM_CAMELLIA_MAC_GENERAL: return "CKM_CAMELLIA_MAC_GENERAL";
    case CKM_CAMELLIA_CBC_PAD: return "CKM_CAMELLIA_CBC_PAD";
    case CKM_CAMELLIA_ECB_ENCRYPT_DATA: return "CKM_CAMELLIA_ECB_ENCRYPT_DATA";
    case CKM_CAMELLIA_CBC_ENCRYPT_DATA: return "CKM_CAMELLIA_CBC_ENCRYPT_DATA";
    case CKM_CAMELLIA_CTR: return "CKM_CAMELLIA_CTR";
    case CKM_ARIA_KEY_GEN: return "CKM_ARIA_KEY_GEN";
    case CKM_ARIA_ECB: return "CKM_ARIA_ECB";
    case CKM_ARIA_CBC: return "CKM_ARIA_CBC";
    case CKM_ARIA_MAC: return "CKM_ARIA_MAC";
    case CKM_ARIA_MAC_GENERAL: return "CKM_ARIA_MAC_GENERAL";
    case CKM_ARIA_CBC_PAD: return "CKM_ARIA_CBC_PAD";
    case CKM_ARIA_ECB_ENCRYPT_DATA: return "CKM_ARIA_ECB_ENCRYPT_DATA";
    case CKM_ARIA_CBC_ENCRYPT_DATA: return "CKM_ARIA_CBC_ENCRYPT_DATA";
    case CKM_SKIPJACK_KEY_GEN: return "CKM_SKIPJACK_KEY_GEN";
    case CKM_SKIPJACK_ECB64: return "CKM_SKIPJACK_ECB64";
    case CKM_SKIPJACK_CBC64: return "CKM_SKIPJACK_CBC64";
    case CKM_SKIPJACK_OFB64: return "CKM_SKIPJACK_OFB64";
    case CKM_SKIPJACK_CFB64: return "CKM_SKIPJACK_CFB64";
    case CKM_SKIPJACK_CFB32: return "CKM_SKIPJACK_CFB32";
    case CKM_SKIPJACK_CFB16: return "CKM_SKIPJACK_CFB16";
    case CKM_SKIPJACK_CFB8: return "CKM_SKIPJACK_CFB8";
    case CKM_SKIPJACK_WRAP: return "CKM_SKIPJACK_WRAP";
    case CKM_SKIPJACK_PRIVATE_WRAP: return "CKM_SKIPJACK_PRIVATE_WRAP";
    case CKM_SKIPJACK_RELAYX: return "CKM_SKIPJACK_RELAYX";
    case CKM_KEA_KEY_PAIR_GEN: return "CKM_KEA_KEY_PAIR_GEN";
    case CKM_KEA_KEY_DERIVE: return "CKM_KEA_KEY_DERIVE";
    case CKM_FORTEZZA_TIMESTAMP: return "CKM_FORTEZZA_TIMESTAMP";
    case CKM_BATON_KEY_GEN: return "CKM_BATON_KEY_GEN";
    case CKM_BATON_ECB128: return "CKM_BATON_ECB128";
    case CKM_BATON_ECB96: return "CKM_BATON_ECB96";
    case CKM_BATON_CBC128: return "CKM_BATON_CBC128";
    case CKM_BATON_COUNTER: return "CKM_BATON_COUNTER";
    case CKM_BATON_SHUFFLE: return "CKM_BATON_SHUFFLE";
    case CKM_BATON_WRAP: return "CKM_BATON_WRAP";
    case CKM_EC_KEY_PAIR_GEN: return "CKM_EC_KEY_PAIR_GEN";
    case CKM_ECDSA: return "CKM_ECDSA";
    case CKM_ECDSA_SHA1: return "CKM_ECDSA_SHA1";
    case CKM_ECDH1_DERIVE: return "CKM_ECDH1_DERIVE";
    case CKM_ECDH1_COFACTOR_DERIVE: return "CKM_ECDH1_COFACTOR_DERIVE";
    case CKM_ECMQV_DERIVE: return "CKM_ECMQV_DERIVE";
    case CKM_JUNIPER_KEY_GEN: return "CKM_JUNIPER_KEY_GEN";
    case CKM_JUNIPER_ECB128: return "CKM_JUNIPER_ECB128";
    case CKM_JUNIPER_CBC128: return "CKM_JUNIPER_CBC128";
    case CKM_JUNIPER_COUNTER: return "CKM_JUNIPER_COUNTER";
    case CKM_JUNIPER_SHUFFLE: return "CKM_JUNIPER_SHUFFLE";
    case CKM_JUNIPER_WRAP: return "CKM_JUNIPER_WRAP";
    case CKM_FASTHASH: return "CKM_FASTHASH";
    case CKM_AES_KEY_GEN: return "CKM_AES_KEY_GEN";
    case CKM_AES_ECB: return "CKM_AES_ECB";
    case CKM_AES_CBC: return "CKM_AES_CBC";
    case CKM_AES_MAC: return "CKM_AES_MAC";
    case CKM_AES_MAC_GENERAL: return "CKM_AES_MAC_GENERAL";
    case CKM_AES_CBC_PAD: return "CKM_AES_CBC_PAD";
    case CKM_AES_CTR: return "CKM_AES_CTR";
    case CKM_BLOWFISH_KEY_GEN: return "CKM_BLOWFISH_KEY_GEN";
    case CKM_BLOWFISH_CBC: return "CKM_BLOWFISH_CBC";
    case CKM_TWOFISH_KEY_GEN: return "CKM_TWOFISH_KEY_GEN";
    case CKM_TWOFISH_CBC: return "CKM_TWOFISH_CBC";
    case CKM_DES_ECB_ENCRYPT_DATA: return "CKM_DES_ECB_ENCRYPT_DATA";
    case CKM_DES_CBC_ENCRYPT_DATA: return "CKM_DES_CBC_ENCRYPT_DATA";
    case CKM_DES3_ECB_ENCRYPT_DATA: return "CKM_DES3_ECB_ENCRYPT_DATA";
    case CKM_DES3_CBC_ENCRYPT_DATA: return "CKM_DES3_CBC_ENCRYPT_DATA";
    case CKM_AES_ECB_ENCRYPT_DATA: return "CKM_AES_ECB_ENCRYPT_DATA";
    case CKM_AES_CBC_ENCRYPT_DATA: return "CKM_AES_CBC_ENCRYPT_DATA";
    case CKM_DSA_PARAMETER_GEN: return "CKM_DSA_PARAMETER_GEN";
    case CKM_DH_PKCS_PARAMETER_GEN: return "CKM_DH_PKCS_PARAMETER_GEN";
    case CKM_X9_42_DH_PARAMETER_GEN: return "CKM_X9_42_DH_PARAMETER_GEN";
    case CKM_VENDOR_DEFINED: return "CKM_VENDOR_DEFINED";
    default: return "UNKNOWN";
  }
}

string certificate_type_name(CK_CERTIFICATE_TYPE val) {
  switch (val) {
    case CKC_X_509: return "CKC_X_509";
    case CKC_X_509_ATTR_CERT: return "CKC_X_509_ATTR_CERT";
    case CKC_WTLS: return "CKC_WTLS";
    case CKC_VENDOR_DEFINED: return "CKC_VENDOR_DEFINED";
    default: return "UNKNOWN";
  }
}

string object_class_name(CK_OBJECT_CLASS val) {
  switch (val) {
    case CKO_DATA: return "CKO_DATA";
    case CKO_CERTIFICATE: return "CKO_CERTIFICATE";
    case CKO_PUBLIC_KEY: return "CKO_PUBLIC_KEY";
    case CKO_PRIVATE_KEY: return "CKO_PRIVATE_KEY";
    case CKO_SECRET_KEY: return "CKO_SECRET_KEY";
    case CKO_HW_FEATURE: return "CKO_HW_FEATURE";
    case CKO_DOMAIN_PARAMETERS: return "CKO_DOMAIN_PARAMETERS";
    case CKO_MECHANISM: return "CKO_MECHANISM";
    case CKO_OTP_KEY: return "CKO_OTP_KEY";
    case CKO_VENDOR_DEFINED: return "CKO_VENDOR_DEFINED";
    default: return "UNKNOWN";
  }
}

namespace ber {
class DataPiece {
 public:
  DataPiece(const string& str) : data((const CK_BYTE*)str.data()), len(str.size()) {}
  DataPiece(const CK_BYTE* d, int l) : data(d), len(l) {}
  const CK_BYTE* data;
  int len;
  CK_BYTE ConsumeByte() {
    assert(len > 0);
    CK_BYTE val = data[0];
    ++data;
    --len;
    return val;
  }
};

class Identifier {
 public:
  enum ASN1Class {
    UNIVERSAL = 0,
    APPLICATION = 1,
    CONTEXT_SPECIFIC = 2,
    PRIVATE = 3
  };
  enum ASN1Tag {
    EOC = 0,
    BOOLEAN = 1,
    INTEGER = 2,
    BIT_STRING = 3,
    OCTET_STRING = 4,
    ASN1_NULL = 5,
    OBJECT_IDENTIFIER = 6,
    OBJECT_DESCRIPTOR = 7,
    EXTERNAL = 8,
    REAL = 9,
    ENUMERATED = 10,
    EMBEDDED_PDV = 11,
    UTF8STRING = 12,
    RELATIVE_OID = 13,
    SEQUENCE_OF = 16,
    SET_OF = 17,
    NUMERIC_STRING = 18,
    PRINTABLE_STRING = 19,
    T61_STRING = 20,
    VIDEOTEX_STRING = 21,
    IA5STRING = 22,
    UTCTIME = 23,
    GENERALIZED_TIME = 24,
    GRAPHIC_STRING = 25,
    VISIBLE_STRING = 26,
    GENERAL_STRING = 27,
    UNIVERSAL_STRING = 28,
    CHARACTER_STRING = 29,
    BMPSTRING = 30,
  };
  ASN1Class asn1class;
  bool constructed;
  int tag;
};

Identifier ParseIdentifier(DataPiece* dp) {
  CK_BYTE id = dp->ConsumeByte();
  Identifier identifier;
  identifier.asn1class = static_cast<Identifier::ASN1Class>(id >> 6);
  identifier.constructed = (bool)(id & 0x20);
  identifier.tag = (id & 0x1F);
  if (identifier.tag == 0x1F) {
    // Long form tag number
    CK_BYTE bb;
    identifier.tag = 0;
    do {
      bb = dp->ConsumeByte();
      identifier.tag <<= 7;
      identifier.tag += (bb & 0x7f);
    } while (bb & 0x80);
  }
  return identifier;
}

int ParseLength(DataPiece* dp) {
  CK_BYTE len = dp->ConsumeByte();
  if (len == 0x80) {
    // Indefinite form -- look for EOC to find end
    return -1;
  } else if (len & 0x80) {
    // Definite long form
    int num_len_bytes = (len & 0x7f);
    int full_len = 0;
    for (int ii = 0; ii < num_len_bytes; ii++) {
      len = dp->ConsumeByte();
      full_len = (full_len << 8) + len;
    }
    return full_len;
  } else {
    // Definite short form
    return len;
  }
}

// OIDs that we know a short name for.
map <string, string> shortnames = {
  { "oid2.5.4.3", "CN="},
  { "oid2.5.4.6", "C="},
  { "oid2.5.4.10", "O="},
  { "oid2.5.4.11", "OU="},
  { "oid1.2.840.113549.1.9.1", "email=" },
  { "oid1.2.840.113549.1.1.5", "sha1-with-rsa-signature="},
  { "oid1.2.840.113549.1.1.1", "rsaEncryption="},
  { "oid2.5.29.15", "keyUsage="},
  { "oid2.5.29.19", "basicConstraints="},
  { "oid2.5.29.31", "cRLDistributionPoints="},
  { "oid2.5.29.37", "extKeyUsage="},
};

string ObjectIdentifier(const DataPiece& dp) {
  // Build an OID string
  if (dp.len == 0)  return "";
  int first = (int)dp.data[0];
  stringstream ss;
  ss << "oid" << (first / 40) << '.' << (first % 40);
  unsigned int value = 0;
  for (int ii = 1; ii < dp.len; ii++) {
    int b = (int)dp.data[ii];
    value = (value << 7) + (b & 0x7f);
    if (!(b & 0x80)) {
      ss << '.' << value;
      value = 0;
    }
  }
  string result = ss.str();
  auto it = shortnames.find(result);
  if (it == shortnames.end()) {
    return result;
  } else {
    return it->second;
  }
}

string ParseContent(const Identifier& ident, const DataPiece& content) {
  switch (ident.tag) {
    case Identifier::OBJECT_IDENTIFIER:
      return ObjectIdentifier(content);
    case Identifier::UTF8STRING:
    case Identifier::NUMERIC_STRING:
    case Identifier::PRINTABLE_STRING:
    case Identifier::T61_STRING:
    case Identifier::VIDEOTEX_STRING:
    case Identifier::IA5STRING:
    case Identifier::GRAPHIC_STRING:
    case Identifier::VISIBLE_STRING:
    case Identifier::GENERAL_STRING:
    case Identifier::UNIVERSAL_STRING:
    case Identifier::CHARACTER_STRING:
    case Identifier::BMPSTRING:
    case Identifier::UTCTIME:
      return "'" + string((const char*)content.data, content.len) + "'";
    // TODO(drysdale): add other types, check all strings work.
    default:
      return pkcs11::hex_data((CK_BYTE_PTR)content.data, content.len);
  }
}

// Consume a TLV from dp, update dp to remove it, and return the result.
string BERDecodeTLV(DataPiece* dp) {
  if (dp->len == 0) return "<error>";
  Identifier ident = ParseIdentifier(dp);
  if (ident.tag == Identifier::EOC) return "EOC";
  int length = ParseLength(dp);
  if (!ident.constructed) {
    assert(length != -1); // no way to spot the end of a primitive
    // Parse and consume the primitive value.
    DataPiece content = *dp;
    content.len = length;
    string result = ParseContent(ident, content);
    dp->len -= length;
    dp->data += length;
    return result;
  }

  // Value is itself made up of TLVs.
  stringstream ss;
  char end_delim;
  if (ident.tag == Identifier::SET_OF) {
    ss << '{';
    end_delim = '}';
  } else if (ident.tag == Identifier::SEQUENCE_OF) {
    ss << '[';
    end_delim = ']';
  } else {
    ss << '(';
    end_delim = ')';
  }
  bool first = true;

  if (length == -1) {
    // Indefinite length: consume TLVs until EOC reached.
    while (true) {
      string result = BERDecodeTLV(dp);
      if (result == "EOC") break;
      if (!first) ss << ", ";
      first = false;
      ss << result;
    }
  } else {
    // Definite length: consume TLVs until length exhausted
    DataPiece content = *dp;
    content.len = length;
    // Consume the value regardless
    dp->len -= length;
    dp->data += length;
    while (content.len > 0) {
      string result = BERDecodeTLV(&content);
      if (!first) ss << ", ";
      first = false;
      ss << result;
    }
  }
  ss << end_delim;
  return ss.str();
}

}  // namespace ber

namespace {

// Many strings in the PKCS#11 interface are fixed-width, blank-padded, no null terminator.
// This is a utility function to convert such a thing to a C++ string.
string ck_char(const CK_CHAR* p, int width) {
  string s(reinterpret_cast<const char*>(p), width);
  s.erase(s.find_last_not_of(" ") + 1);
  return s;
}

string to_ascii(unsigned char* p, int len) {
  stringstream ss;
  ss << '\'';
  for (int ii = 0; ii < len; ii++) ss << (char)p[ii];
  ss << '\'';
  return ss.str();
}

string to_bool(unsigned char* p, int len) {
  assert(len == 1);
  return (p[0] == CK_FALSE ? "CK_FALSE" : "CK_TRUE");
}

string to_ulong(unsigned char* p, int len) {
  assert(len == sizeof(CK_ULONG));
  stringstream ss;
  CK_ULONG val = *(CK_ULONG_PTR)p;
  ss << (unsigned int)val;
  return ss.str();
}

string to_date(unsigned char* p, int len) {
  if (len == 0) return "";
  assert(len == sizeof(CK_DATE));
  stringstream ss;
  ss << to_ascii(p, 4) << '-' << to_ascii(p+4, 2) << '-' << to_ascii(p+6, 2);
  return ss.str();
}

string to_key_type(unsigned char* p, int len) {
  assert(len == sizeof(CK_KEY_TYPE));
  CK_KEY_TYPE val = *(CK_KEY_TYPE*)p;
  return key_type_name(val);
}

string to_mechanism_type(unsigned char* p, int len) {
  assert(len == sizeof(CK_MECHANISM_TYPE));
  CK_MECHANISM_TYPE val = *(CK_MECHANISM_TYPE_PTR)p;
  return mechanism_type_name(val);
}

string to_certificate_type(unsigned char* p, int len) {
  assert(len == sizeof(CK_CERTIFICATE_TYPE));
  CK_CERTIFICATE_TYPE val = *(CK_CERTIFICATE_TYPE*)p;
  return certificate_type_name(val);
}

string to_object_class(unsigned char* p, int len) {
  assert(len == sizeof(CK_OBJECT_CLASS));
  CK_OBJECT_CLASS val = *(CK_OBJECT_CLASS*)p;
  return object_class_name(val);
}

}  // namespace

string BERDecode(CK_BYTE_PTR p, int len) {
  ber::DataPiece data(p, len);
  string result = BERDecodeTLV(&data);
  assert(data.len == 0);  // expect to consume all data
  return result;
}

#define VN(x)  {x, #x, &hex_data}
#define VNA(x) {x, #x, &to_ascii}
#define VNB(x) {x, #x, &to_bool}
#define VNU(x) {x, #x, &to_ulong}
#define VND(x) {x, #x, &to_date}
#define VNK(x) {x, #x, &to_key_type}
#define VNM(x) {x, #x, &to_mechanism_type}
#define VNC(x) {x, #x, &to_certificate_type}
#define VNO(x) {x, #x, &to_object_class}
#define VNN(x) {x, #x, &BERDecode}  // DER-encoding
#define VNV(x) {x, #x, &BERDecode}  // BER-encoding
const struct attr_val_name attribute_info[] = {
  VNO(CKA_CLASS),
  VNA(CKA_LABEL),
  VN(CKA_ID),
  VNN(CKA_SUBJECT),
  VNC(CKA_CERTIFICATE_TYPE),
  VNK(CKA_KEY_TYPE),
  VNN(CKA_OWNER),
  VNB(CKA_TOKEN),
  VNB(CKA_PRIVATE),
  VNA(CKA_APPLICATION),
  VNV(CKA_VALUE),
  VNN(CKA_OBJECT_ID),
  VNN(CKA_ISSUER),
  VNN(CKA_SERIAL_NUMBER),
  VNN(CKA_AC_ISSUER),
  VNV(CKA_ATTR_TYPES),
  VNB(CKA_TRUSTED),
  VNU(CKA_CERTIFICATE_CATEGORY),
  VNU(CKA_JAVA_MIDP_SECURITY_DOMAIN),
  VNA(CKA_URL),
  VN(CKA_HASH_OF_SUBJECT_PUBLIC_KEY),
  VN(CKA_HASH_OF_ISSUER_PUBLIC_KEY),
  VN(CKA_CHECK_VALUE),
  VNB(CKA_SENSITIVE),
  VNB(CKA_ENCRYPT),
  VNB(CKA_DECRYPT),
  VNB(CKA_WRAP),
  VNB(CKA_UNWRAP),
  VNB(CKA_SIGN),
  VNB(CKA_SIGN_RECOVER),
  VNB(CKA_VERIFY),
  VNB(CKA_VERIFY_RECOVER),
  VNB(CKA_DERIVE),
  VND(CKA_START_DATE),
  VND(CKA_END_DATE),
  VN(CKA_MODULUS),
  VN(CKA_MODULUS_BITS),
  VN(CKA_PUBLIC_EXPONENT),
  VN(CKA_PRIVATE_EXPONENT),
  VN(CKA_PRIME_1),
  VN(CKA_PRIME_2),
  VN(CKA_EXPONENT_1),
  VN(CKA_EXPONENT_2),
  VN(CKA_COEFFICIENT),
  VN(CKA_PRIME),
  VN(CKA_SUBPRIME),
  VN(CKA_BASE),
  VN(CKA_PRIME_BITS),
  VN(CKA_SUBPRIME_BITS),
  VN(CKA_VALUE_BITS),
  VNU(CKA_VALUE_LEN),
  VNB(CKA_EXTRACTABLE),
  VNB(CKA_LOCAL),
  VNB(CKA_NEVER_EXTRACTABLE),
  VNB(CKA_ALWAYS_SENSITIVE),
  VN(CKA_KEY_GEN_MECHANISM),
  VNB(CKA_MODIFIABLE),
  VN(CKA_ECDSA_PARAMS),
  VN(CKA_EC_PARAMS),
  VN(CKA_EC_POINT),
  VN(CKA_SECONDARY_AUTH),
  VN(CKA_AUTH_PIN_FLAGS),
  VNB(CKA_ALWAYS_AUTHENTICATE),
  VNB(CKA_WRAP_WITH_TRUSTED),
  // VN(CKA_WRAP_TEMPLATE),  @@@ disable - needs special setup
  // VN(CKA_UNWRAP_TEMPLATE),  @@ disable
  VN(CKA_OTP_FORMAT),
  VN(CKA_OTP_LENGTH),
  VN(CKA_OTP_TIME_INTERVAL),
  VN(CKA_OTP_USER_FRIENDLY_MODE),
  VN(CKA_OTP_CHALLENGE_REQUIREMENT),
  VN(CKA_OTP_TIME_REQUIREMENT),
  VN(CKA_OTP_COUNTER_REQUIREMENT),
  VN(CKA_OTP_PIN_REQUIREMENT),
  VN(CKA_OTP_COUNTER),
  VN(CKA_OTP_TIME),
  VN(CKA_OTP_USER_IDENTIFIER),
  VN(CKA_OTP_SERVICE_IDENTIFIER),
  VN(CKA_OTP_SERVICE_LOGO),
  VN(CKA_OTP_SERVICE_LOGO_TYPE),
  VN(CKA_HW_FEATURE_TYPE),
  VNB(CKA_RESET_ON_INIT),
  VNB(CKA_HAS_RESET),
  VNU(CKA_PIXEL_X),
  VNU(CKA_PIXEL_Y),
  VNU(CKA_RESOLUTION),
  VNU(CKA_CHAR_ROWS),
  VNU(CKA_CHAR_COLUMNS),
  VNB(CKA_COLOR),
  VNU(CKA_BITS_PER_PIXEL),
  VNA(CKA_CHAR_SETS),
  VNA(CKA_ENCODING_METHODS),
  VNA(CKA_MIME_TYPES),
  VNM(CKA_MECHANISM_TYPE),
  VN(CKA_REQUIRED_CMS_ATTRIBUTES),
  VN(CKA_DEFAULT_CMS_ATTRIBUTES),
  VN(CKA_SUPPORTED_CMS_ATTRIBUTES),
  VN(CKA_ALLOWED_MECHANISMS),
  VN(CKA_VENDOR_DEFINED),
};
int attribute_count = sizeof(attribute_info) / sizeof(attribute_info[0]);
#define MAX_ATTR_SIZE 2048


string attribute_description(CK_ATTRIBUTE_PTR attr) {
  if (attr == NULL_PTR) return "<nullptr>";
  AttrValueToString* val_converter = hex_data;
  stringstream ss;
  int ii;
  ss << "CK_ATTRIBUTE {.type=";
  for (ii = 0; ii < attribute_count; ii++) {
    if (attribute_info[ii].val == attr->type) {
      val_converter = attribute_info[ii].val_converter;
      ss << attribute_info[ii].name;
      break;
    }
  }
  if (ii >= attribute_count) {
    ss << "UNKNOWN(" << hex << (unsigned int) attr->type << ")";
  }
  int len = (int)attr->ulValueLen;
  unsigned char* p = static_cast<unsigned char*>(attr->pValue);
  ss << ", .ulValueLen=" << len << " .pValue=" << val_converter(p, len) << "}";
  return ss.str();
}


string info_description(CK_INFO_PTR info) {
  // PKCS#11 s9.1: General information
  if (info == NULL_PTR) return "<nullptr>";
  stringstream ss;
  ss << "CK_INFO {.cryptokiVersion="
     << static_cast<int>(info->cryptokiVersion.major) << "."
     << static_cast<int>(info->cryptokiVersion.minor) << ",";
  ss << ".manufacturerID='" << ck_char(info->manufacturerID, 32) << "', ";
  ss << ".flags=" << hex << (unsigned int)info->flags << ", ";
  ss << ".libraryDescription='" << ck_char(info->libraryDescription, 32) << "', ";
  ss << ".libraryVersion="
     << static_cast<int>(info->libraryVersion.major) << "."
     << static_cast<int>(info->libraryVersion.minor) << "}";
  return ss.str();
}

string function_list_description(CK_FUNCTION_LIST_PTR fns) {
  // PKCS#11 s9.6: Function types
  if (fns == NULL_PTR) return "<nullptr>";
  stringstream ss;
  ss << "{" << endl << "  .version="
     << static_cast<int>(fns->version.major) << "."
     << static_cast<int>(fns->version.minor) << "," << endl;

  // Hackery.
#undef CK_NEED_ARG_LIST
#define CK_PKCS11_FUNCTION_INFO(name) \
  ss << "  ." << #name << fns->name << endl;
#include <pkcs11f.h>
  ss << "}" << endl;
  return ss.str();
}

namespace {
#define FLAG_VAL_NAME(name) (unsigned long)(name), #name
// Expects pairs of val,name arguments until val of zero is reached.
string flag_names(unsigned long val, ...) {
  va_list vl;
  bool first = true;
  stringstream ss;
  va_start(vl, val);
  while (true) {
    int flag = va_arg(vl, unsigned long);
    if (flag == 0) break;
    const char* flag_name = va_arg(vl, const char *);
    if (val & flag) {
      if (!first) ss << "|";
      ss << flag_name;
      first = false;
      val &= ~flag;
    }
  }
  if (val != 0) {
    if (!first) ss << "|";
    ss << hex << val;
  }
  va_end(vl);
  return ss.str();
}

}  // namespace

string slot_description(CK_SLOT_INFO_PTR slot) {
  // PKCS#11 s9.2: Slot and token types
  stringstream ss;
  ss <<"CK_SLOT_INFO {";
  ss << ".slotDescription='" << ck_char(slot->slotDescription, 32) << "', ";
  ss << ".manufacturerID='" << ck_char(slot->manufacturerID, 32) << "', ";
  ss << ".hardwareVersion="
     << static_cast<int>(slot->hardwareVersion.major) << "."
     << static_cast<int>(slot->hardwareVersion.minor) << ", ";
  // Table 10: Slot Information Flags
  ss << ".flags=" << flag_names(slot->flags,
                                FLAG_VAL_NAME(CKF_TOKEN_PRESENT),
                                FLAG_VAL_NAME(CKF_REMOVABLE_DEVICE),
                                FLAG_VAL_NAME(CKF_HW_SLOT), 0) << ", ";
  ss << ".firmwareVersion="
     << static_cast<int>(slot->firmwareVersion.major) << "."
     << static_cast<int>(slot->firmwareVersion.minor);
  ss << "}";
  return ss.str();
}

string token_description(CK_TOKEN_INFO_PTR token) {
  // PKCS#11 s9.2: Slot and token types
  if (token == NULL_PTR) return "<nullptr>";
  stringstream ss;
  ss << "CK_TOKEN_INFO {.label='" << ck_char(token->label, 32) << "', ";
  ss << ".manufacturerID='" << ck_char(token->manufacturerID, 32) << "', ";
  ss << ".model='" << ck_char(token->model, 16) << "', ";
  ss << ".serialNumber=" << ck_char(token->serialNumber, 16) << "', ";
  // Table 11: Token information flags
  ss << ".flags=" << flag_names(token->flags,
                                FLAG_VAL_NAME(CKF_RNG),
                                FLAG_VAL_NAME(CKF_WRITE_PROTECTED),
                                FLAG_VAL_NAME(CKF_LOGIN_REQUIRED),
                                FLAG_VAL_NAME(CKF_USER_PIN_INITIALIZED),
                                FLAG_VAL_NAME(CKF_RESTORE_KEY_NOT_NEEDED),
                                FLAG_VAL_NAME(CKF_CLOCK_ON_TOKEN),
                                FLAG_VAL_NAME(CKF_PROTECTED_AUTHENTICATION_PATH),
                                FLAG_VAL_NAME(CKF_DUAL_CRYPTO_OPERATIONS),
                                FLAG_VAL_NAME(CKF_TOKEN_INITIALIZED),
                                FLAG_VAL_NAME(CKF_SECONDARY_AUTHENTICATION),
                                FLAG_VAL_NAME(CKF_USER_PIN_COUNT_LOW),
                                FLAG_VAL_NAME(CKF_USER_PIN_FINAL_TRY),
                                FLAG_VAL_NAME(CKF_USER_PIN_LOCKED),
                                FLAG_VAL_NAME(CKF_USER_PIN_TO_BE_CHANGED),
                                FLAG_VAL_NAME(CKF_SO_PIN_COUNT_LOW),
                                FLAG_VAL_NAME(CKF_SO_PIN_FINAL_TRY),
                                FLAG_VAL_NAME(CKF_SO_PIN_LOCKED),
                                FLAG_VAL_NAME(CKF_SO_PIN_TO_BE_CHANGED), 0) << ", ";
  ss << ".ulMaxSessionCount=" << (unsigned int)token->ulMaxSessionCount << ", ";
  ss << ".ulSessionCount=" << (unsigned int)token->ulSessionCount << ", ";
  ss << ".ulMaxRwSessionCount=" << (unsigned int)token->ulMaxRwSessionCount << ", ";
  ss << ".ulRwSessionCount=" << (unsigned int)token->ulRwSessionCount << ", ";
  ss << ".ulMaxPinLen=" << (unsigned int)token->ulMaxPinLen << ", ";
  ss << ".ulMinPinLen=" << (unsigned int)token->ulMinPinLen << ", ";
  ss << ".ulTotalPublicMemory=" << (unsigned int)token->ulTotalPublicMemory << ", ";
  ss << ".ulFreePublicMemory=" << (unsigned int)token->ulFreePublicMemory << ", ";
  ss << ".ulTotalPrivateMemory=" << (unsigned int)token->ulTotalPrivateMemory << ", ";
  ss << ".ulFreePrivateMemory=" << (unsigned int)token->ulFreePrivateMemory << ", ";
  ss << ".hardwareVersion="
     << static_cast<int>(token->hardwareVersion.major) << "."
     << static_cast<int>(token->hardwareVersion.minor) << ", ";
  ss << ".firmwareVersion="
     << static_cast<int>(token->firmwareVersion.major) << "."
     << static_cast<int>(token->firmwareVersion.minor) << ", ";
  ss << ".utcTime='" << token->utcTime << "'}";
  return ss.str();
}

string session_info_description(CK_SESSION_INFO_PTR session) {
  // PKCS#11 s9.3: Session types
  if (session == NULL_PTR) return "<nullptr>";
  stringstream ss;
  ss << "CK_SESSION_INFO {.slotID=" << (unsigned int)session->slotID << ", ";
  ss << ".state=";
  if (session->state==CKS_RO_PUBLIC_SESSION) ss << "CKS_RO_PUBLIC_SESSION";
  else if (session->state==CKS_RO_USER_FUNCTIONS) ss << "CKS_RO_USER_FUNCTIONS";
  else if (session->state==CKS_RW_PUBLIC_SESSION) ss << "CKS_RW_PUBLIC_SESSION";
  else if (session->state==CKS_RW_USER_FUNCTIONS) ss << "CKS_RW_USER_FUNCTIONS";
  else if (session->state==CKS_RW_SO_FUNCTIONS) ss << "CKS_RW_SO_FUNCTIONS";
  else ss << "UNKNOWN(" << (int)session->state << ")";
  ss << ", ";
  ss << ".flags=" << flag_names(session->flags, FLAG_VAL_NAME(CKF_RW_SESSION), FLAG_VAL_NAME(CKF_SERIAL_SESSION), 0);
  ss << ".ulDeviceError=" << (unsigned int)session->ulDeviceError << "}";
  return ss.str();
}

string mechanism_info_description(CK_MECHANISM_INFO_PTR mechanism) {
  // PKCS#11 s9.5: Data types for mechanisms
  if (mechanism == NULL_PTR) return "<nullptr>";
  stringstream ss;
  ss << "CK_MECHANISM_INFO {.ulMinKeySize=" << (unsigned int)mechanism->ulMinKeySize << ", ";
  ss << ".ulMaxKeySize=" << (unsigned int)mechanism->ulMaxKeySize << ", ";
  ss << ".flags=" << flag_names(mechanism->flags,
                                FLAG_VAL_NAME(CKF_HW),
                                FLAG_VAL_NAME(CKF_ENCRYPT),
                                FLAG_VAL_NAME(CKF_DECRYPT),
                                FLAG_VAL_NAME(CKF_DIGEST),
                                FLAG_VAL_NAME(CKF_SIGN),
                                FLAG_VAL_NAME(CKF_SIGN_RECOVER),
                                FLAG_VAL_NAME(CKF_VERIFY),
                                FLAG_VAL_NAME(CKF_VERIFY_RECOVER),
                                FLAG_VAL_NAME(CKF_GENERATE),
                                FLAG_VAL_NAME(CKF_GENERATE_KEY_PAIR),
                                FLAG_VAL_NAME(CKF_WRAP),
                                FLAG_VAL_NAME(CKF_UNWRAP),
                                FLAG_VAL_NAME(CKF_DERIVE),
                                FLAG_VAL_NAME(CKF_EC_F_P),
                                FLAG_VAL_NAME(CKF_EC_F_2M),
                                FLAG_VAL_NAME(CKF_EC_ECPARAMETERS),
                                FLAG_VAL_NAME(CKF_EC_NAMEDCURVE),
                                FLAG_VAL_NAME(CKF_EC_UNCOMPRESS),
                                FLAG_VAL_NAME(CKF_EC_COMPRESS),
                                FLAG_VAL_NAME(CKF_EXTENSION), 0);
  ss << "}";
  return ss.str();
}

string object_description(CK_FUNCTION_LIST_PTR fns,
                          CK_SESSION_HANDLE session,
                          CK_OBJECT_HANDLE object) {
  stringstream ss;
  for (int ii = 0; ii < attribute_count; ii++) {
    CK_BYTE buffer[2048];
    CK_ATTRIBUTE attr;
    attr.type = attribute_info[ii].val;
    attr.pValue = &(buffer[0]);
    attr.ulValueLen = sizeof(buffer);
    CK_RV rv = fns->C_GetAttributeValue(session, object, &attr, 1);
    if (rv == CKR_OK) {
      ss << "    " << attribute_description(&attr) << endl;
    }
  }
  return ss.str();
}

}  // namespace pkcs11
