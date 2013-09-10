#ifndef PKCS11_ENV_H
#define PKCS11_ENV_H

/* The following definitions need to be provided to the preprocessor before the PKCS#11 header file can be included */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#endif  // PKCS11_ENV_H
