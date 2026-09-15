//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// FIPS FFI glue for the X.509 entry points: the base x509_ni_ffi.c re-included
// under JoFIPS_-prefixed exports (see md_fips_ffi.c for the rationale).
//
// The two interface libraries must not export identical names: a FIPS FFI
// class handed the wrong SymbolLookup would otherwise resolve into the BASE
// library and parse certificates in the wrong lib ctx with no symptom. With
// the names disjoint, and the Java side taking the lookup and the prefix as
// separate parameters, either mistake alone fails at construction.
//
// This file must only ever contain renames.
//

/* *INDENT-OFF* */
#define JoX509_allocate         JoFIPS_JoX509_allocate
#define JoX509_allocateCrl      JoFIPS_JoX509_allocateCrl
#define JoX509_crlEntries       JoFIPS_JoX509_crlEntries
#define JoX509_crlEntriesLen    JoFIPS_JoX509_crlEntriesLen
#define JoX509_crlExtensions    JoFIPS_JoX509_crlExtensions
#define JoX509_crlExtensionsLen JoFIPS_JoX509_crlExtensionsLen
#define JoX509_crlFields        JoFIPS_JoX509_crlFields
#define JoX509_crlFieldsLen     JoFIPS_JoX509_crlFieldsLen
#define JoX509_dispose          JoFIPS_JoX509_dispose
#define JoX509_disposeCrl       JoFIPS_JoX509_disposeCrl
#define JoX509_extensions       JoFIPS_JoX509_extensions
#define JoX509_extensionsLen    JoFIPS_JoX509_extensionsLen
#define JoX509_fields           JoFIPS_JoX509_fields
#define JoX509_fieldsLen        JoFIPS_JoX509_fieldsLen
/* *INDENT-ON* */

#include "x509_ni_ffi.c"
