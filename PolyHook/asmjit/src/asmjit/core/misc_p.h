// [AsmJit]
// Machine Code Generation for C++.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#ifndef _ASMJIT_CORE_MISC_P_H
#define _ASMJIT_CORE_MISC_P_H

#include "../core/build.h"

ASMJIT_BEGIN_NAMESPACE

//! \cond INTERNAL
//! \addtogroup asmjit_support
//! \{

#define ASMJIT_LOOKUP_TABLE_8(T, I) T((I)), T((I+1)), T((I+2)), T((I+3)), T((I+4)), T((I+5)), T((I+6)), T((I+7))
#define ASMJIT_LOOKUP_TABLE_16(T, I) ASMJIT_LOOKUP_TABLE_8(T, I), ASMJIT_LOOKUP_TABLE_8(T, I + 8)
#define ASMJIT_LOOKUP_TABLE_32(T, I) ASMJIT_LOOKUP_TABLE_16(T, I), ASMJIT_LOOKUP_TABLE_16(T, I + 16)
#define ASMJIT_LOOKUP_TABLE_64(T, I) ASMJIT_LOOKUP_TABLE_32(T, I), ASMJIT_LOOKUP_TABLE_32(T, I + 32)
#define ASMJIT_LOOKUP_TABLE_128(T, I) ASMJIT_LOOKUP_TABLE_64(T, I), ASMJIT_LOOKUP_TABLE_64(T, I + 64)
#define ASMJIT_LOOKUP_TABLE_256(T, I) ASMJIT_LOOKUP_TABLE_128(T, I), ASMJIT_LOOKUP_TABLE_128(T, I + 128)
#define ASMJIT_LOOKUP_TABLE_512(T, I) ASMJIT_LOOKUP_TABLE_256(T, I), ASMJIT_LOOKUP_TABLE_256(T, I + 256)
#define ASMJIT_LOOKUP_TABLE_1024(T, I) ASMJIT_LOOKUP_TABLE_512(T, I), ASMJIT_LOOKUP_TABLE_512(T, I + 512)

//! \}
//! \endcond

ASMJIT_END_NAMESPACE

#endif // _ASMJIT_CORE_MISC_P_H
