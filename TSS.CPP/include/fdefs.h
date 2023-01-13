/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

// fdefs.h - Macro definitions, various forward definitions, and STL-declarations
//           to keep the linker happy.

#pragma once

#ifdef _MSC_VER
#   ifdef _TPMCPPLIB
#       define TPM_DLLEXP __declspec(dllexport)
#   else
#       define TPM_DLLEXP __declspec(dllimport)
#   endif
#else
#   undef TPM_DLLEXP
#   define TPM_DLLEXP
#endif // _MSC_VER

#ifdef WIN32
#   define WIN32_LEAN_AND_MEAN
#   define NOMINMAX

// REVISIT: Lots of these warnings.
// In STL: 'std::_Compressed_pair<>' needs to have dll-interface to be used by clients of class 'std::_Vector_alloc<>'
#pragma  warning(disable:4251)

#   include <crtdbg.h>
#   include <windows.h>
#   include <winsock2.h>
#   include <ws2tcpip.h>
#   include <tchar.h>

#   define TPM_ASSERT _ASSERT
#endif // WIN32

#ifdef __linux__
#   include <arpa/inet.h>
#   include <assert.h>
#   include <string.h>
#endif


#include <vector>
#include <map>

#ifdef __linux__
#include <memory>   // shared_ptr<>

#define TPM_ASSERT assert
#endif


namespace TpmCpp {

using byte = std::uint8_t;
using std::vector;
using std::map;
using std::string;
using std::shared_ptr;

using ByteVec = vector<std::uint8_t>;

class TPMS_PCR_SELECTION;
class TPM_HANDLE;
class TPMS_TAGGED_PROPERTY;
class TPMT_HA;
class TPM2B_DIGEST;
class AUTH_SESSION;
class TPMS_ALG_PROPERTY;
class TPMS_PCR_SELECT;
class TPMS_TAGGED_PCR_SELECT;
class PABase;
class TPMT_SENSITIVE;

}

//#include "TpmTypes.h"
