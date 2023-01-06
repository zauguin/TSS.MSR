/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

// fdefs.h - Macro definitions, various forward definitions, and STL-declarations
//           to keep the linker happy.

#pragma once

#ifdef _MSC_VER
#   ifdef _TPMCPPLIB
#       define _DLLEXP_ __declspec(dllexport)
#   else
#       define _DLLEXP_ __declspec(dllimport)
#   endif
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
#endif // WIN32

#ifdef __linux__
#   include <arpa/inet.h>
#   include <assert.h>
#   include <string.h>

#   undef _DLLEXP_
#   define _DLLEXP_
#endif


#include <vector>
#include <map>

#ifdef __linux__
#include <memory>   // shared_ptr<>

using BYTE = unsigned char;
using INT8 = char;
using UINT8 = unsigned char;
using UINT16 = unsigned short;
using UINT32 = unsigned int;
using INT64 = long long;
using UINT64 = unsigned long long;
using INT16 = short;
using INT32 = int;
using SOCKET = int;
using BOOL = bool;
using WCHAR = wchar_t;

#define FALSE false
#define TRUE  true

#define _ASSERT assert
#endif


namespace TpmCpp {

using std::vector;
using std::map;
using std::string;
using std::shared_ptr;

using ByteVec = vector<BYTE>;

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

#ifdef _TPMCPPLIB

using namespace TpmCpp;

#endif // _TPMCPPLIB

//#include "TpmTypes.h"
