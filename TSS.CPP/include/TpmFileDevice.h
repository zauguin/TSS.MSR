/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#pragma once

#if __linux__

#include "TpmDevice.h"

namespace TpmCpp {

class TPM_DLLEXP TpmFileDevice : public TpmDevice
{
public:
    TpmFileDevice(const char *filename = "/dev/tpmrm0"): filename(filename) {}
    ~TpmFileDevice();

    bool Connect() override;
    void Close() override;

    void DispatchCommand(const ByteVec& outBytes) override;
    ByteVec GetResponse() override;
    bool ResponseIsReady() const override;

private:
    const char *filename;
    int fd;
};

}

#endif // __linux__
