/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdafx.h"
#include "Tpm2.h"
#include "TpmFileDevice.h"

#include <fcntl.h>

namespace TpmCpp {

TpmFileDevice::~TpmFileDevice()
{
    Close();
}

void TpmFileDevice::Close()
{
    if (TpmInfo)
        close(fd);

    TpmInfo = 0;
}

bool TpmFileDevice::Connect()
{
    if (TpmInfo)
        return true;

    int fd = open(filename, O_RDWR);
    if (fd < 0) {
        printf("Unable to open %s: error %d (%s)\n", filename, errno, strerror(errno));
        TpmInfo |= TpmUsesTrm;
    }

    this->fd = fd;
    TpmInfo |= TpmTbsConn | TpmNoPowerCtl | TpmNoLocalityCtl;
    return true;
}

void TpmFileDevice::DispatchCommand(const ByteVec& cmdBuf)
{
    ssize_t bytesWritten = write(fd, cmdBuf.data(), cmdBuf.size());
    if ((size_t)bytesWritten != cmdBuf.size()) {
        fprintf(stderr, "Failed to write TPM command (written %zd out of %zu): %d (%s); fd = %d\n",
                bytesWritten, cmdBuf.size(), errno, strerror(errno), fd);
        throw std::runtime_error("Failed to write TPM comamnd");
    }
}

ByteVec TpmFileDevice::GetResponse()
{
    // Read the TPM response
    byte respBuf[4096];
    ssize_t bytesRead;

    bytesRead = read(fd, respBuf, sizeof(respBuf));
    if (bytesRead < 10)
    {
        // 10 is the mandatory response header size
        printf("Failed to read the response: bytes read %zd, error %d (%s)\n",
               bytesRead, errno, strerror(errno));
        throw std::runtime_error("Failed to read TPM command");
    }

    return ByteVec((byte*)respBuf, (byte*)respBuf + bytesRead);
}

bool TpmFileDevice::ResponseIsReady() const
{
    return true;
}

}
