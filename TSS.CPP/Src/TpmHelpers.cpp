/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdafx.h"

namespace TpmCpp {

using namespace std;

string EnumToStr(uint32_t enumVal, const EnumID *enumID)
{
    const auto& enumMap = enumID->enum2str;
    auto it = enumMap.find(enumVal);
    if (it != enumMap.end())
        return it->second;

    uint32_t curBit = 1,
             count = 0,
             foundBits = 0;
    string res = "";
    while (foundBits != enumVal)
    {
        if (curBit & enumVal)
        {
            foundBits |= curBit;
            if (!res.empty())
              res += " | ";
            auto &&currentNameIt = enumMap.find(curBit);
            if (currentNameIt == enumMap.end()) {
              res += "bit(" + std::to_string(count) + ")";
            } else {
              res += currentNameIt->second;
            }
        }
        curBit <<= 1;
        ++count;
    }
    return res;
}

uint32_t StrToEnum(const string& enumName, const EnumID *enumID)
{
    const auto& enumMap = enumID->str2enum;
    auto it = enumMap.find(enumName);
    if (it != enumMap.end())
        return it->second;

    uint32_t val = 0;
    size_t  beg = 0,
            next = 0;
    bool done = false;
    do {
        while (enumName[beg] == ' ')
            ++beg;
        size_t  end = enumName.find('|', beg);
        if (end == string::npos)
        {
            done = true;
            end = enumName.length();
        }
        else
        {
            next = end + 1;
            while (enumName[end - 1] == ' ')
                --end;
        }

        string frag = enumName.substr(beg, end - beg);
        it = enumMap.find(frag);
        if (it == enumMap.end())
            throw runtime_error("Invalid ORed component '" + frag + "' of expr '" + enumName + "'");
        val |= it->second;
        beg = next;
    } while (!done);
    return val;
}

inline char hexDigit(uint8_t d)
{
    return d < 10 ? '0' + d : 'A' + (d - 10);
}

/// <summary>  Output a formatted byte-stream </summary>
string to_hex(uint64_t val, size_t width)
{
    if (!val)
        return "00";

    string res;
    uint64_t mask = 0x0F;
    // This loop would work for Java, too (Java is terrible with signed bit propagation)
    for (int offs = 0; val != 0; val &= ~mask, mask <<= 4, offs += 4)
    {
        res = hexDigit((uint8_t)(((val & mask) >> offs) & 0x0F)) + res;
    }
    if (res.length() & 1)
        res = "0" + res;
    if (res.length() < width)
        res = string((width - res.length()) * 2, '0') + res;
    return res;
}

inline uint8_t hexDigitVal(char hexDigit)
{
    return hexDigit <= '9' ? hexDigit - '0' : 10 + hexDigit - 'A';
}

uint64_t from_hex(const string& hex)
{
    uint64_t res = 0;
    for (size_t i = 0; i < hex.length(); ++i)
        res = (res << 4) + hexDigitVal(hex[i]);
    return res;
}

ostream& operator<<(ostream& s, const ByteVec& b)
{
    for (std::uint32_t j = 0; j < b.size(); j++) {
        s << setw(2) << setfill('0') << hex << (std::uint32_t)b[j];
        if ((j + 1) % 4 == 0)
            s << " ";
    }
    return s;
}


TPM_ALG_ID GetSigningHashAlg(const TPMT_PUBLIC& pub)
{
    switch (pub.type()) {
        case TPM_ALG_ID::RSA:
        {
            const TPMS_RSA_PARMS &rsaParms = static_cast<const TPMS_RSA_PARMS&>(*pub.parameters);

            TPMS_SCHEME_RSASSA *scheme = dynamic_cast<TPMS_SCHEME_RSASSA*>(&*rsaParms.scheme);
            if (!scheme)
                throw domain_error("only RSASSA is supported");
            return scheme->hashAlg;
        }
        case TPM_ALG_ID::ECC:
        {
            const TPMS_ECC_PARMS &eccParms = static_cast<const TPMS_ECC_PARMS&>(*pub.parameters);

            TPMS_SCHEME_HASH *scheme = dynamic_cast<TPMS_SCHEME_HASH*>(&*eccParms.scheme);
            if (!scheme)
                throw domain_error("ECDAA is not supported");
            return scheme->hashAlg;
        }
        default:
            throw domain_error("Only RSA or ECC signature verification is supported");
    }
}

namespace Helpers
{
    ByteVec RandomBytes(size_t numBytes)
    {
        return Crypto::GetRand(numBytes);
    }

    ByteVec Concatenate(const ByteVec& buf1, const ByteVec& buf2)
    {
        ByteVec x(buf1.size() + buf2.size());
        copy(buf1.begin(), buf1.end(), x.begin());
        copy(buf2.begin(), buf2.end(), x.begin() + buf1.size());
        return x;
    }

    ByteVec Concatenate(const vector<ByteVec>& bufs)
    {
        size_t size = 0;
        for (const auto& buf : bufs)
            size += buf.size();

        ByteVec res(size);
        size_t pos = 0;
        for (const auto& buf : bufs)
        {
            copy(buf.begin(), buf.end(), res.begin() + pos);
            pos += buf.size();
        }
        return res;
    }

    ByteVec TrimTrailingZeros(const ByteVec& buf)
    {
        if (buf.empty() || buf.back() != 0)
            return buf;

        size_t size = buf.size();
        while (size > 0 && buf[size-1] == 0)
            --size;
        return ByteVec(buf.begin(), buf.begin() + size);
    }

    ByteVec HashPcrs(TPM_ALG_ID hashAlg, const vector<TPM2B_DIGEST>& PcrValues)
    {
        // Note: we assume that these have been presented in the same order as the selection array
        ByteVec pcrDigests;
        for (auto& pcrDigest : PcrValues)
            pcrDigests.insert(pcrDigests.end(), pcrDigest.buffer.begin(), pcrDigest.buffer.end());
        return Crypto::Hash(hashAlg, pcrDigests);
    }

    ByteVec ShiftRight(const ByteVec& x, size_t numBits)
    {
        size_t  newSize = x.size() - numBits / 8;

        if (numBits % 8 == 0)
            return ByteVec(x.begin(), x.begin() + newSize);

        if (numBits > 7)
            throw domain_error("Can only shift up to 7 bits");

        size_t  numCarryBits = 8 - numBits;
        ByteVec y(newSize);

        for (size_t j = newSize - 1; j >= 0; --j)
        {
            y[j] = (byte)(x[j] >> numBits);
            if (j != 0)
                y[j] |= (byte)(x[j - 1] << numCarryBits);
        }
        return y;
    }

} // namespace Helpers


}
