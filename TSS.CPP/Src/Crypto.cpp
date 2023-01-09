/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdafx.h"
#include "Crypto.h"
#include "cryptopp/aes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"

#if !defined(NO_SM3)
#   define ALG_SM3_256  1
#   include <cryptopp/sm3.h>
#endif

typedef struct {
    std::uint16_t  size;
    CryptoPP::byte buffer[4096];
} TPM2B;

typedef struct {
    std::uint32_t exponent;      // The public exponent pointer
    TPM2B *publicKey;     // Pointer to the public modulus
} RSA_KEY;

enum class CryptResult {
  FAIL      =  1,
  SUCCESS   =  0,
  NO_RESULT = -1,
  SCHEME    = -2,
  PARAMETER = -3,
  UNDERFLOW = -4,
  POINT     = -5,
  CANCEL    = -6,
};


namespace TpmCpp {

using namespace std;

template<template<typename> typename Trait, typename ... Args>
std::unique_ptr<typename Trait<void>::type> buildForHash(TPM_ALG_ID hashAlg, Args &&...args) {
    using ReturnType = std::unique_ptr<typename Trait<void>::type>;
    switch (hashAlg) {
        case TPM_ALG_ID::SHA1:   return ReturnType(new typename Trait<CryptoPP::SHA1>::type(std::forward<Args>(args)...));
        case TPM_ALG_ID::SHA256: return ReturnType(new typename Trait<CryptoPP::SHA256>::type(std::forward<Args>(args)...));
        case TPM_ALG_ID::SHA384: return ReturnType(new typename Trait<CryptoPP::SHA384>::type(std::forward<Args>(args)...));
        case TPM_ALG_ID::SHA512: return ReturnType(new typename Trait<CryptoPP::SHA512>::type(std::forward<Args>(args)...));
#if ALG_SM3_256
        case TPM_ALG_ID::SM3_256: return ReturnType(new typename Trait<CryptoPP::SM3>::type(std::forward<Args>(args)...));
#endif
    }
    throw domain_error("buildForHash: Unknown or not a hash algorithm");
}

namespace {
CryptoPP::OID getCurve(TPM_ECC_CURVE curve) {
    switch(curve) {
        case TPM_ECC_CURVE::NIST_P192: return CryptoPP::ASN1::secp192r1();
        case TPM_ECC_CURVE::NIST_P224: return CryptoPP::ASN1::secp224r1();
        case TPM_ECC_CURVE::NIST_P256: return CryptoPP::ASN1::secp256r1();
        case TPM_ECC_CURVE::NIST_P384: return CryptoPP::ASN1::secp384r1();
        case TPM_ECC_CURVE::NIST_P521: return CryptoPP::ASN1::secp521r1();
        case TPM_ECC_CURVE::SM2_P256: return CryptoPP::ASN1::sm2p256v1();
        /* case TPM_ECC_CURVE::BN_P256: */
        /* case TPM_ECC_CURVE::BN_P638: */
        default:
            throw std::domain_error("Unsupported curve");
  }
}
}

bool Crypto::IsImplemented(TPM_ALG_ID hashAlg)
{
    switch (hashAlg) {
        case TPM_ALG_ID::SHA1:
        case TPM_ALG_ID::SHA256:
        case TPM_ALG_ID::SHA384:
        case TPM_ALG_ID::SHA512:
#if ALG_SM3_256
        case TPM_ALG_ID::SM3_256:
#endif
            return true;
    }
    return false;
}


std::uint16_t Crypto::HashLength(TPM_ALG_ID hashAlg)
{
    switch (hashAlg) {
        case TPM_ALG_NULL:  return 0;
        case TPM_ALG_ID::SHA1:   return 20;
        case TPM_ALG_ID::SHA256: return 32;
        case TPM_ALG_ID::SHA384: return 48;
        case TPM_ALG_ID::SHA512: return 64;
        case TPM_ALG_ID::SM3_256: return 32;
    }
    return 0;
}

namespace {
template<typename Hash>
class NoopHash : public CryptoPP::HashTransformation {
  public:
    static constexpr auto DIGESTSIZE = Hash::DIGESTSIZE;
    void Update(const CryptoPP::byte *input, std::size_t length) override {
        written = std::copy(input, input + length, written);
    }
    unsigned DigestSize() const override { return DIGESTSIZE; }
    void TruncatedFinal(CryptoPP::byte *digest, std::size_t length) override {
        TPM_ASSERT(written == hash.end());
        std::memcpy(digest, hash.data(), length);
    }
    static const char *StaticAlgorithmName() {
        return Hash::StaticAlgorithmName();
    }
  private:
    CryptoPP::SecByteBlock hash{DIGESTSIZE};
    CryptoPP::SecByteBlock::iterator written = hash.begin();
};
}
}

namespace CryptoPP {
template<typename Hash>
struct PKCS_DigestDecoration<TpmCpp::NoopHash<Hash>> : PKCS_DigestDecoration<Hash> {};
}

namespace TpmCpp {
namespace {
template<typename Hash>
struct GetHash {
    using type = Hash;
};
template<>
struct GetHash<void> {
    using type = CryptoPP::HashTransformation;
};
template<typename Hash>
struct GetHMAC {
    using type = CryptoPP::HMAC<Hash>;
};
template<>
struct GetHMAC<void> {
    using type = CryptoPP::HMAC_Base;
};
template<typename Hash>
struct GetSigner {
    using type = typename CryptoPP::RSASS<CryptoPP::PKCS1v15, NoopHash<Hash>>::Signer;
};
template<>
struct GetSigner<void> {
    using type = CryptoPP::PK_Signer;
};
template<typename Hash>
struct GetVerifier {
    using type = typename CryptoPP::RSASS<CryptoPP::PKCS1v15, NoopHash<Hash>>::Verifier;
};
template<>
struct GetVerifier<void> {
    using type = CryptoPP::PK_Verifier;
};
template<typename Hash>
struct GetEncryptor {
    using type = typename CryptoPP::RSAES<CryptoPP::OAEP<Hash>>::Encryptor;
};
template<>
struct GetEncryptor<void> {
    using type = CryptoPP::PK_Encryptor;
};

CryptoPP::RandomNumberGenerator &getRNG() {
    thread_local static CryptoPP::DefaultAutoSeededRNG rng;
    return rng;
}
}

ByteVec Crypto::Hash(TPM_ALG_ID hashAlg, const ByteVec& toHash, size_t startPos, size_t len)
{
    if (toHash.size() < startPos + len)
    {
        throw out_of_range("Crypto::Hash([" + to_string(toHash.size()) + "], " + 
                                            to_string(startPos) + ", " + to_string(len) + ")");
    }

    auto hash = buildForHash<GetHash>(hashAlg);
    ByteVec digest(hash->DigestSize());
    if (!len)
    {
        len = toHash.size() - startPos;
        if (!len)
            return digest;
    }

    hash->Update(toHash.data() + startPos, len);
    hash->Final(digest.data());
    return digest;
}

ByteVec Crypto::HMAC(TPM_ALG_ID hashAlg, const ByteVec& key, const ByteVec& toHash)
{
    auto hmac = buildForHash<GetHMAC>(hashAlg, key.data(), key.size());

    hmac->Update(toHash.data(), toHash.size());
    ByteVec result(hmac->DigestSize());
    hmac->Final(result.data());

    return result;
}

/// <summary> Default source of random numbers is OpenSSL </summary>
ByteVec Crypto::GetRand(size_t numBytes)
{
    ByteVec resp(numBytes);
    getRNG().GenerateBlock(resp.data(), resp.size());
    return resp;
}

/// <summary> TPM KDF function. Note, a zero is added to the end of label by this routine </summary>
ByteVec Crypto::KDFa(TPM_ALG_ID hmacHash, const ByteVec& hmacKey, const string& label, 
                     const ByteVec& contextU, const ByteVec& contextV, uint32_t numBitsRequired)
{
    uint32_t bitsPerLoop = Crypto::HashLength(hmacHash) * 8;
    uint32_t numLoops = (numBitsRequired + bitsPerLoop - 1) / bitsPerLoop;
    ByteVec kdfStream(numLoops * bitsPerLoop / 8);
    ByteVec labelBytes(label.length());

    for (size_t k = 0; k < label.size(); k++)
        labelBytes[k] = label[k];

    for (uint32_t i = 0; i < numLoops; ++i)
    {
        TpmBuffer toHmac;
        toHmac.writeInt(i + 1);
        toHmac.writeByteBuf(labelBytes);
        toHmac.writeByte(0);
        toHmac.writeByteBuf(contextU);
        toHmac.writeByteBuf(contextV);
        toHmac.writeInt(numBitsRequired);

        auto frag = Crypto::HMAC(hmacHash, hmacKey, toHmac.trim());
        copy(frag.begin(), frag.end(), &kdfStream[i * bitsPerLoop / 8]);
    }

    return Helpers::ShiftRight(kdfStream, bitsPerLoop * numLoops - numBitsRequired);
}

/// <summary> TPM KDF function for ECDH. Note, a zero is added to the end of label by this routine </summary>
ByteVec Crypto::KDFe(TPM_ALG_ID hash, const TPMS_ECC_POINT& z, const string& label, const ByteVec& contextU,
                     const ByteVec& contextV, uint32_t numBitsRequired)
{
    uint32_t bitsPerLoop = Crypto::HashLength(hash) * 8;
    uint32_t numLoops = (numBitsRequired + bitsPerLoop - 1) / bitsPerLoop;
    ByteVec kdfStream(numLoops * bitsPerLoop / 8);
    ByteVec labelBytes(label.length());

    for (size_t k = 0; k < label.size(); k++)
        labelBytes[k] = label[k];

    for (uint32_t i = 0; i < numLoops; ++i)
    {
        TpmBuffer toHash;
        toHash.writeInt(i + 1);
        toHash.writeByteBuf(z.x);
        toHash.writeByteBuf(labelBytes);
        toHash.writeByte(0);
        toHash.writeByteBuf(contextU);
        toHash.writeByteBuf(contextV);

        auto frag = Crypto::Hash(hash, toHash.trim());
        copy(frag.begin(), frag.end(), &kdfStream[i * bitsPerLoop / 8]);
    }

    return Helpers::ShiftRight(kdfStream, bitsPerLoop * numLoops - numBitsRequired);
}

bool Crypto::ValidateSignature(const TPMT_PUBLIC& pubKey, const ByteVec& signedDigest,
                               const TPMU_SIGNATURE& sig)
{
    TPMS_RSA_PARMS *rsaParms = dynamic_cast<TPMS_RSA_PARMS*>(&*pubKey.parameters);
    if (rsaParms == NULL)
        throw domain_error("ValidateSignature: Only RSA is supported");

    const TPMS_SIGNATURE_RSASSA *rsaSig = dynamic_cast<const TPMS_SIGNATURE_RSASSA*>(&sig);
    if (rsaSig == NULL)
        throw domain_error("ValidateSignature: Only RSASSA scheme is supported");

    TPM2B_PUBLIC_KEY_RSA *rsaPubKey = dynamic_cast<TPM2B_PUBLIC_KEY_RSA*>(&*pubKey.unique);

    CryptoPP::Integer n;
    n.Decode(rsaPubKey->buffer.data(), rsaPubKey->buffer.size());
    CryptoPP::RSA::PublicKey pkey;
    pkey.Initialize(n, rsaParms->exponent);

    auto verifier = buildForHash<GetVerifier>(GetSigningHashAlg(pubKey), pkey);

    return verifier->VerifyMessage(signedDigest.data(), signedDigest.size(), rsaSig->sig.data(), rsaSig->sig.size());
}

void Crypto::CreateRsaKey(int bits, int exponent, ByteVec& outPublic, ByteVec& outPrivate)
{
    CryptoPP::RSA::PrivateKey key;
    key.Initialize(getRNG(), bits, exponent ? exponent : 65537);

    outPublic.resize(key.GetModulus().MinEncodedSize());
    key.GetModulus().Encode(outPublic.data(), outPublic.size());

    outPrivate.resize(key.GetPrime1().MinEncodedSize());
    key.GetPrime1().Encode(outPrivate.data(), outPrivate.size());
}

std::pair<TPMS_ECC_POINT, TPMS_ECC_POINT> Crypto::KeyGen(const TPMT_PUBLIC& pubKey)
{
    TPMS_ECC_PARMS *eccParms = dynamic_cast<TPMS_ECC_PARMS*>(pubKey.parameters.get());
    if (eccParms == NULL)
        throw domain_error("Only ECC keygen is supported");

    TPMS_ECC_POINT *eccPubKey = dynamic_cast<TPMS_ECC_POINT *>(pubKey.unique.get());

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> parameters(getCurve(eccParms->curveID));

    CryptoPP::Integer x, y;
    x.Decode(eccPubKey->x.data(), eccPubKey->x.size());
    y.Decode(eccPubKey->y.data(), eccPubKey->y.size());

    CryptoPP::ECPPoint theirPub(x, y);

    CryptoPP::Integer priv(getRNG(), 1, parameters.GetMaxExponent());
    CryptoPP::ECPPoint ourPub = parameters.ExponentiateBase(priv);

    TPMS_ECC_POINT encodedPub{};
    encodedPub.x.resize(parameters.GetEncodedElementSize(false));
    encodedPub.y.resize(parameters.GetEncodedElementSize(false));
    ourPub.x.Encode(encodedPub.x.data(), encodedPub.x.size());
    ourPub.y.Encode(encodedPub.y.data(), encodedPub.y.size());

    CryptoPP::ECPPoint shared = parameters.ExponentiateElement(theirPub, priv);
    TPMS_ECC_POINT encodedShared{};
    encodedShared.x.resize(parameters.GetEncodedElementSize(false));
    encodedShared.y.resize(parameters.GetEncodedElementSize(false));
    shared.x.Encode(encodedShared.x.data(), encodedShared.x.size());
    shared.y.Encode(encodedShared.y.data(), encodedShared.y.size());

    return {std::move(encodedPub), std::move(encodedShared)};
}

ByteVec Crypto::Encrypt(const TPMT_PUBLIC& pubKey,
                        const ByteVec& secret, const ByteVec& encodingParms)
{
    TPMS_RSA_PARMS *rsaParms = dynamic_cast<TPMS_RSA_PARMS*>(&*pubKey.parameters);
    if (rsaParms == NULL)
        throw domain_error("Only RSA encryption is supported");

    TPM_ALG hashAlg;
    switch(rsaParms->schemeScheme()) {
        case TPM_ALG::OAEP:
            hashAlg = static_cast<const TPMS_SCHEME_OAEP *>(rsaParms->scheme.get())->hashAlg;
            break;
        case TPM_ALG_NULL:
            hashAlg = pubKey.nameAlg;
            break;
        default:
            throw domain_error("Only OAEP encryption is supported");
    }

    TPM2B_PUBLIC_KEY_RSA *rsaPubKey = dynamic_cast<TPM2B_PUBLIC_KEY_RSA*>(&*pubKey.unique);

    CryptoPP::Integer n;
    n.Decode(rsaPubKey->buffer.data(), rsaPubKey->buffer.size());
    CryptoPP::RSA::PublicKey pkey;
    pkey.Initialize(n, rsaParms->exponent);

    auto encryptor = buildForHash<GetEncryptor>(hashAlg, pkey);
    std::size_t encBlobSize = encryptor->CiphertextLength(secret.size());

    ByteVec res(encBlobSize);

    encryptor->Encrypt(getRNG(), secret.data(), secret.size(), res.data(), MakeParameters
        (CryptoPP::Name::EncodingParameters(), CryptoPP::ConstByteArrayParameter(encodingParms.data(), encodingParms.size()))
    );

    return res;
}

SignResponse Crypto::Sign(const TSS_KEY& key, const ByteVec& toSign,
                          const TPMU_SIG_SCHEME& explicitScheme)
{
    // Set the selectors
    const TPMT_PUBLIC& pubKey = key.publicPart;
    TPMS_RSA_PARMS *rsaParms = dynamic_cast<TPMS_RSA_PARMS*>(&*pubKey.parameters);
    if (rsaParms == NULL)
        throw domain_error("Only RSA signing is supported");

    TPM2B_PUBLIC_KEY_RSA *rsaPubKey = dynamic_cast<TPM2B_PUBLIC_KEY_RSA*>(&*pubKey.unique);

    TPM_ALG_ID schemeAlg = rsaParms->schemeScheme(),
               expSchemeAlg = explicitScheme.GetUnionSelector();
    auto *scheme = dynamic_cast<const TPMS_SCHEME_RSASSA*>(&*rsaParms->scheme);

    if (schemeAlg == TPM_ALG_NULL)
    {
        schemeAlg = expSchemeAlg;
        scheme = dynamic_cast<const TPMS_SCHEME_RSASSA*>(&explicitScheme);
        if (schemeAlg == TPM_ALG_NULL)
            throw domain_error("Crypto::Sign: No signing scheme specified");
        else if (schemeAlg != TPM_ALG::RSASSA)
            throw domain_error("Crypto::Sign: Only RSASSA is supported");
    }
    else if (expSchemeAlg != TPM_ALG_NULL)
        throw domain_error("Crypto::Sign: Non-default scheme can only be used for a key with no scheme of its own");

    CryptoPP::Integer n;
    n.Decode(rsaPubKey->buffer.data(), rsaPubKey->buffer.size());
    CryptoPP::Integer e = rsaParms->exponent;
    CryptoPP::Integer p;
    p.Decode(key.privatePart.data(), key.privatePart.size());

    CryptoPP::Integer q = n/p;
    CryptoPP::Integer phi = n;
    phi -= p;
    phi -= q;
    phi += 1;

    CryptoPP::Integer d = e.InverseMod(phi);

    CryptoPP::RSA::PrivateKey pkey;
    pkey.Initialize(n, e, d);

    const int maxBuf = 4096;
    byte signature[maxBuf];

    auto signer = buildForHash<GetSigner>(scheme->hashAlg, pkey);

    size_t sigLen = signer->SignMessage(getRNG(), toSign.data(), toSign.size(), signature);

    TPM_ASSERT(sigLen <= maxBuf);

    SignResponse resp;
    resp.signature = make_shared<TPMS_SIGNATURE_RSASSA>(scheme->hashAlg,
                                                        ByteVec{signature, signature + sigLen});
    return resp;
}

ByteVec Crypto::CFBXcrypt(bool encrypt, TPM_ALG_ID algId,
                          const ByteVec& keyBytes, ByteVec& iv, const ByteVec& data)
{
    if (algId != TPM_ALG_ID::AES)
        throw domain_error("unsuppported SymmCipher");

    if (data.empty())
        return ByteVec();

    ByteVec res(data.size());

    const byte nullVec[16] = {0};
    const byte *pIv = iv.empty() ? nullVec : iv.data();
    std::size_t ivLength = iv.empty() ? sizeof(nullVec) : iv.size(); // Must be the block size

    int num = 0;

    if (encrypt) {
      CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor;
      encryptor.SetKeyWithIV(keyBytes.data(), keyBytes.size(), pIv, ivLength);
      CryptoPP::StringSource source(data.data(), data.size(), true,
          new CryptoPP::StreamTransformationFilter(
            encryptor,
            new CryptoPP::ArraySink(res.data(), res.size()),
            CryptoPP::StreamTransformationFilter::NO_PADDING));
    } else {
      CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor;
      decryptor.SetKeyWithIV(keyBytes.data(), keyBytes.size(), pIv, ivLength);
      CryptoPP::StringSource source(data.data(), data.size(), true,
          new CryptoPP::StreamTransformationFilter(
            decryptor,
            new CryptoPP::ArraySink(res.data(), res.size()),
            CryptoPP::StreamTransformationFilter::NO_PADDING));
    }
    return res;
}

ByteVec Crypto::StringToEncodingParms(const string& s)
{
    ByteVec parms(s.length() + 1);

    for (size_t k = 0; k < s.size(); k++) {
        parms[k] = s[k];
    }

    parms[s.length()] = 0;
    return parms;
}

}
