/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

#include "stdafx.h"

namespace TpmCpp {

using namespace std;

#define null  {}


//
// TPM_HANDLE
//

void TPM_HANDLE::SetName(const ByteVec& name)
{
    std::uint32_t handleType = GetHandleType();

    if (handleType == TPM_HT::NV_INDEX ||
        handleType == TPM_HT::TRANSIENT || 
        handleType == TPM_HT::PERSISTENT ||
        handleType == TPM_HT::PERSISTENT)
    {
        Name = name;
    }
        else
            assert (name == GetName() && "Setting an invalid name of an entity with the name defined by the handle value");
}

ByteVec TPM_HANDLE::GetName() const
{
    switch (GetHandleType())
    {
        case 0:
        case 2:
        case 3:
        case 0x40:
            Name = Int32ToTpm(handle);
            return Name;

        case 1:
        case 0x80:
        case 0x81:
            if (Name.empty())
                throw runtime_error("Name is not set for handle");
            return Name;

        default:
            throw runtime_error("Unknown handle type");
    }
}

//
// TPM_HANDLE
//

bool TPMT_PUBLIC::ValidateSignature(const ByteVec& signedData, const TPMU_SIGNATURE& sig)
{
    return Crypto::ValidateSignature(*this, signedData, sig);
}

bool TPMT_PUBLIC::ValidateQuote(const PCR_ReadResponse& expectedPcrVals,
                                const ByteVec& Nonce, QuoteResponse& quote) const
{
    TPM_ALG_ID hashAlg = GetSigningHashAlg(*this);
    TPMS_ATTEST attest = quote.quoted;

    // Validate the quote
    if (attest.extraData != Nonce)
        return false;

    if (attest.magic != TPM_GENERATED::VALUE)
        return false;

    TPMS_QUOTE_INFO *quoteInfo = dynamic_cast<TPMS_QUOTE_INFO*>(&*attest.attested);
    if (!quoteInfo)
        return false;

    if (quoteInfo->pcrSelect != expectedPcrVals.pcrSelectionOut)
        return false;

    // Check that the expected PCRs digest is as quoted
    if (quoteInfo->pcrDigest != Helpers::HashPcrs(hashAlg, expectedPcrVals.pcrValues))
        return false;

    // And finally check the signature
    ByteVec signedBlob = quote.quoted.toBytes();
    ByteVec signedBlobHash = Crypto::Hash(hashAlg, signedBlob);

    return Crypto::ValidateSignature(*this, signedBlobHash, *quote.signature);
}

bool TPMT_PUBLIC::ValidateCertify(const TPMT_PUBLIC& certifiedKey,
                                  const ByteVec& Nonce, CertifyResponse& certResponse) const
{
    TPM_ALG_ID hashAlg = GetSigningHashAlg(*this);
    TPMS_ATTEST attest = certResponse.certifyInfo;

    // Validate the quote
    if (attest.extraData != Nonce)
        return false;

    if (attest.magic != TPM_GENERATED::VALUE)
        return false;

    TPMS_CERTIFY_INFO *quoteInfo = dynamic_cast<TPMS_CERTIFY_INFO*>(&*attest.attested);
    if (quoteInfo == NULL)
        return false;

    if (quoteInfo->name != certifiedKey.GetName())
        return false;

    // TODO: Fully qualified name

    // And finally check the signature
    ByteVec signedBlob = certResponse.certifyInfo.toBytes();
    auto signedBlobHash = Crypto::Hash(hashAlg, signedBlob);
    return Crypto::ValidateSignature(*this, signedBlobHash, *certResponse.signature);
}

bool TPMT_PUBLIC::ValidateCertifyCreation(const ByteVec& Nonce, const ByteVec& creationHash,
                                          CertifyCreationResponse& certResponse) const
{
    TPM_ALG_ID hashAlg = GetSigningHashAlg(*this);
    TPMS_ATTEST attest = certResponse.certifyInfo;

    // Validate the quote
    if (attest.extraData != Nonce)
        return false;

    if (attest.magic != TPM_GENERATED::VALUE)
        return false;

    TPMS_CREATION_INFO *quoteInfo = dynamic_cast<TPMS_CREATION_INFO*>(&*attest.attested);
    if (!quoteInfo)
        return false;

    if (quoteInfo->creationHash != creationHash)
        return false;

    // And finally check the signature
    ByteVec signedBlob = certResponse.certifyInfo.toBytes();
    auto signedBlobHash = Crypto::Hash(hashAlg, signedBlob);
    return Crypto::ValidateSignature(*this, signedBlobHash, *certResponse.signature);
}

bool TPMT_PUBLIC::ValidateGetTime(const ByteVec& Nonce, GetTimeResponse& timeQuote) const
{
    TPM_ALG_ID hashAlg = GetSigningHashAlg(*this);
    TPMS_ATTEST attest = timeQuote.timeInfo;

    // Validate the quote
    if (attest.extraData != Nonce)
        return false;

    if (attest.magic != TPM_GENERATED::VALUE)
        return false;

    // And finally check the signature
    ByteVec signedBlob = timeQuote.timeInfo.toBytes();
    auto signedBlobHash = Crypto::Hash(hashAlg, signedBlob);
    return Crypto::ValidateSignature(*this, signedBlobHash, *timeQuote.signature);
}

bool TPMT_PUBLIC::ValidateCommandAudit(const TPMT_HA& expectedHash, const ByteVec& Nonce,
                                       GetCommandAuditDigestResponse& quote) const
{
    TPM_ALG_ID hashAlg = GetSigningHashAlg(*this);
    TPMS_ATTEST attest = quote.auditInfo;

    // Validate the quote
    if (attest.extraData != Nonce)
        return false;

    if (attest.magic != TPM_GENERATED::VALUE)
        return false;

    auto sessionInfo = dynamic_cast<TPMS_COMMAND_AUDIT_INFO*>(&*attest.attested);
    if (expectedHash != sessionInfo->auditDigest)
        return false;

    // And finally check the signature
    ByteVec signedBlob = quote.auditInfo.toBytes();
    auto signedBlobHash = Crypto::Hash(hashAlg, signedBlob);
    return Crypto::ValidateSignature(*this, signedBlobHash, *(quote.signature));
}

bool TPMT_PUBLIC::ValidateSessionAudit(const TPMT_HA& expectedHash, const ByteVec& Nonce,
                                       GetSessionAuditDigestResponse& quote) const
{
    TPM_ALG_ID hashAlg = GetSigningHashAlg(*this);
    TPMS_ATTEST attest = quote.auditInfo;

    // Validate the quote
    if (attest.extraData != Nonce)
        return false;

    if (attest.magic != TPM_GENERATED::VALUE)
        return false;

    auto sessionInfo = dynamic_cast<TPMS_SESSION_AUDIT_INFO*>(&*attest.attested);
    if (expectedHash != sessionInfo->sessionDigest)
        return false;

    // And finally check the signature
    ByteVec signedBlob = quote.auditInfo.toBytes();
    auto signedBlobHash = Crypto::Hash(hashAlg, signedBlob);
    return Crypto::ValidateSignature(*this, signedBlobHash, *(quote.signature));
}

bool TPMT_PUBLIC::ValidateCertifyNV(const ByteVec& Nonce, const ByteVec& expectedContents,
                                    std::uint16_t offset,  NV_CertifyResponse& quote) const
{
    TPM_ALG_ID hashAlg = GetSigningHashAlg(*this);
    TPMS_ATTEST attest = quote.certifyInfo;

    // Validate the quote
    if (attest.extraData != Nonce)
        return false;

    if (attest.magic != TPM_GENERATED::VALUE)
        return false;

    TPMS_NV_CERTIFY_INFO *nvInfo = dynamic_cast<TPMS_NV_CERTIFY_INFO*>(&*attest.attested);
    if (nvInfo->nvContents != expectedContents)
        return false;

    if (nvInfo->offset != offset)
        return false;

    // And finally check the signature
    ByteVec signedBlob = quote.certifyInfo.toBytes();
    auto signedBlobHash = Crypto::Hash(hashAlg, signedBlob);
    return Crypto::ValidateSignature(*this, signedBlobHash, *(quote.signature));
}

ByteVec TPMT_PUBLIC::Encrypt(const ByteVec& secret, const ByteVec& encodingParms) const
{
    return Crypto::Encrypt(*this, secret, encodingParms);
}

std::pair<ByteVec, ByteVec> TPMT_PUBLIC::GenerateSessionSalt() const
{
    switch (parameters->GetUnionSelector()) {
        case TPM_ALG_ID::ECC: {
            auto generated = Crypto::KeyGen(*this);
            ByteVec secret = Crypto::KDFe(this->nameAlg, generated.second, "SECRET",
                                          generated.first.x, static_cast<TPMS_ECC_POINT *>(unique.get())->x, 8 * Crypto::HashLength(this->nameAlg));
            return {std::move(secret), generated.first.toBytes()};
        }
        case TPM_ALG_ID::RSA: {
            ByteVec secret = Crypto::GetRand(Crypto::HashLength(nameAlg));
            ByteVec encrypted = EncryptSessionSalt(secret);
            return {std::move(secret), std::move(encrypted)};
        }
        default:
            throw domain_error("Session key generation only supported for ECC and RSA");
    }
}

ByteVec TPMT_PUBLIC::EncryptSessionSalt(const ByteVec& secret) const
{
    string idString = string("SECRET");
    ByteVec label(idString.length() + 1);

    for (size_t j = 0; j < idString.length(); j++)
        label[j] = (byte)idString[j];

    return Crypto::Encrypt(*this, secret, label);
}

ActivationData TPMT_PUBLIC::CreateActivation(const ByteVec& secret, const ByteVec& activatedName) const
{
    const TPMT_SYM_DEF_OBJECT *symDef;
    ByteVec seed;
    ActivationData act;

    switch (parameters->GetUnionSelector()) {
        case TPM_ALG_ID::ECC:
        {
            const TPMS_ECC_PARMS &newParentParms = static_cast<const TPMS_ECC_PARMS &>(*this->parameters);
            symDef = &newParentParms.symmetric;

            auto generated = Crypto::KeyGen(*this);
            seed = Crypto::KDFe(nameAlg, generated.second, "IDENTITY",
                                generated.first.x, static_cast<TPMS_ECC_POINT *>(unique.get())->x, 8 * Crypto::HashLength(nameAlg));
            act.Secret = generated.first.toBytes();
            break;
        }
        case TPM_ALG_ID::RSA:
        {
            const TPMS_RSA_PARMS &parms = static_cast<const TPMS_RSA_PARMS&>(*parameters);

            symDef = &parms.symmetric;

            seed = Crypto::GetRand(Crypto::HashLength(nameAlg));
            ByteVec label = Crypto::StringToEncodingParms("IDENTITY");
            act.Secret = this->Encrypt(seed, label);
            break;
        }
        default:
            throw domain_error("Only ECC and RSA activation supported");
    }

    if ((symDef->algorithm != TPM_ALG_ID::AES) ||
        (symDef->keyBits % 8 != 0) ||
        (symDef->mode != TPM_ALG_ID::CFB)) {
        throw domain_error("Unsupported wrapping scheme");
    }

    TPM2B_DIGEST secretStruct(secret);
    ByteVec lengthPrependedSecret = secretStruct.toBytes();
    // Then make the cred blob. First the encrypted secret.  Make the key then encrypt.

    ByteVec symKey = Crypto::KDFa(this->nameAlg, seed, "STORAGE",
                                   activatedName, {}, symDef->keyBits);
    ByteVec encIdentity = Crypto::CFBXcrypt(true, TPM_ALG_ID::AES, symKey, {}, lengthPrependedSecret);

    // Next the HMAC protection
    int npNameNumBits = Crypto::HashLength(nameAlg) * 8;
    ByteVec hmacKey = Crypto::KDFa(nameAlg, seed, "INTEGRITY",
                                   null, null, npNameNumBits);
    // Next the outer HMAC
    ByteVec outerHmac = Crypto::HMAC(this->nameAlg, hmacKey,
                                     Helpers::Concatenate(encIdentity, activatedName));

    act.CredentialBlob = TPMS_ID_OBJECT(outerHmac, encIdentity);
    return act;
}

DuplicationBlob TPMT_PUBLIC::GetDuplicationBlob(Tpm2& _tpm, const TPMT_PUBLIC& pub,
                                                const TPMT_SENSITIVE& sensitive,
                                                const TPMT_SYM_DEF_OBJECT& innerWrapper) const
{
    DuplicationBlob blob;
    ByteVec encryptedSensitive;
    ByteVec innerWrapperKey;

    switch (innerWrapper.algorithm) {
        case TPM_ALG_NULL:
            encryptedSensitive = sensitive.asTpm2B();
            break;
        case TPM_ALG_ID::AES:
        {
            if (innerWrapper.keyBits % 8 != 0 ||
                innerWrapper.mode != TPM_ALG_ID::CFB) {
                throw domain_error("innerWrapper KeyDef is not supported for import");
            }

            ByteVec sens = sensitive.asTpm2B();
            ByteVec toHash = Helpers::Concatenate(sens, pub.GetName());

            ByteVec innerIntegrity = Helpers::ToTpm2B(Crypto::Hash(pub.nameAlg, toHash));
            ByteVec innerData = Helpers::Concatenate(innerIntegrity, sens);

            blob.InnerWrapperKey = Helpers::RandomBytes(innerWrapper.keyBits/8);
            encryptedSensitive = Crypto::CFBXcrypt(true, TPM_ALG_ID::AES,
                                                   blob.InnerWrapperKey, {}, innerData);
            break;
        }
        default:
            throw domain_error("innerWrapper KeyDef is not supported for import");
    }

    ByteVec seed;
    const TPMT_SYM_DEF_OBJECT *newParentSymDef;
    switch (type())
    {
        case TPM_ALG_ID::RSA:
        {
            const TPMS_RSA_PARMS &newParentParms = static_cast<const TPMS_RSA_PARMS &>(*this->parameters);
            newParentSymDef = &newParentParms.symmetric;

            seed = Helpers::RandomBytes(Crypto::HashLength(nameAlg));
            ByteVec parms = Crypto::StringToEncodingParms("DUPLICATE");
            blob.EncryptedSeed = this->Encrypt(seed, parms);
            break;
        }
        case TPM_ALG_ID::ECC:
        {
            const TPMS_ECC_PARMS &newParentParms = static_cast<const TPMS_ECC_PARMS &>(*this->parameters);
            newParentSymDef = &newParentParms.symmetric;

            auto generated = Crypto::KeyGen(*this);
            seed = Crypto::KDFe(nameAlg, generated.second, "DUPLICATE",
                                generated.first.x, static_cast<TPMS_ECC_POINT *>(unique.get())->x, 8 * Crypto::HashLength(nameAlg));
            blob.EncryptedSeed = generated.first.toBytes();
            break;
        }
        default:
            throw domain_error("Only import of keys to RSA storage parents supported");
    }

    if (newParentSymDef->algorithm != TPM_ALG_ID::AES ||
        newParentSymDef->mode != TPM_ALG_ID::CFB)
    {
        throw domain_error("new parent symmetric key is not supported for import");
    }

    ByteVec symmKey = Crypto::KDFa(this->nameAlg, seed, "STORAGE",
                                   pub.GetName(), null, newParentSymDef->keyBits);
    ByteVec dupSensitive = Crypto::CFBXcrypt(true, TPM_ALG_ID::AES, symmKey, {}, encryptedSensitive);

    int npNameNumBits = Crypto::HashLength(nameAlg) * 8;
    ByteVec hmacKey = Crypto::KDFa(nameAlg, seed, "INTEGRITY", null, null, npNameNumBits);
    ByteVec outerDataToHmac = Helpers::Concatenate(dupSensitive, pub.GetName());
    ByteVec outerHmacBytes = Crypto::HMAC(nameAlg, hmacKey, outerDataToHmac);
    ByteVec outerHmac = Helpers::ToTpm2B(outerHmacBytes);
    blob.DuplicateObject = Helpers::Concatenate(outerHmac, dupSensitive);

    return blob;
} // TPMT_PUBLIC::GetDuplicationBlob()

DuplicationBlob TPMT_PUBLIC::CreateImportableObject(Tpm2& tpm, const TPMT_PUBLIC& pub, const TPMT_SENSITIVE& sensitive,
                                                const TPMT_SYM_DEF_OBJECT& innerWrapper)
{
    return GetDuplicationBlob(tpm, pub, sensitive, innerWrapper);
}

ByteVec TPMT_PUBLIC::GetName() const
{
    ByteVec pubHash = Crypto::Hash(nameAlg, toBytes());
    ByteVec theHashAlg = Int16ToTpm(nameAlg);
    pubHash.insert(pubHash.begin(), theHashAlg.begin(), theHashAlg.end());
    return pubHash;
}

//
// TPMS_PCR_SELECTION
//

TPMS_PCR_SELECTION::TPMS_PCR_SELECTION(TPM_ALG_ID hashAlg, std::uint32_t pcr)
{
    hash = hashAlg;
    std::uint32_t sz = 3;

    if ((pcr / 8 + 1) > sz)
        sz = pcr / 8 + 1;

    pcrSelect.resize(sz);
    pcrSelect[pcr / 8] = 1 << (pcr % 8);
}

TPMS_PCR_SELECTION::TPMS_PCR_SELECTION(TPM_ALG_ID hashAlg, const vector<std::uint32_t>& pcrs)
{
    hash = hashAlg;
    std::uint32_t pcrMax = 0;

    for (size_t i = 0; i < pcrs.size(); i++)
    {
        if (pcrs[i] > pcrMax)
            pcrMax = pcrs[i];
    }
    if (pcrMax < 23)
        pcrMax = 23;

    pcrSelect.resize(pcrMax / 8 + 1);
    for (size_t i = 0; i < pcrs.size(); i++)
        pcrSelect[pcrs[i] / 8] |= 1 << (pcrs[i] % 8);
}

vector<std::uint32_t> TPMS_PCR_SELECTION::ToArray()
{
    vector<std::uint32_t> arr;
    int maxIs = (int)pcrSelect.size() * 8;

    for (int j = 0; j < maxIs; j++) {
        if (PcrIsSelected(j))
            arr.push_back((std::uint32_t)j);
    }
    return arr;
}

//
// TSS_KEY
//

void TSS_KEY::CreateKey()
{
    switch (publicPart.parameters->GetUnionSelector()) {
        case TPM_ALG::ECC:
        {
            const TPMS_ECC_PARMS &parms = static_cast<const TPMS_ECC_PARMS&>(*publicPart.parameters);

            ByteVec x, y, priv;
            Crypto::CreateEccKey(parms.curveID, x, y, priv);

            TPMS_ECC_POINT &pubKey = static_cast<TPMS_ECC_POINT&>(*publicPart.unique);
            pubKey.x = std::move(x);
            pubKey.y = std::move(y);
            this->privatePart = std::move(priv);
            return;
        }
        case TPM_ALG::RSA:
        {
            const TPMS_RSA_PARMS &parms = static_cast<const TPMS_RSA_PARMS&>(*publicPart.parameters);

            int keySize = parms.keyBits;
            std::uint32_t exponent = parms.exponent;
            ByteVec pub, priv;
            Crypto::CreateRsaKey(keySize, exponent, pub, priv);

            TPM2B_PUBLIC_KEY_RSA *pubKey = dynamic_cast<TPM2B_PUBLIC_KEY_RSA*>(&*publicPart.unique);
            pubKey->buffer = pub;
            this->privatePart = priv;
            break;
        }
        default:
            throw domain_error("Only RSA and ECC activation supported");
    }
}

SignResponse TSS_KEY::Sign(const ByteVec& dataToSign, const TPMU_SIG_SCHEME& nonDefaultScheme) const
{
    return Crypto::Sign(*this, dataToSign, nonDefaultScheme);
}

//
// TPMT_HA
//

TPMT_HA::TPMT_HA(TPM_ALG_ID alg)
{
    auto hashLen = Crypto::HashLength(alg);
    hashAlg = alg;
    digest.resize(0);
    digest.resize(hashLen);
}

TPMT_HA TPMT_HA::FromHashOfData(TPM_ALG_ID alg, const ByteVec& data)
{
    return TPMT_HA(alg, Crypto::Hash(alg, data));
}

TPMT_HA TPMT_HA::FromHashOfString(TPM_ALG_ID alg, const string& str)
{
    // TODO: Unicode
    ByteVec t(str.begin(), str.end());
    return TPMT_HA(alg, Crypto::Hash(alg, t));
}

std::uint16_t TPMT_HA::DigestSize()
{
    return Crypto::HashLength(hashAlg);
}

std::uint16_t TPMT_HA::DigestSize(TPM_ALG_ID alg)
{
    return Crypto::HashLength(alg);
}

TPMT_HA& TPMT_HA::Extend(const ByteVec& x)
{
    ByteVec t = Helpers::Concatenate(digest, x);
    digest = Crypto::Hash(hashAlg, t);
    return *this;

}

TPMT_HA TPMT_HA::Event(const ByteVec& x)
{
    auto s = Crypto::Hash(hashAlg, x);
    ByteVec t = Helpers::Concatenate(digest, s);
    digest = Crypto::Hash(hashAlg, t);
    return *this;
}

void TPMT_HA::Reset()
{
    fill(digest.begin(), digest.end(), (byte)0);
}

}
