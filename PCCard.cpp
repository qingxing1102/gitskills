#include "PCCard.h"
#include "Buffer.h"
#include "PKey.h"
#include "ifs/aixing.h"
#include "ssl.h"

#define PCIE_KEY_INDEX 1
#define PCIE_CA_FILE_NAME "pcie_ca.der"
#define PCIE_CERT_FILE_NAME "pcie_cert.der"

namespace fibjs {

result_t aixing_base::pcie_reset(exlib::string old_passwd, exlib::string new_passwd, obj_ptr<PCCard_base> &retVal)
{
    obj_ptr<PCCard> card = new PCCard();

    retVal = card;

    return card->reset(old_passwd, new_passwd);
}


result_t aixing_base::pcie_open(exlib::string passwd, obj_ptr<PCCard_base>& retVal)
{
    obj_ptr<PCCard> card = new PCCard();

    retVal = card;

    return card->open(passwd);
}

inline result_t sdf_error(const char* api, int ret)
{
    char msg[128];
    sprintf(msg, "%s error: %x", api, ret);
    return Runtime::setError(msg);
}

result_t PCCard::open(exlib::string passwd)
{
    int ret;

    ret = SDF_OpenDevice(&hdev);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_OpenDevice", ret));

    ret = SDF_OpenSession(hdev, &hsess);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_OpenSession", ret));

    ret = SDF_GetPrivateKeyAccessRight(hsess, PCIE_KEY_INDEX, (u8*)passwd.c_str(), passwd.length());
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_GetPrivateKeyAccessRight", ret));

    m_passwd = passwd;

    return 0;
}

result_t PCCard::write_cert(const char* name, X509Cert* cert)
{
    int ret = 0;
    u32 file_size = 0;
    int32_t slen = qstrlen(name);

    SDF_DeleteFile(hsess, (u8*)name, slen);

    ret = SDF_CreateFile(hsess, (u8*)name, slen, cert->m_crt.raw.len);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_CreateFile", ret));

    ret = SDF_WriteFile(hsess, (u8*)name, slen, 0, cert->m_crt.raw.len, (u8*)cert->m_crt.raw.p);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_WriteFile", ret));

    return 0;
}

result_t PCCard::read_cert(const char* name, obj_ptr<X509Cert>& retVal)
{
    int ret = 0;
    int32_t slen = qstrlen(name);
    u32 len = 0;
    exlib::string buf;

    ret = SDF_ReadFile(hsess, (u8*)name, slen, 0, &len, NULL);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_ReadFile", ret));

    buf.resize(len);
    ret = SDF_ReadFile(hsess, (u8*)name, slen, 0, &len, (u8*)buf.c_buffer());
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_ReadFile", ret));

    retVal = new X509Cert();
    ret = mbedtls_x509_crt_parse_der(&retVal->m_crt, (const unsigned char*)buf.c_str(), len);
    if (ret != 0)
        return CHECK_ERROR(_ssl::setError(ret));

    return 0;
}

result_t PCCard::reset(exlib::string old_passwd, exlib::string new_passwd)
{
    int ret;
    unsigned char firm_version[64] = {0};
    unsigned char root_key[16] = {0xAF, 0x86, 0x18, 0x23, 0x8C, 0x94, 0xA1, 0x19, 0xAE, 0x6D, 0xE9, 0x22, 0xDB, 0xB9, 0x35, 0x4D};
    ret = SDF_OpenDevice(&hdev);
    if (ret)
    	return CHECK_ERROR(sdf_error("SDF_OpenDevice", ret));

    ret = SDF_OpenSession(hdev, &hsess);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_OpenSession", ret));

    ret = EVDF_GetFirmwareVersion(hsess, firm_version);
    if (ret)
        return CHECK_ERROR(sdf_error("EVDF_GetFirmwareVersion", ret));

    ret = EVDF_InitKeyFileSystem(hsess, (char *)old_passwd.c_str(), root_key, 128, (char *)new_passwd.c_str(), (char *)new_passwd.c_str());
    if (ret)
    {
        return CHECK_ERROR(sdf_error("EVDF_InitKeyFileSystem", ret));
    }

    ret = SDF_GetPrivateKeyAccessRight(hsess, PCIE_KEY_INDEX, (u8 *)new_passwd.c_str(), new_passwd.length());
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_GetPrivateKeyAccessRight", ret));

    m_passwd = new_passwd;

    return 0;
}


result_t PCCard::init(X509Cert_base* ca, X509Cert_base* crt, PKey_base* key)
{
    PKey* _key = (PKey*)key;
    X509Cert* _ca = (X509Cert*)ca;
    X509Cert* _crt = (X509Cert*)crt;

    mbedtls_pk_type_t type = mbedtls_pk_get_type(&_key->m_key);
    if (type != MBEDTLS_PK_SM2)
        return CHECK_ERROR(CALL_E_INVALID_CALL);

    mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(_key->m_key);
    int32_t sz = (int32_t)mbedtls_mpi_size(&ecp->Q.X);

    ECCrefPublicKey ecc_pubkey;
    ECCrefPrivateKey ecc_prikey;

    memset(&ecc_pubkey, 0, sizeof(ecc_pubkey));
    ecc_pubkey.bits = 256;
    mbedtls_mpi_write_binary(&ecp->Q.X, (u8*)ecc_pubkey.x + sizeof(ecc_pubkey.x) - sz, sz);
    mbedtls_mpi_write_binary(&ecp->Q.Y, (u8*)ecc_pubkey.y + sizeof(ecc_pubkey.y) - sz, sz);

    memset(&ecc_prikey, 0, sizeof(ecc_prikey));
    ecc_prikey.bits = 256;
    mbedtls_mpi_write_binary(&ecp->d, (u8*)ecc_prikey.K + sizeof(ecc_prikey.K) - sz, sz);

    EVDF_DeleteInternalKeyPair_ECC(hsess, 0, PCIE_KEY_INDEX, (char*)m_passwd.c_str());
    EVDF_DeleteInternalKeyPair_ECC(hsess, 1, PCIE_KEY_INDEX, (char*)m_passwd.c_str());

    int ret;
    ret = EVDF_ImportKeyPair_ECC(hsess, 0, PCIE_KEY_INDEX, &ecc_pubkey, &ecc_prikey);
    if (ret)
        return CHECK_ERROR(sdf_error("EVDF_ImportKeyPair_ECC", ret));
    ret = EVDF_ImportKeyPair_ECC(hsess, 1, PCIE_KEY_INDEX, &ecc_pubkey, &ecc_prikey);
    if (ret)
        return CHECK_ERROR(sdf_error("EVDF_ImportKeyPair_ECC", ret));

    ret = write_cert(PCIE_CA_FILE_NAME, _ca);
    if (ret < 0)
        return ret;

    ret = write_cert(PCIE_CERT_FILE_NAME, _crt);
    if (ret < 0)
        return ret;

    return 0;
}

result_t PCCard::sign(Buffer_base* data, obj_ptr<Buffer_base>& retVal)
{
    int ret;
    exlib::string buf;
    ECCSignature ecc_sig;

    data->toString(buf);
    ret = SDF_InternalSign_ECC(hsess, PCIE_KEY_INDEX, (u8*)buf.c_str(), buf.length(), &ecc_sig);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_InternalSign_ECC", ret));

    exlib::string _sign;

    _sign.resize(32 * 2 + 6);
    char* p = _sign.c_buffer();

    *p++ = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
    *p++ = (32 + 2) * 2;

    *p++ = MBEDTLS_ASN1_INTEGER;
    *p++ = 32;
    memcpy(p, ecc_sig.r + sizeof(ecc_sig.r) - 32, 32);
    p += 32;

    *p++ = MBEDTLS_ASN1_INTEGER;
    *p++ = 32;
    memcpy(p, ecc_sig.s + sizeof(ecc_sig.s) - 32, 32);
    p += 32;

    retVal = new Buffer(_sign);

    return 0;
}

result_t PCCard::encrypt(Buffer_base* data, obj_ptr<Buffer_base>& retVal)
{
    exlib::string buf;
    char enbuf[1024];
    ECCCipher* endata = (ECCCipher*)enbuf;

    data->toString(buf);
    int ret = SDF_InternalEncrypt_ECC(hsess, PCIE_KEY_INDEX, (u8*)buf.c_str(), buf.length(), endata);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_InternalEncrypt_ECC", ret));

    buf.resize(32 * 3 + 1 + endata->L);
    char* p = buf.c_buffer();
    *p++ = MBEDTLS_ECP_POINT_CONVERSION_UNCOMPRESSED;

    memcpy(p, endata->x + sizeof(endata->x) - 32, 32);
    p += 32;
    memcpy(p, endata->y + sizeof(endata->y) - 32, 32);
    p += 32;
    memcpy(p, endata->C, endata->L);
    p += endata->L;
    memcpy(p, endata->M, 32);
    p += 32;

    retVal = new Buffer(buf);

    return 0;
}

result_t PCCard::decrypt(Buffer_base* data, obj_ptr<Buffer_base>& retVal)
{
    exlib::string buf;
    char enbuf[1024];
    ECCCipher* endata = (ECCCipher*)enbuf;
    char debuf[1024];
    u32 len = sizeof(debuf);

    memset(enbuf, 0, sizeof(enbuf));

    data->toString(buf);
    const char* p = buf.c_str();

    if (*p++ != MBEDTLS_ECP_POINT_CONVERSION_UNCOMPRESSED)
        return CHECK_ERROR(CALL_E_INVALID_DATA);

    endata->L = buf.length() - 32 * 3 - 1;
    memcpy(endata->x + sizeof(endata->x) - 32, p, 32);
    p += 32;
    memcpy(endata->y + sizeof(endata->y) - 32, p, 32);
    p += 32;
    memcpy(endata->C, p, endata->L);
    p += endata->L;
    memcpy(endata->M, p, 32);
    p += 32;

    int ret = SDF_InternalDecrypt_ECC(hsess, PCIE_KEY_INDEX, endata, (u8*)debuf, &len);
    if (ret)
        return CHECK_ERROR(sdf_error("SDF_InternalDecrypt_ECC", ret));

    retVal = new Buffer(debuf, len);

    return 0;
}

result_t PCCard::close()
{
    if (hsess) {
        SDF_CloseSession(hsess);
        hsess = NULL;
    }

    if (hdev) {
        SDF_CloseDevice(hdev);
        hdev = NULL;
    }

    return 0;
}

result_t PCCard::get_cert(obj_ptr<X509Cert_base>& retVal)
{
    if (!m_cert) {
        result_t ret = read_cert(PCIE_CERT_FILE_NAME, m_cert);
        if (ret < 0)
            return ret;
    }

    retVal = m_cert;

    return 0;
}

result_t PCCard::get_ca(obj_ptr<X509Cert_base>& retVal)
{
    if (!m_ca) {
        result_t ret = read_cert(PCIE_CA_FILE_NAME, m_ca);
        if (ret < 0)
            return ret;
    }

    retVal = m_ca;

    return 0;
}

}
