#include "TFCard.h"
#include "Buffer.h"
#include "PKey.h"
#include "X509Cert.h"
#include "ifs/aixing.h"
#include "ssl.h"

#define BLOCK_SIZE 65536
#define APP_NAME "DEFAULT"
#define CTN_NAME "DEFAULT"
#define TF_CA_FILE_NAME "tf_ca.der"

u32 DEVAPI _V_Control(HANDLE hHandle, u32 request, void* p);
#undef V_Control
#define V_Control _V_Control

namespace fibjs {

DECLARE_MODULE(aixing);

result_t aixing_base::tf_open(exlib::string pin, obj_ptr<TFCard_base>& retVal)
{
    obj_ptr<TFCard> card = new TFCard();

    retVal = card;

    return card->open(pin);
}

inline result_t skf_error(const char* api, int ret)
{
    char msg[128];
    sprintf(msg, "%s error: %x", api, ret);
    return Runtime::setError(msg);
}

result_t TFCard::open(exlib::string pin)
{
    int ret;
    char names[1024] = { 0 };
    u32 names_len = sizeof(names);

    ret = SKF_EnumDev(1, names, &names_len);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_EnumDev", ret));

    ret = SKF_ConnectDev(names, &hdev);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_ConnectDev", ret));

    ret = SKF_OpenApplication(hdev, APP_NAME, &happ);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_OpenApplication", ret));

    m_pin = pin;

    return 0;
}

result_t TFCard::init(X509Cert_base* ca, X509Cert_base* crt, PKey_base* key)
{
    PKey* _key = (PKey*)key;
    X509Cert* _ca = (X509Cert*)ca;
    X509Cert* _crt = (X509Cert*)crt;

    mbedtls_pk_type_t type = mbedtls_pk_get_type(&_key->m_key);
    if (type != MBEDTLS_PK_SM2)
        return CHECK_ERROR(CALL_E_INVALID_CALL);

    int ret;
    HCONTAINER hctn = 0;

    u32 retry = 0;
    ret = SKF_VerifyPIN(happ, USER_TYPE, (LPSTR)m_pin.c_str(), &retry);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_VerifyPIN", ret));

    ret = SKF_OpenContainer(happ, CTN_NAME, &hctn);
    if (ret == SAR_FILE_NOT_EXIST) {
        ret = SKF_CreateContainer(happ, CTN_NAME, &hctn);
        if (ret)
            return CHECK_ERROR(skf_error("SKF_CreateContainer", ret));
    } else if (ret)
        return CHECK_ERROR(skf_error("SKF_OpenContainer", ret));

    exlib::string data;
    mbedtls_ecp_keypair* ecp = mbedtls_pk_ec(_key->m_key);
    int32_t sz = (int32_t)mbedtls_mpi_size(&ecp->Q.X);

    data.resize(sz * 3);
    mbedtls_mpi_write_binary(&ecp->Q.X, (unsigned char*)data.c_buffer(), sz);
    mbedtls_mpi_write_binary(&ecp->Q.Y, (unsigned char*)data.c_buffer() + sz, sz);
    mbedtls_mpi_write_binary(&ecp->d, (unsigned char*)data.c_buffer() + sz * 2, sz);

    ret = V_ImportKeyPair(hctn, V_F_KEY_ALGO_SM2 | V_F_KEY_BITS_256 | V_F_KEY_USAGE_SIGN,
        (u8*)data.c_str(), sz * 3);
    if (ret) {
        SKF_CloseContainer(hctn);
        return CHECK_ERROR(skf_error("V_ImportKeyPair", ret));
    }

    ret = SKF_ImportCertificate(hctn, 1, _crt->m_crt.raw.p, _crt->m_crt.raw.len);
    if (ret) {
        SKF_CloseContainer(hctn);
        return CHECK_ERROR(skf_error("SKF_ImportCertificate", ret));
    }

    SKF_CloseContainer(hctn);

    FILEATTRIBUTE attr;

    memset(&attr, 0, sizeof(attr));
    ret = SKF_GetFileInfo(happ, TF_CA_FILE_NAME, &attr);
    if (ret == 0 && attr.FileSize != _ca->m_crt.raw.len) {
        ret = SKF_DeleteFile(happ, TF_CA_FILE_NAME);
        if (ret)
            return CHECK_ERROR(skf_error("SKF_DeleteFile", ret));

        ret = SAR_FILE_NOT_EXIST;
    }
    if (ret == SAR_FILE_NOT_EXIST) {
        ret = SKF_CreateFile(happ, TF_CA_FILE_NAME, _ca->m_crt.raw.len, SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
        if (ret)
            return CHECK_ERROR(skf_error("SKF_CreateFile", ret));
    } else if (ret)
        return CHECK_ERROR(skf_error("SKF_GetFileInfo", ret));

    ret = SKF_WriteFile(happ, TF_CA_FILE_NAME, 0, _ca->m_crt.raw.p, _ca->m_crt.raw.len);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_CreateFile", ret));

    return 0;
}

result_t TFCard::exchg_cr(X509Cert_base* sc, Buffer_base* sr, obj_ptr<Exchg_crType>& retVal)
{
    int ret;
    GEN_CR_PARAM param;
    char buf[512];

    X509Cert* _sc = (X509Cert*)sc;
    memset(&param, 0, sizeof(param));
    param.szCAFile = TF_CA_FILE_NAME;
    param.pbSC = _sc->m_crt.raw.p;
    param.cbSC = _sc->m_crt.raw.len;
    param.pbCipherCr = (PECCCIPHERBLOB)buf;

    u32 retry = 0;
    ret = SKF_VerifyPIN(happ, USER_TYPE, (LPSTR)m_pin.c_str(), &retry);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_VerifyPIN", ret));

    ret = V_Control(happ, V_CTL_GEN_CR, &param);
    if (ret)
        return CHECK_ERROR(skf_error("V_Control", ret));

    exlib::string _cr1;
    _cr1.resize(32 * 3 + 1 + param.pbCipherCr->CipherLen);
    char* p = _cr1.c_buffer();
    *p++ = MBEDTLS_ECP_POINT_CONVERSION_UNCOMPRESSED;

    memcpy(p, param.pbCipherCr->XCoordinate + sizeof(param.pbCipherCr->XCoordinate) - 32, 32);
    p += 32;
    memcpy(p, param.pbCipherCr->YCoordinate + sizeof(param.pbCipherCr->XCoordinate) - 32, 32);
    p += 32;
    memcpy(p, param.pbCipherCr->Cipher, param.pbCipherCr->CipherLen);
    p += param.pbCipherCr->CipherLen;
    memcpy(p, param.pbCipherCr->HASH, 32);
    p += 32;

    retVal = new Exchg_crType();
    retVal->cr1 = new Buffer(_cr1);

    HANDLE hhash = 0;
    u8 hash[128] = { 0 };
    u32 hash_len = sizeof(hash);

    ret = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &hhash);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_DigestInit", ret));

    exlib::string _sr;
    sr->toString(_sr);

    ret = SKF_DigestUpdate(hhash, (u8*)_sr.c_str(), _sr.length());
    if (ret)
        return CHECK_ERROR(skf_error("SKF_DigestUpdate", ret));

    ret = SKF_DigestUpdate(hhash, (u8*)_cr1.c_str(), _cr1.length());
    if (ret)
        return CHECK_ERROR(skf_error("SKF_DigestUpdate", ret));

    ret = SKF_DigestFinal(hhash, hash, &hash_len);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_DigestFinal", ret));

    HCONTAINER hctn = 0;
    ret = SKF_OpenContainer(happ, CTN_NAME, &hctn);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_OpenContainer", ret));

    ret = SKF_ECCSignData(hctn, hash, hash_len, (PECCSIGNATUREBLOB)buf);
    if (ret) {
        SKF_CloseContainer(hctn);
        return CHECK_ERROR(skf_error("SKF_ECCSignData", ret));
    }

    PECCSIGNATUREBLOB psb = (PECCSIGNATUREBLOB)buf;

    exlib::string _sign;

    _sign.resize(32 * 2 + 6);
    p = _sign.c_buffer();

    *p++ = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
    *p++ = (32 + 2) * 2;

    *p++ = MBEDTLS_ASN1_INTEGER;
    *p++ = 32;
    memcpy(p, psb->r + sizeof(psb->r) - 32, 32);
    p += 32;

    *p++ = MBEDTLS_ASN1_INTEGER;
    *p++ = 32;
    memcpy(p, psb->s + sizeof(psb->s) - 32, 32);
    p += 32;

    retVal->cs = new Buffer(_sign);

    u32 len = sizeof(buf);
    ret = SKF_ExportCertificate(hctn, 1, (u8*)buf, &len);
    if (ret) {
        SKF_CloseContainer(hctn);
        return CHECK_ERROR(skf_error("SKF_ExportCertificate", ret));
    }

    SKF_CloseContainer(hctn);

    obj_ptr<X509Cert> crt = new X509Cert();
    ret = mbedtls_x509_crt_parse_der(&crt->m_crt, (const unsigned char*)buf, len);
    if (ret != 0)
        return CHECK_ERROR(_ssl::setError(ret));

    retVal->cc = crt;

    return 0;
}

result_t TFCard::verify_ss(Buffer_base* ss)
{
    int ret;

    ECCSIGNATUREBLOB sb;
    memset(&sb, 0, sizeof(sb));

    exlib::string _ss;
    ss->toString(_ss);
    const char* p = _ss.c_str();
    int32_t len;

    if (*p++ != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
        return CHECK_ERROR(CALL_E_INVALID_DATA);
    p++;

    if (*p++ != MBEDTLS_ASN1_INTEGER)
        return CHECK_ERROR(CALL_E_INVALID_DATA);
    len = *p++;
    memcpy(sb.r + sizeof(sb.r) - len, p, len);
    p += len;

    if (*p++ != MBEDTLS_ASN1_INTEGER)
        return CHECK_ERROR(CALL_E_INVALID_DATA);
    len = *p++;
    memcpy(sb.s + sizeof(sb.s) - len, p, len);
    p += len;

    u32 retry = 0;
    ret = SKF_VerifyPIN(happ, USER_TYPE, (LPSTR)m_pin.c_str(), &retry);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_VerifyPIN", ret));

    ret = V_Control(happ, V_CTL_VERIFY_SS, (void*)&sb);
    if (ret)
        return CHECK_ERROR(skf_error("V_Control", ret));

    return 0;
}

result_t TFCard::read(int32_t pos, obj_ptr<Buffer_base>& retVal)
{
    exlib::string _data;
    _data.resize(BLOCK_SIZE);

    RW_PARAM rd = {
        (u32)(pos * BLOCK_SIZE / 512),
        (u8*)_data.c_buffer(),
        (u32)_data.length()
    };

    int ret = V_Control(hdev, V_CTL_PRV_READ, &rd);
    if (ret)
        return CHECK_ERROR(skf_error("V_Control", ret));

    retVal = new Buffer(_data);

    return 0;
}

result_t TFCard::write(int32_t pos, Buffer_base* data)
{
    exlib::string _data;
    data->toString(_data);

    RW_PARAM wr = {
        (u32)(pos * BLOCK_SIZE / 512),
        (u8*)_data.c_str(),
        (u32)_data.length()
    };

    int ret = V_Control(hdev, V_CTL_PRV_WRITE, &wr);
    if (ret)
        return CHECK_ERROR(skf_error("V_Control", ret));

    return 0;
}

result_t TFCard::close()
{
    if (happ) {
        SKF_CloseApplication(happ);
        happ = 0;
    }

    if (hdev) {
        SKF_DisconnectDev(hdev);
        hdev = 0;
    }

    return 0;
}

result_t TFCard::get_stat(obj_ptr<NObject>& retVal)
{
    DEVINFO di;
    int ret = SKF_GetDevInfo(hdev, &di);
    if (ret)
        return CHECK_ERROR(skf_error("SKF_GetDevInfo", ret));

    int32_t cap = 0;
    ret = V_Control(hdev, V_CTL_PRV_CAPACITY, &cap);
    if (ret)
        return CHECK_ERROR(skf_error("V_Control", ret));
    
    obj_ptr<NObject> info = new NObject();

    info->add("SerialNumber", di.SerialNumber);
    info->add("TotalSpace", (int32_t)di.TotalSpace);
    info->add("FreeSpace", (int32_t)di.FreeSpace);
    info->add("PrivateSpace", (int32_t)cap);
    
    retVal = info;
    return 0;
}

}