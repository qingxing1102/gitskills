#include <sdf/sdf.h>
#include <sdf/sdf_dev_manage.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "common.h"
#include "log.h"
#include "tf.h"
#include "pcie.h"

int pcie_gen_random(unsigned char *sr, int sr_len)
{
    int ret = 0;
    void *hdev = NULL;
    void *hsess = NULL;

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = SDF_GenerateRandom(hsess, sr_len, sr));

end:
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

int pcie_verify_cc(unsigned char *cc, int cc_len)
{
    int ret = 0;
    void *hdev = NULL;
    void *hsess = NULL;
    CHECK_CERT_PARAM param;

    memset(&param, 0, sizeof(param));
    // param.szCAFile = "./certs/sm2_ca.der";
    param.szCAFile = PCIE_CA_FILE_NAME;
    param.pbSC = cc;
    param.cbSC = cc_len;
    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = PCI_V_Control(hsess, V_CTL_CHECK_CERT, &param));

end:
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

int pcie_verify_cs(unsigned char *cc, int cc_len, unsigned char *sr, int sr_len, unsigned char *cr, int cr_len, unsigned char *sig, int sig_len)
{
    int ret = 0;
    void *hdev = NULL;
    void *hsess = NULL;
    u8 hash[128];
    u32 hash_len = sizeof(hash);
    unsigned char pubkey[128];
    int pubkey_len = sizeof(pubkey);
    ECCrefPublicKey ecc_pubkey;

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = SDF_GetPrivateKeyAccessRight(hsess, PCIE_KEY_INDEX, (void *)PCIE_PASSWD, strlen(PCIE_PASSWD)));
    CHECK_FUNC(ret = SDF_HashInit(hsess, SGD_SM3, NULL, NULL, 0));
    CHECK_FUNC(ret = SDF_HashUpdate(hsess, sr, sr_len));
    CHECK_FUNC(ret = SDF_HashUpdate(hsess, cr, cr_len));
    CHECK_FUNC(ret = SDF_HashFinal(hsess, hash, &hash_len));
    // log_data("hash", hash, hash_len);
    // log_data("sig", sig, sig_len);

    memset(&ecc_pubkey, 0, sizeof(ecc_pubkey));
    CHECK_FUNC(ret = PCI_V_Control(hsess, V_CTL_GET_CERT_PUBKEY, cc, cc_len, pubkey, &pubkey_len));
    ecc_pubkey.bits = 256;
    memcpy(ecc_pubkey.x + 32, pubkey, 32);
    memcpy(ecc_pubkey.y + 32, pubkey + 32, 32);
    // log_data("c.x", ecc_pubkey.x + 32, 32);
    // log_data("c.y", ecc_pubkey.y + 32, 32);
    CHECK_FUNC(ret = SDF_ExternalVerify_ECC(hsess, SGD_SM2_1, &ecc_pubkey, hash, hash_len, (void *)sig));

end:
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

int pcie_decrypt_cr(unsigned char *cr, int cr_len, unsigned char **dec_cr, int *dec_cr_len)
{
    int ret = 0;
    void *hdev = NULL;
    void *hsess = NULL;
    u32 dec_len = cr_len;
    u8 *dec = NULL;
    ECCCipher *cipher = (void *)cr;

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = SDF_GetPrivateKeyAccessRight(hsess, PCIE_KEY_INDEX, (void *)PCIE_PASSWD, strlen(PCIE_PASSWD)));
    dec = malloc(cr_len);
    if (!dec) {
        ret = errno;
        LOG("malloc() failed: %s\n", strerror(errno));
        goto end;
    }
    // log_data("cr", cr, cr_len);
    // log_data("x", cipher->x + 32, 32);
    // log_data("y", cipher->y + 32, 32);
    // log_data("m", cipher->M, 32);
    // log_data("L", cipher->C, cipher->L);
    // LOG("cr = %p, cr_len = %d, dec = %p, dec_len = %d\n", cr, cr_len, dec, dec_len);

    CHECK_FUNC(ret = SDF_InternalDecrypt_ECC(hsess, PCIE_KEY_INDEX, cipher, dec, &dec_len));
    *dec_cr = dec;
    *dec_cr_len = dec_len;

end:
    if (ret && dec) free(dec);
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

int pcie_sign_ss(unsigned char *cr, int cr_len, unsigned char **sig, int *sig_len)
{
    int ret = 0;
    void *hdev = NULL;
    void *hsess = NULL;
    u8 hash[128];
    u32 hash_len = sizeof(hash);
    ECCrefPublicKey ecc_pubkey;
    ECCSignature ecc_sig;

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = SDF_GetPrivateKeyAccessRight(hsess, PCIE_KEY_INDEX, (void *)PCIE_PASSWD, strlen(PCIE_PASSWD)));
    CHECK_FUNC(ret = SDF_ExportSignPublicKey_ECC(hsess, PCIE_KEY_INDEX, &ecc_pubkey));
    CHECK_FUNC(ret = SDF_HashInit(hsess, SGD_SM3, &ecc_pubkey, (void *)"1234567812345678", 16));
    CHECK_FUNC(ret = SDF_HashUpdate(hsess, cr, cr_len));
    CHECK_FUNC(ret = SDF_HashFinal(hsess, hash, &hash_len));

    CHECK_FUNC(ret = SDF_InternalSign_ECC(hsess, PCIE_KEY_INDEX, hash, hash_len, &ecc_sig));
    CHECK_FUNC(ret = SDF_InternalVerify_ECC(hsess, PCIE_KEY_INDEX, hash, hash_len, &ecc_sig));
    *sig = malloc(sizeof(ecc_sig));
    if (*sig == NULL) {
        ret = errno;
        LOG("malloc() failed: %s\n", strerror(errno));
        goto end;
    }
    memcpy(*sig, &ecc_sig, sizeof(ecc_sig));
    *sig_len = sizeof(ecc_sig);
    // log_data("sig", *sig, *sig_len);

end:
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

int pcie_encypt_data(unsigned char *cr, unsigned char *data, int data_len, unsigned char **enc_data, int *enc_data_len)
{
    int ret = 0;
    void *hdev = NULL;
    void *hsess = NULL;
    void *hkey = NULL;
    unsigned char *tmp = NULL, *buf;
    int max_len = 1024 * 1024, l;
    unsigned char left[16];
    u32 enc_len = 0, out_len = 0;
    int left_len = 0;
    char c;

    buf = tmp = malloc((data_len + 511) / 512 * 512 + 512);
    if (!tmp) {
        ret = errno;
        LOG("malloc() failed: %s\n", strerror(errno));
        return ret;
    }

    /**
     * 统一对原文数据进行padding处理
     *
     * 注意：padding采用PKCS5方式
     */
    if (data_len % 16) {
        left_len = data_len % 16;
        c = (char)(16 - left_len);
        memset(left, 0, sizeof(left));
        memcpy(left, data + data_len - left_len, left_len);
        for (l = left_len; l < 16; l++) {
            left[l] = c;
        }
        data_len -= left_len;
    } else {
        c = 16;
        memset(left, c, 16);
    }

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = SDF_ImportKey(hsess, cr, 16, &hkey));
    while (data_len > 0) {
        l = data_len > max_len ? max_len : data_len;
        enc_len = l;
        // LOG("data_len = %d, l = %d, data = %p, tmp = %p\n", data_len, l, data, tmp);
        CHECK_FUNC(ret = SDF_Encrypt(hsess, hkey, SGD_SMS4_ECB, NULL, data, l, tmp, &enc_len));

        data_len -= l;
        out_len += enc_len;

        tmp += l;
        data += l;
    }

    enc_len = 16;
    // log_data("left", left, 16);
    CHECK_FUNC(ret = SDF_Encrypt(hsess, hkey, SGD_SMS4_ECB, NULL, left, 16, tmp, &enc_len));
    out_len += enc_len;
    *enc_data = buf;
    *enc_data_len = out_len;

end:
    if (ret && buf) free(buf);
    if (hkey) SDF_DestroyKey(hsess, hkey);
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

int pcie_decypt_data(unsigned char *cr, unsigned char *enc_data, int enc_data_len, unsigned char **data, int *data_len)
{
    int ret = 0, i;
    void *hdev = NULL;
    void *hsess = NULL;
    void *hkey = NULL;
    unsigned char *tmp = NULL, *buf = NULL;
    int max_len = 1024 * 1024, l = 0;
    u32 enc_len = 0, out_len = 0;
    unsigned char padding = 0;

    buf = tmp = malloc(enc_data_len);
    if (!tmp) {
        ret = errno;
        LOG("malloc() failed: %s\n", strerror(errno));
        return ret;
    }

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = SDF_ImportKey(hsess, cr, 16, &hkey));
    while (enc_data_len > 0) {
        l = enc_data_len > max_len ? max_len : enc_data_len;
        enc_len = l;

        // LOG("enc_data = %p, l = %d, tmp = %p, enc_len = %d\n", enc_data, l, tmp, enc_len);
        CHECK_FUNC(ret = SDF_Decrypt(hsess, hkey, SGD_SMS4_ECB, NULL, enc_data, l, tmp, &enc_len));

        enc_data_len -= l;
        out_len += enc_len;

        tmp += l;
        enc_data += l;
    }

    /**
     * 因为pcie_encypt_data加密时，统一对原文数据进行了padding处理,
     * 因此，解密时需要统一进行去padding处理。
     *
     * 注意：padding和去padding均采用PKCS5方式
     */
    padding = buf[out_len - 1];
    if (padding == 0 || padding > 16) {
        ret = -1;
        goto end;
    }
    l = out_len - 1 - padding;
    for (i = out_len - 1; i > l; i--) {
        if (buf[i] != padding) {
            ret = -1;
            goto end;
        }
    }

    *data = buf;
    *data_len = out_len - padding;

end:
    if (ret && buf) free(buf);
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

static int pcie_read_file(char *name, unsigned char **data, int *data_len)
{
    int ret = 0;
    u32 len = 0;
    void *hdev = NULL;
    void *hsess = NULL;
    u8 *buf = NULL;

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = SDF_ReadFile(hsess, (void *)name, strlen(name), 0, &len, buf));
    buf = malloc(len);
    if (!buf) {
        LOG("malloc() failed: %s\n", strerror(errno));
        ret = SDR_NOBUFFER;
        goto end;
    }
    CHECK_FUNC(ret = SDF_ReadFile(hsess, (void *)name, strlen(name), 0, &len, buf));
    *data = buf;
    *data_len = len;

end:
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

int pcie_load_ca(unsigned char **ca, int *ca_len)
{
    int ret = 0;

    ret = pcie_read_file(PCIE_CA_FILE_NAME, ca, ca_len);
    return ret;
}

int pcie_load_cert(unsigned char **cert, int *cert_len)
{
    int ret = 0;

    ret = pcie_read_file(PCIE_CERT_FILE_NAME, cert, cert_len);
    return ret;
}
static int pcie_import_file(char *name, unsigned char *data, int len)
{
    int ret = 0;
    void *hdev = NULL;
    void *hsess = NULL;
    u32 file_size = 0;

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));

    SDF_DeleteFile(hsess, (void *)name, strlen(name));
    CHECK_FUNC(ret = SDF_CreateFile(hsess, (void *)name, strlen(name), len));
    CHECK_FUNC(ret = SDF_WriteFile(hsess, (void *)name, strlen(name), 0, len, data));
    CHECK_FUNC(ret = SDF_ReadFile(hsess, (void *)name, strlen(name), 0, &file_size, NULL));
    if (len != file_size) {
        LOG("file size invalid\n");
        ret = -1;
        goto end;
    }

end:
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

int pcie_import_ca()
{
    int ret = 0;
    unsigned char *ca = NULL;
    int ca_len = 0;
    char *file = PCIE_CA_FILE_NAME;

    CHECK_FUNC(ret = load_file("./certs/sm2_ca.der", &ca, &ca_len));
    CHECK_FUNC(ret = pcie_import_file(file, ca, ca_len));

end:
    if (ca) free(ca);
    return ret;
}

int pcie_import_cert()
{
    int ret = 0;
    unsigned char *cert = NULL;
    int cert_len = 0;
    char *file = PCIE_CERT_FILE_NAME;

    CHECK_FUNC(ret = load_file("./certs/sm2_cert_pcie.der", &cert, &cert_len));
    CHECK_FUNC(ret = pcie_import_file(file, cert, cert_len));

end:
    if (cert) free(cert);
    return ret;
}

int pcie_init()
{
    int ret = 0;
    void *hdev = NULL;
    void *hsess = NULL;
    unsigned char *pubkey = NULL;
    int pubkey_len = 0;
    unsigned char *prikey = NULL;
    int prikey_len = 0;
    ECCrefPublicKey ecc_pubkey;
    ECCrefPrivateKey ecc_prikey;

    CHECK_FUNC(ret = SDF_OpenDevice(&hdev));
    CHECK_FUNC(ret = SDF_OpenSession(hdev, &hsess));
    CHECK_FUNC(ret = SDF_GetPrivateKeyAccessRight(hsess, PCIE_KEY_INDEX, (void *)PCIE_PASSWD, strlen(PCIE_PASSWD)));
    CHECK_FUNC(ret = load_file("./certs/sm2_cert_pubkey_pcie.bin", &pubkey, &pubkey_len));
    CHECK_FUNC(ret = load_file("./certs/sm2_cert_prikey_pcie.bin", &prikey, &prikey_len));

    memset(&ecc_pubkey, 0, sizeof(ecc_pubkey));
    memset(&ecc_prikey, 0, sizeof(ecc_prikey));
    ecc_pubkey.bits = 256;
    memcpy(ecc_pubkey.x + 32, pubkey, 32);
    memcpy(ecc_pubkey.y + 32, pubkey + 32, 32);
    ecc_prikey.bits = 256;
    memcpy(ecc_prikey.K + 32, prikey, 32);

    EVDF_DeleteInternalKeyPair_ECC(hsess, 0, PCIE_KEY_INDEX, PCIE_PASSWD);
    EVDF_DeleteInternalKeyPair_ECC(hsess, 1, PCIE_KEY_INDEX, PCIE_PASSWD);
    CHECK_FUNC(ret = EVDF_ImportKeyPair_ECC(hsess, 0, PCIE_KEY_INDEX, &ecc_pubkey, &ecc_prikey));
    CHECK_FUNC(ret = EVDF_ImportKeyPair_ECC(hsess, 1, PCIE_KEY_INDEX, &ecc_pubkey, &ecc_prikey));

    CHECK_FUNC(ret = pcie_import_ca());
    CHECK_FUNC(ret = pcie_import_cert());

end:
    if (pubkey) free(pubkey);
    if (prikey) free(prikey);
    if (hsess) SDF_CloseSession(hsess);
    if (hdev) SDF_CloseDevice(hdev);
    return ret;
}

