#include <skf/skf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "common.h"
#include "log.h"
#include "tf.h"

/* 应用名称 */
#define APP_NAME "DEFAULT"

/* 容器名称 */
#define CTN_NAME "DEFAULT"

int tf_gen_cr(unsigned char *sc, int sc_len, unsigned char **cr, int *cr_len)
{
    int ret = 0;
    char *pin = APP_PIN;
    char *app = APP_NAME;
    DEVHANDLE hdev = 0;
    HAPPLICATION happ = 0;
    GEN_CR_PARAM param;
    void *buf = NULL;
    char names[1024] = {0};
    u32 names_len = sizeof(names);
    u32 retry = 0;
    
    buf = malloc(128 + sizeof(ECCCIPHERBLOB));
    if (!buf) {
        ret = errno;
        LOG("malloc() failed: %s\n", strerror(errno));
        goto end;
    }

    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));
    CHECK_FUNC(ret = SKF_OpenApplication(hdev, app, &happ));
    CHECK_FUNC(ret = SKF_VerifyPIN(happ, USER_TYPE, pin, &retry));

    memset(&param, 0, sizeof(param));
    // param.szCAFile = "./certs/sm2_ca.der";
    param.szCAFile = TF_CA_FILE_NAME;
    param.pbSC = sc;
    param.cbSC = sc_len;
    param.pbCipherCr = buf;
    CHECK_FUNC(ret = V_Control(happ, V_CTL_GEN_CR, &param));
    *cr_len = sizeof(ECCCIPHERBLOB) - 1 + param.pbCipherCr->CipherLen;
    *cr = buf;

end:
    if (ret && buf) free(buf);
    if (happ) SKF_CloseApplication(happ);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}


int tf_sign_sr_cr(unsigned char *sr, int sr_len, unsigned char *cr, int cr_len, unsigned char **sig, int *sig_len)
{
    int ret = 0;
    char *pin = APP_PIN;
    char *app = APP_NAME;
    char *ctn = CTN_NAME;
    HANDLE hhash = 0;
    DEVHANDLE hdev = 0;
    HAPPLICATION happ = 0;
    HCONTAINER hctn = 0;
    void *buf = NULL;
    char names[1024] = {0};
    u8 hash[128] = {0};
    u32 hash_len = sizeof(hash);
    u32 names_len = sizeof(names);
    u32 retry = 0;
    
    buf = malloc(sizeof(ECCSIGNATUREBLOB));
    if (!buf) {
        ret = errno;
        LOG("malloc() failed: %s\n", strerror(errno));
        goto end;
    }

    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));
    CHECK_FUNC(ret = SKF_OpenApplication(hdev, app, &happ));
    CHECK_FUNC(ret = SKF_VerifyPIN(happ, USER_TYPE, pin, &retry));
    CHECK_FUNC(ret = SKF_OpenContainer(happ, ctn, &hctn));

    CHECK_FUNC(ret = SKF_DigestInit(hdev, SGD_SM3, NULL, NULL, 0, &hhash));
    CHECK_FUNC(ret = SKF_DigestUpdate(hhash, sr, sr_len));
    CHECK_FUNC(ret = SKF_DigestUpdate(hhash, cr, cr_len));
    CHECK_FUNC(ret = SKF_DigestFinal(hhash, hash, &hash_len));
    // log_data("hash", hash, hash_len);

    CHECK_FUNC(ret = SKF_ECCSignData(hctn, hash, hash_len, buf));
    *sig = buf;
    *sig_len = sizeof(ECCSIGNATUREBLOB);
    // log_data("sig", *sig, *sig_len);
    
end:
    if (ret && buf) free(buf);
    if (hhash) SKF_CloseHandle(hhash);
    if (hctn) SKF_CloseContainer(hctn);
    if (happ) SKF_CloseApplication(happ);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}

int tf_verify_ss(unsigned char *ss, int ss_len)
{
    int ret = 0;
    char *pin = APP_PIN;
    char *app = APP_NAME;
    HANDLE hhash = 0;
    DEVHANDLE hdev = 0;
    HAPPLICATION happ = 0;
    char names[1024] = {0};
    u32 names_len = sizeof(names);
    u32 retry = 0;

    if (ss_len != sizeof(ECCSIGNATUREBLOB)) return SAR_INDATALENERR;
    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));
    CHECK_FUNC(ret = SKF_OpenApplication(hdev, app, &happ));
    CHECK_FUNC(ret = SKF_VerifyPIN(happ, USER_TYPE, pin, &retry));
    CHECK_FUNC(ret = V_Control(happ, V_CTL_VERIFY_SS, (void *)ss));

end:
    if (hhash) SKF_CloseHandle(hhash);
    if (happ) SKF_CloseApplication(happ);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}

int tf_priv_write(int lba, unsigned char *data, int data_len)
{
    int ret = 0;
    DEVHANDLE hdev = 0;
    char names[1024] = {0};
    u32 names_len = sizeof(names);
    u32 per_len = 1024 * 1024, l;
    RW_PARAM wr = {0};

    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));

    while (data_len > 0) {
        l = data_len > per_len ? per_len : data_len;
        wr.uLba = lba;
        wr.pbData = data;
        wr.uLen = l;

        // LOG("lba = %d, data = %p, l = %d\n", lba, data, l);
        CHECK_FUNC(ret = V_Control(hdev, V_CTL_PRV_WRITE, &wr));
        data_len -= l;
        data += l;
        lba += (l / 512);
    }

end:
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}

int tf_priv_read(int lba, unsigned char **data, int data_len)
{
    int ret = 0;
    DEVHANDLE hdev = 0;
    char names[1024] = {0};
    unsigned char *tmp = NULL, *buf = NULL;
    u32 names_len = sizeof(names);
    u32 per_len = 1024 * 1024, l = 0;
    RW_PARAM rd = {0};

    buf = tmp = malloc(data_len + 512);
    if (!tmp) {
        ret = errno;
        LOG("malloc = %s\n", strerror(errno));
        return ret;
    }

    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));

    while (data_len > 0) {
        l = data_len > per_len ? per_len : data_len;
        rd.uLba = lba;
        rd.pbData = tmp;
        rd.uLen = l;

        // LOG("lba = %d, tmp = %p, l = %d\n", lba, tmp, l);
        CHECK_FUNC(ret = V_Control(hdev, V_CTL_PRV_READ, &rd));
        data_len -= l;
        lba += (l / 512);
        tmp += l;
    }
    *data = buf;

end:
    if (ret && buf) free(buf);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}

int tf_import_ca()
{
    int ret = 0;
    char *app = APP_NAME;
    char *file = TF_CA_FILE_NAME;
    DEVHANDLE hdev = 0;
    HAPPLICATION happ = 0;
    char names[1024] = {0};
    unsigned char *ca = NULL;
    int ca_len = 0;
    u32 names_len = sizeof(names);
    FILEATTRIBUTE attr;
    
    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));
    CHECK_FUNC(ret = SKF_OpenApplication(hdev, app, &happ));
    CHECK_FUNC(ret = load_file("./certs/sm2_ca.der", &ca, &ca_len));
    memset(&attr, 0, sizeof(attr));
    ret = SKF_GetFileInfo(happ, file, &attr);
    if (ret) {
        if (ret == SAR_FILE_NOT_EXIST) {
            CHECK_FUNC(ret = SKF_CreateFile(happ, file, ca_len, SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT));
        } else {
            LOG("SKF_GetFileInfo() failed: %#x\n", ret);
            goto end;
        }
    } else {
        if (attr.FileSize != ca_len) {
            CHECK_FUNC(ret = SKF_DeleteFile(happ, file));
            CHECK_FUNC(ret = SKF_CreateFile(happ, file, ca_len, SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT));
        }
    }
    CHECK_FUNC(ret = SKF_WriteFile(happ, file, 0, ca, ca_len));

end:
    if (ca) free(ca);
    if (happ) SKF_CloseApplication(happ);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}

int tf_import_cert()
{
    int ret = 0;
    char *app = APP_NAME;
    char *ctn = CTN_NAME;
    DEVHANDLE hdev = 0;
    HAPPLICATION happ = 0;
    HCONTAINER hctn = 0;
    char names[1024] = {0};
    unsigned char *cert = NULL;
    int cert_len = 0;
    u32 names_len = sizeof(names);
    
    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));
    CHECK_FUNC(ret = SKF_OpenApplication(hdev, app, &happ));
    ret = SKF_OpenContainer(happ, ctn, &hctn);
    if (ret) {
        if (ret == SAR_FILE_NOT_EXIST) {
            CHECK_FUNC(ret = SKF_CreateContainer(happ, ctn, &hctn));
        } else {
            LOG("SKF_OpenContainer() failed: %#x\n", ret);
            goto end;
        }
    }
    CHECK_FUNC(ret = load_file("./certs/sm2_cert_tf.der", &cert, &cert_len));
    CHECK_FUNC(ret = SKF_ImportCertificate(hctn, 1, cert, cert_len));

end:
    if (cert) free(cert);
    if (hctn) SKF_CloseContainer(hctn);
    if (happ) SKF_CloseApplication(happ);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}

int tf_init()
{
    int ret = 0;
    char *pin = APP_PIN;
    char *app = APP_NAME;
    char *ctn = CTN_NAME;
    DEVHANDLE hdev = 0;
    HAPPLICATION happ = 0;
    HCONTAINER hctn = 0;
    char names[1024] = {0};
    unsigned char *pubkey = NULL;
    int pubkey_len = 0;
    unsigned char *prikey = NULL;
    int prikey_len = 0;
    unsigned char keypair[96];
    u32 names_len = sizeof(names);
    u32 retry = 0;
    
    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));
    CHECK_FUNC(ret = SKF_OpenApplication(hdev, app, &happ));
    CHECK_FUNC(ret = SKF_VerifyPIN(happ, USER_TYPE, pin, &retry));
    ret = SKF_OpenContainer(happ, ctn, &hctn);
    if (ret) {
        if (ret == SAR_FILE_NOT_EXIST) {
            CHECK_FUNC(ret = SKF_CreateContainer(happ, ctn, &hctn));
        } else {
            LOG("SKF_OpenContainer() failed: %#x\n", ret);
            goto end;
        }
    }
    CHECK_FUNC(ret = load_file("./certs/sm2_cert_pubkey_tf.bin", &pubkey, &pubkey_len));
    CHECK_FUNC(ret = load_file("./certs/sm2_cert_prikey_tf.bin", &prikey, &prikey_len));
    memcpy(keypair, pubkey, 64);
    memcpy(keypair + 64, prikey, 32);
    CHECK_FUNC(ret = V_ImportKeyPair(hctn, V_F_KEY_ALGO_SM2 | V_F_KEY_BITS_256 | V_F_KEY_USAGE_SIGN, keypair, 96));
    
    CHECK_FUNC(ret = tf_import_cert());
    CHECK_FUNC(ret = tf_import_ca());

end:
    if (pubkey) free(pubkey);
    if (prikey) free(prikey);
    if (hctn) SKF_CloseContainer(hctn);
    if (happ) SKF_CloseApplication(happ);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}

int tf_load_cert(unsigned char **cert, int *cert_len)
{
    int ret = 0;
    char *app = APP_NAME;
    char *ctn = CTN_NAME;
    DEVHANDLE hdev = 0;
    HAPPLICATION happ = 0;
    HCONTAINER hctn = 0;
    char names[1024] = {0};
    u8 *buf = NULL;
    u32 names_len = sizeof(names);
    u32 len = 0;
    
    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));
    CHECK_FUNC(ret = SKF_OpenApplication(hdev, app, &happ));
    CHECK_FUNC(ret = SKF_OpenContainer(happ, ctn, &hctn));
    CHECK_FUNC(ret = SKF_ExportCertificate(hctn, 1, buf, &len));
    buf = malloc(len);
    if (!buf) {
        LOG("malloc() failed: %s\n", strerror(errno));
        ret = SAR_NO_ROOM;
        goto end;
    }
    CHECK_FUNC(ret = SKF_ExportCertificate(hctn, 1, buf, &len));
    *cert = buf;
    *cert_len = len;

end:
    if (ret && buf) free(buf);
    if (hctn) SKF_CloseContainer(hctn);
    if (happ) SKF_CloseApplication(happ);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}

int tf_load_ca(unsigned char **ca, int *ca_len)
{
    int ret = 0;
    char *app = APP_NAME;
    char *file = TF_CA_FILE_NAME;
    DEVHANDLE hdev = 0;
    HAPPLICATION happ = 0;
    FILEATTRIBUTE attr;
    char names[1024] = {0};
    u8 *buf = NULL;
    u32 names_len = sizeof(names);
    u32 len = 0;
    
    CHECK_FUNC(ret = SKF_EnumDev(1, names, &names_len));
    CHECK_FUNC(ret = SKF_ConnectDev(names, &hdev));
    CHECK_FUNC(ret = SKF_OpenApplication(hdev, app, &happ));

    memset(&attr, 0, sizeof(attr));
    CHECK_FUNC(ret = SKF_GetFileInfo(happ, file, &attr));
    buf = malloc(attr.FileSize);
    if (!buf) {
        LOG("malloc() failed: %s\n", strerror(errno));
        ret = SAR_NO_ROOM;
        goto end;
    }
    len = attr.FileSize;
    CHECK_FUNC(ret = SKF_ReadFile(happ, file, 0, attr.FileSize, buf, &len));
    *ca = buf;
    *ca_len = len;

end:
    if (ret && buf) free(buf);
    if (happ) SKF_CloseApplication(happ);
    if (hdev) SKF_DisConnectDev(hdev);
    return ret;
}
