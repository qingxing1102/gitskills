
#include "sdf/sdf.h"
#include "sdf/sdf_dev_manage.h"
#include <exlib/include/dl_func.h>

#ifdef _WIN32
#define SDF_LIB "SDF.dll"
#else
#define SDF_LIB "./libsdf_crypto.so"
#endif

static void* sdf_handle;
#define sdf_func(func) dl_def_func(sdf_handle, SDF_LIB, func)

int SDF_OpenDevice(void** phDeviceHandle)
{
    sdf_func(SDF_OpenDevice);
    return s_SDF_OpenDevice(phDeviceHandle);
}

int SDF_CloseDevice(void* hDeviceHandle)
{
    sdf_func(SDF_CloseDevice);
    return s_SDF_CloseDevice(hDeviceHandle);
}

int SDF_OpenSession(void* hDeviceHandle, void** phSessionHandle)
{
    sdf_func(SDF_OpenSession);
    return s_SDF_OpenSession(hDeviceHandle, phSessionHandle);
}

int SDF_CloseSession(void* hSessionHandle)
{
    sdf_func(SDF_CloseSession);
    return s_SDF_CloseSession(hSessionHandle);
}

int SDF_GetPrivateKeyAccessRight(void* hSessionHandle, unsigned int uiKeyIndex, unsigned char* pucPassword, unsigned int uiPwdLength)
{
    sdf_func(SDF_GetPrivateKeyAccessRight);
    return s_SDF_GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex, pucPassword, uiPwdLength);
}

int SDF_ReleasePrivateKeyAccessRight(void* hSessionHandle, unsigned int uiKeyIndex)
{
    sdf_func(SDF_ReleasePrivateKeyAccessRight);
    return s_SDF_ReleasePrivateKeyAccessRight(hSessionHandle, uiKeyIndex);
}

int EVDF_ImportKeyPair_ECC(void* hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, ECCrefPublicKey* pucPublicKey, ECCrefPrivateKey* pucPrivateKey)
{
    sdf_func(EVDF_ImportKeyPair_ECC);
    return s_EVDF_ImportKeyPair_ECC(hSessionHandle, uiSignFlag, uiKeyIndex, pucPublicKey, pucPrivateKey);
}

int EVDF_DeleteInternalKeyPair_ECC(void* hSessionHandle, unsigned int uiSignFlag, unsigned int uiKeyIndex, char* AdminPIN)
{
    sdf_func(EVDF_DeleteInternalKeyPair_ECC);
    return s_EVDF_DeleteInternalKeyPair_ECC(hSessionHandle, uiSignFlag, uiKeyIndex, AdminPIN);
}

int SDF_InternalSign_ECC(void* hSessionHandle, unsigned int uiISKIndex, unsigned char* pucData,
    unsigned int uiDataLength, ECCSignature* pucSignature)
{
    sdf_func(SDF_InternalSign_ECC);
    return s_SDF_InternalSign_ECC(hSessionHandle, uiISKIndex, pucData, uiDataLength, pucSignature);
}

int SDF_InternalEncrypt_ECC(void* hSessionHandle, unsigned int uiIPKIndex, unsigned char* pucData,
    unsigned int uiDataLength, ECCCipher* pucEncData)
{
    sdf_func(SDF_InternalEncrypt_ECC);
    return s_SDF_InternalEncrypt_ECC(hSessionHandle, uiIPKIndex, pucData, uiDataLength, pucEncData);
}

int SDF_InternalDecrypt_ECC(void* hSessionHandle, unsigned int uiISKIndex, ECCCipher* pucEncData,
    unsigned char* pucData, unsigned int* puiDataLength)
{
    sdf_func(SDF_InternalDecrypt_ECC);
    return s_SDF_InternalDecrypt_ECC(hSessionHandle, uiISKIndex, pucEncData, pucData, puiDataLength);
}

int SDF_CreateFile(void* hSessionHandle, unsigned char* pucFileName, unsigned int uiNameLen, unsigned int uiFileSize)
{
    sdf_func(SDF_CreateFile);
    return s_SDF_CreateFile(hSessionHandle, pucFileName, uiNameLen, uiFileSize);
}

int SDF_ReadFile(void* hSessionHandle, unsigned char* pucFileName, unsigned int uiNameLen,
    unsigned int uiOffset, unsigned int* puiFileLength, unsigned char* pucBuffer)
{
    sdf_func(SDF_ReadFile);
    return s_SDF_ReadFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, puiFileLength, pucBuffer);
}

int SDF_WriteFile(void* hSessionHandle, unsigned char* pucFileName, unsigned int uiNameLen,
    unsigned int uiOffset, unsigned int uiFileLength, unsigned char* pucBuffer)
{
    sdf_func(SDF_WriteFile);
    return s_SDF_WriteFile(hSessionHandle, pucFileName, uiNameLen, uiOffset, uiFileLength, pucBuffer);
}

int SDF_DeleteFile(void* hSessionHandle, unsigned char* pucFileName, unsigned int uiNameLen)
{
    sdf_func(SDF_DeleteFile);
    return s_SDF_DeleteFile(hSessionHandle, pucFileName, uiNameLen);
}

int EVDF_GetFirmwareVersion(void* hSessionHandle, unsigned char* pstFirmInfo)
{
    sdf_func(EVDF_GetFirmwareVersion);
    return s_EVDF_GetFirmwareVersion(hSessionHandle, pstFirmInfo);
}

int EVDF_InitKeyFileSystem(void* hSessionHandle, char* AdminPin, unsigned char* pucRootKey, unsigned int uiKeyBits, char* NewAdminPin, char* NewUserPIN)
{
    sdf_func(EVDF_InitKeyFileSystem);
    return s_EVDF_InitKeyFileSystem(hSessionHandle, AdminPin, pucRootKey, uiKeyBits, NewAdminPin, NewUserPIN);
}
