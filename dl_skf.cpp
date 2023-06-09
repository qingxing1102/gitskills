
#include "skf/skf.h"
#include <exlib/include/dl_func.h>

#ifdef _WIN32
#define SKF_LIB "SKF.dll"
#else
#define SKF_LIB "./libskf_tf_x86_64.so"
#endif

static void* skf_handle;
#define skf_func(func) dl_def_func(skf_handle, SKF_LIB, func)

u32 DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, u32* pulSize)
{
    skf_func(SKF_EnumDev);
    return s_SKF_EnumDev(bPresent, szNameList, pulSize);
}

u32 DEVAPI SKF_ConnectDev(LPSTR szName, DEVHANDLE* phDev)
{
    skf_func(SKF_ConnectDev);
    return s_SKF_ConnectDev(szName, phDev);
}

u32 DEVAPI SKF_GetDevInfo(DEVHANDLE hDev, PDEVINFO pInfo)
{
    skf_func(SKF_GetDevInfo);
    return s_SKF_GetDevInfo(hDev, pInfo);
}

u32 DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION* phApplication)
{
    skf_func(SKF_OpenApplication);
    return s_SKF_OpenApplication(hDev, szAppName, phApplication);
}

u32 DEVAPI SKF_DisconnectDev(DEVHANDLE hDev)
{
    skf_func(SKF_DisconnectDev);
    return s_SKF_DisconnectDev(hDev);
}

u32 DEVAPI SKF_CloseApplication(HAPPLICATION hApplication)
{
    skf_func(SKF_CloseApplication);
    return s_SKF_CloseApplication(hApplication);
}

u32 DEVAPI SKF_OpenContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER* phContainer)
{
    skf_func(SKF_OpenContainer);
    return s_SKF_OpenContainer(hApplication, szContainerName, phContainer);
}

u32 DEVAPI SKF_CreateContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER* phContainer)
{
    skf_func(SKF_CreateContainer);
    return s_SKF_CreateContainer(hApplication, szContainerName, phContainer);
}

u32 DEVAPI SKF_CloseContainer(HCONTAINER hContainer)
{
    skf_func(SKF_CloseContainer);
    return s_SKF_CloseContainer(hContainer);
}

u32 DEVAPI SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag, u8* pbCert, u32* pulCertLen)
{
    skf_func(SKF_ExportCertificate);
    return s_SKF_ExportCertificate(hContainer, bSignFlag, pbCert, pulCertLen);
}

u32 DEVAPI SKF_VerifyPIN(HAPPLICATION hApplication, u32 ulPinType, LPSTR szPin, u32* pulRetry)
{
    skf_func(SKF_VerifyPIN);
    return s_SKF_VerifyPIN(hApplication, ulPinType, szPin, pulRetry);
}

u32 DEVAPI V_ImportKeyPair(HCONTAINER hContainer, u32 ulFlags, u8* pbKeyData, u32 ulKeyData)
{
    skf_func(V_ImportKeyPair);
    return s_V_ImportKeyPair(hContainer, ulFlags, pbKeyData, ulKeyData);
}

u32 DEVAPI SKF_ImportCertificate(HCONTAINER hContainer, BOOL bSignFlag, u8* pbCert, u32 ulCertLen)
{
    skf_func(SKF_ImportCertificate);
    return s_SKF_ImportCertificate(hContainer, bSignFlag, pbCert, ulCertLen);
}

u32 DEVAPI SKF_CreateFile(HAPPLICATION hApplication, LPSTR szFileName, u32 ulFileSize, u32 ulReadRights, u32 ulWriteRights)
{
    skf_func(SKF_CreateFile);
    return s_SKF_CreateFile(hApplication, szFileName, ulFileSize, ulReadRights, ulWriteRights);
}

u32 DEVAPI SKF_DeleteFile(HAPPLICATION hApplication, LPSTR szFileName)
{
    skf_func(SKF_DeleteFile);
    return s_SKF_DeleteFile(hApplication, szFileName);
}

u32 DEVAPI SKF_EnumFiles(HAPPLICATION hApplication, LPSTR szFileList, u32* pulSize)
{
    skf_func(SKF_EnumFiles);
    return s_SKF_EnumFiles(hApplication, szFileList, pulSize);
}

u32 DEVAPI SKF_GetFileInfo(HAPPLICATION hApplication, LPSTR szFileName, PFILEATTRIBUTE pFileInfo)
{
    skf_func(SKF_GetFileInfo);
    return s_SKF_GetFileInfo(hApplication, szFileName, pFileInfo);
}

u32 DEVAPI SKF_ReadFile(HAPPLICATION hApplication, LPSTR szFileName, u32 ulOffset, u32 ulSize, u8* pbOutData, u32* pulOutLen)
{
    skf_func(SKF_ReadFile);
    return s_SKF_ReadFile(hApplication, szFileName, ulOffset, ulSize, pbOutData, pulOutLen);
}

u32 DEVAPI SKF_WriteFile(HAPPLICATION hApplication, LPSTR szFileName, u32 ulOffset, u8* pbData, u32 ulSize)
{
    skf_func(SKF_WriteFile);
    return s_SKF_WriteFile(hApplication, szFileName, ulOffset, pbData, ulSize);
}

u32 DEVAPI SKF_ECCSignData(HCONTAINER hContainer, u8* pbData, u32 ulDataLen, PECCSIGNATUREBLOB pSignature)
{
    skf_func(SKF_ECCSignData);
    return s_SKF_ECCSignData(hContainer, pbData, ulDataLen, pSignature);
}

u32 DEVAPI SKF_ExtECCEncrypt(DEVHANDLE hDev, PECCPUBLICKEYBLOB pECCPubKeyBlob,
    u8* pbPlainText, u32 ulPlainTextLen, PECCCIPHERBLOB pCipherText)
{
    skf_func(SKF_ExtECCEncrypt);
    return s_SKF_ExtECCEncrypt(hDev, pECCPubKeyBlob, pbPlainText, ulPlainTextLen, pCipherText);
}

u32 DEVAPI SKF_DigestInit(DEVHANDLE hDev, u32 ulAlgID, PECCPUBLICKEYBLOB pPubKey,
    u8* pucID, u32 ulIDLen, HANDLE* phHash)
{
    skf_func(SKF_DigestInit);
    return s_SKF_DigestInit(hDev, ulAlgID, pPubKey, pucID, ulIDLen, phHash);
}

u32 DEVAPI SKF_DigestUpdate(HANDLE hHash, u8* pbData, u32 ulDataLen)
{
    skf_func(SKF_DigestUpdate);
    return s_SKF_DigestUpdate(hHash, pbData, ulDataLen);
}

u32 DEVAPI SKF_DigestFinal(HANDLE hHash, u8* pbDigest, u32* pulDigestLen)
{
    skf_func(SKF_DigestFinal);
    return s_SKF_DigestFinal(hHash, pbDigest, pulDigestLen);
}

u32 DEVAPI V_Control(HANDLE hHandle, u32 request, ...)
{
    puts("never call V_Control");
    exit(-1);
    return -1;
}

u32 DEVAPI _V_Control(HANDLE hHandle, u32 request, void* p)
{
    static auto s_V_Control = exlib::dl_func(skf_handle, SKF_LIB, "V_Control", V_Control);
    return s_V_Control(hHandle, request, p);
}
