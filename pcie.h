#ifndef __PCIE_H__
#define __PCIE_H__

/* PCIE加密卡卡默认密码为8个1（11111111） */
#define PCIE_PASSWD "11111111"

/* PCIE加密卡CA证书文件名称 */
#define PCIE_CA_FILE_NAME "pcie_ca.der"

/* PCIE加密卡证书文件名称 */
#define PCIE_CERT_FILE_NAME "pcie_cert.der"

/* PCIE密钥存放索引号 */
#define PCIE_KEY_INDEX 1

/**
 * @brief 生成随机数
 *
 * @param sr      [out] 产生的随机缓冲区
 * @param sr_len  [in]  要产生的随机数长度(需位16字节的倍数)
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_gen_random(unsigned char *sr, int sr_len);

/**
 * @brief 获取PCIE加密卡证书
 *
 * @param cert      [out] 证书
 * @param cert_len  [out] 证书长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_load_cert(unsigned char **cert, int *cert_len);

/**
 * @brief 验证TF卡证书有效性
 *
 * @param cc      [in] TF卡证书
 * @param cc_len  [in] TF卡证书长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_verify_cc(unsigned char *cc, int cc_len);

/**
 * @brief 验证TF签名值
 *
 * @param cc       [in] TF卡证书
 * @param cc_len   [in] TF卡证书长度
 * @param sr       [in] PCIE加密卡pcie_gen_random接口生成的随机数
 * @param sr_len   [in] 随机数长度
 * @param cr       [in] TF卡tf_gen_cr接口产生的随机数密文
 * @param cr_len   [in] TF卡CR随机数长度
 * @param sig      [in] TF卡tf_sign_sr_cr接口产生的签名值 
 * @param sig_len  [in] 签名值长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_verify_cs(unsigned char *cc, int cc_len, unsigned char *sr, int sr_len, unsigned char *cr, int cr_len, unsigned char *sig, int sig_len);

/**
 * @brief 解密TF卡随机数密文
 *
 * @param cr          [in]  TF卡随机数密文
 * @param cr_len      [in]  随机数密文长度
 * @param dec_cr      [out] 明文缓冲区
 * @param dec_cr_len  [out] 明文长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_decrypt_cr(unsigned char *cr, int cr_len, unsigned char **dec_cr, int *dec_cr_len);

/**
 * @brief 对TF卡随机数明文进行签名
 *
 * @param cr        [in] TF卡随机数明文（可由pcie_decrypt_cr接口获得）
 * @param cr_len    [in] TF卡随机数明文长度
 * @param sig       [out] 签名值缓冲区
 * @param sig_len   [out] 签名值长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_sign_ss(unsigned char *cr, int cr_len, unsigned char **sig, int *sig_len);

/**
 * @brief 对数据进行对称加密
 *
 * @param cr            [in] TF卡随机数明文
 * @param data          [in] 需要加密的原始数据
 * @param data_len      [in] 数据长度
 * @param enc_data      [out] 密文缓冲区
 * @param enc_data_len  [out] 密文长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_encypt_data(unsigned char *cr, unsigned char *data, int data_len, unsigned char **enc_data, int *enc_data_len);

/**
 * @brief 对数据进行对称解密
 *
 * @param cr            [in] TF卡随机数明文
 * @param enc_data      [in] 密文数据
 * @param enc_data_len  [in] 密文数据长度
 * @param data          [out] 原文缓冲区 
 * @param data_len      [out] 原文长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_decypt_data(unsigned char *cr, unsigned char *enc_data, int enc_data_len, unsigned char **data, int *data_len);

/**
 * @brief 设备初始化（一个设备作一次即可）
 *          主要导入CA证书、PCIE加密卡证书及密钥对等
 *
 * @return 成功，返回0；失败，返回其他；
 */
int pcie_init();

#endif /* __PCIE_H__ */
