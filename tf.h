#ifndef __TF_H__
#define __TF_H__

/* TF卡应用用户密码，默认为6个1（111111） */
#define APP_PIN "111111"

/* TF卡CA证书文件名称 */
#define TF_CA_FILE_NAME "tf_ca.der"

/**
 * @brief 获取TF卡证书
 *
 * @param cert      [out] 证书
 * @param cert_len  [out] 证书长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int tf_load_cert(unsigned char **cert, int *cert_len);

/**
 * @brief 生成TF卡随机数密文
 *
 * @param sc      [in] PCIE加密卡证书
 * @param sc_len  [in] PCIE加密卡证书长度
 * @param cr      [out] 随机数密文
 * @param cr_len  [out] 密文长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int tf_gen_cr(unsigned char *sc, int sc_len, unsigned char **cr, int *cr_len);

/**
 * @brief 对PCIE加密卡证书、TF卡随机数密文进行签名
 *
 * @param sr       [in] PCIE加密卡证书
 * @param sr_len   [in] PCIE加密卡证书长度
 * @param cr       [in] 随机数密文
 * @param cr_len   [in] 随机数密文长度
 * @param sig      [out] 签名值缓冲区
 * @param sig_len  [out] 签名值长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int tf_sign_sr_cr(unsigned char *sr, int sr_len, unsigned char *cr, int cr_len, unsigned char **sig, int *sig_len);

/**
 * @brief 验证PCIE加密卡对TF卡明文随机数的签名
 *
 * @param ss      [in] PCIE加密卡对TF卡明文随机数的签名值
 * @param ss_len  [in] 签名值长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int tf_verify_ss(unsigned char *ss, int ss_len);

/**
 * @brief 写私有区
 *
 * @param lba       [in] 起始LBA号
 * @param data      [in] 数据
 * @param data_len  [in] 数据长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int tf_priv_write(int lba, unsigned char *data, int data_len);

/**
 * @brief 读私有区
 *
 * @param lba       [in] 起始LBA号
 * @param data      [out] 数据缓冲区
 * @param data_len  [int] 要读取的数据长度
 *
 * @return 成功，返回0；失败，返回其他；
 */
int tf_priv_read(int lba, unsigned char **data, int data_len);

/**
 * @brief 设备初始化（一个设备作一次即可）
 *          主要导入CA证书、TF卡证书及密钥对等
 *
 * @return 成功，返回0；失败，返回其他；
 */
int tf_init();

#endif /* __TF_H__ */
