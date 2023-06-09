#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "pcie.h"
#include "log.h"
#include "tf.h"
#include "common.h"

static int download(int lba, unsigned char *cr, unsigned char *data, int *data_len)
{
    int ret = 0;
    unsigned char *enc_data = NULL;
    int enc_data_len = 0;

    /**
     * ############### PCIE加密卡端 ##################
     * (1.1) 对数据进行加密；
     *      (1.1.1) 由于对称算法ECB模式要求原文数据长度必需是16的整数倍，隐藏pcie_encypt_data函数内部会自动进行padding处理；
     *      (1.1.2) 当前私有区加解密算法采用SM4算法，因此pcie_encypt_data内核使用PCIE加密卡SM4模块进行加密；
     * (1.2) 将加密数据发送至TF卡；
     */
    CHECK_FUNC(ret = pcie_encypt_data(cr, data, *data_len, &enc_data, &enc_data_len));

    /**
     * ############### TF卡端 ##################
     * (2.1) 将1.2发送过来的加密数据写入私有区；
     */
    CHECK_FUNC(ret = tf_priv_write(lba, enc_data, enc_data_len));
    *data_len = enc_data_len;

end:
    if (enc_data) free(enc_data);
    return ret;
}

static int upload(int lba, unsigned char *cr, unsigned char **data, int *data_len)
{
    int ret = 0;
    unsigned char *enc_data = NULL;

    /**
     * ############### TF卡端 ##################
     * (1.1) 从私有区读数据（读取的大小必需是16的整数倍）；
     * (1.2) 将1.1读到的数据发送至PCIE加密卡端；
     */
    CHECK_FUNC(ret = tf_priv_read(lba, &enc_data, *data_len));

    /**
     * ############### PCIE加密卡端 ##################
     * (2.1) 对数据进行解密；
     *      (2.1.1) 由于1.1中读取到的是经过padding后的密文，因此解密时pcie_decypt_data函数内需要作去padding的操作；
     */
    CHECK_FUNC(ret = pcie_decypt_data(cr, enc_data, *data_len, data, data_len));

end:
    if (enc_data) free(enc_data);
    return ret;
}

int main(int argc, char **argv)
{
    int ret = 0;
    unsigned char sr[16];
    int sr_len = sizeof(sr);
    unsigned char *sc = NULL;
    int sc_len = 0;
    unsigned char *cc = NULL;
    int cc_len = 0;
    unsigned char *cr = NULL;
    int cr_len = 0;
    unsigned char *sig = NULL;
    int sig_len = 0;
    unsigned char *dec_cr = NULL;
    int dec_cr_len = 0;
    unsigned char *ss = NULL;
    int ss_len = 0;
    unsigned char *download_data = NULL;
    int download_data_len = 0;
    unsigned char *upload_data = NULL;
    int upload_data_len = 0;

    /**
     * ############### TF卡和PCIE加密卡端初始化 ##################
     * ############### 只需作一次即可，无需重复操作 ##################
     */
    CHECK_FUNC(ret = tf_init());
    CHECK_FUNC(ret = pcie_init());

    /**
     * ############### PCIE加密卡端 ##################
     * (1.1) PCIE加密卡获取随机数(SR)；
     * (1.2) 获取PCIE加密卡证书(SC)；
     *
     * (1.3) 把1.1中得到的随机数和1.2中得到的PCIE加密卡证书发送至TF卡(传输格式自行定义，接收端能正确解析就行)；
     */
    CHECK_FUNC(ret = pcie_gen_random(sr, sr_len));
    CHECK_FUNC(ret = pcie_load_cert(&sc, &sc_len));

    /**
     * ############### TF卡端 ##################
     * (2.1) 根据PCIE加密卡传过来的随机数(1.1 SR)和证书(1.2 SC)，得到加密的CR；
     * (2.2) 获取TF卡证书（CC）；
     * (2.3) 对PCIE加密卡传过来的随机数(1.1 SR)和2.1中得到的CR进行签名；
     *
     * (2.4) 把2.2中得到的TF卡证书（CC）、2.1中得到的CR以及2.3中得到的签名值（CS）发送至PCIE加密卡端(传输格式自行定义，接收端能正确解析就行)；
     */
    CHECK_FUNC(ret = tf_gen_cr(sc, sc_len, &cr, &cr_len));
    CHECK_FUNC(ret = tf_load_cert(&cc, &cc_len));
    CHECK_FUNC(ret = tf_sign_sr_cr(sr, sr_len, cr, cr_len, &sig, &sig_len));

    /**
     * ############### PCIE加密卡端 ##################
     * (3.1) 验证TF卡传过来的证书（2.2 CC）； 
     * (3.2) 验证1.1的随机数（SR）和2.1的加密随机数（CR）的签名值（2.3得到）；
     * (3.3) 解密2.1中的加密CR；
     * (3.4) 对明文CR进行签名，得到签名值（SS）；
     *
     * (3.5) 将3.4中得到的签名值（SS）发送至TF卡端；
     */
    CHECK_FUNC(ret = pcie_verify_cc(cc, cc_len));
    CHECK_FUNC(ret = pcie_verify_cs(cc, cc_len, sr, sr_len, cr, cr_len, sig, sig_len));
    CHECK_FUNC(ret = pcie_decrypt_cr(cr, cr_len, &dec_cr, &dec_cr_len));
    // log_data("cr", dec_cr, dec_cr_len);
    CHECK_FUNC(ret = pcie_sign_ss(dec_cr, dec_cr_len, &ss, &ss_len));

    /**
     * ############### TF卡端 ##################
     * (4.1) 验证PCIE加密发送过来的签名值（3.4 SS）；
     */
    // log_data("ss", ss, ss_len);
    CHECK_FUNC(ret = tf_verify_ss(ss, ss_len));

    /**
     * #### 至此,
     * #### (5.1) TF卡读数据时，会自动使用CR进行加密；写数据时，会自动使用CR进行解密；
     * #### (5.2) PCIE加密卡可使用CR配合TF卡读写操作自由进行加密和解密（详见后续下载和上传流程）；
     */

    /**
     * (6.1) 下载；
     * (6.2) 上传；
     */
    CHECK_FUNC(ret = load_file("test.bin", &download_data, &download_data_len));
    upload_data_len = download_data_len;
    CHECK_FUNC(ret = download(0, dec_cr, download_data, &upload_data_len));
    CHECK_FUNC(ret = upload(0, dec_cr, &upload_data, &upload_data_len));
    if (download_data_len != upload_data_len ||
        memcmp(download_data, upload_data, download_data_len)) {
        LOG("download and upload data is not the same!\n");
        write_file("read.bin", upload_data, download_data_len);
        ret = -1;
        goto end;
    } else {
        LOG("download and upload data is the same!\n");
    }

end:
    if (cr) free(cr);
    if (cc) free(cc);
    if (sc) free(sc);
    if (ss) free(ss);
    if (sig) free(sig);
    if (dec_cr) free(dec_cr);
    if (upload_data) free(upload_data);
    if (download_data) free(download_data);
    return ret;
}
