#include "rg_wds_json.h"

#define TYPE_SET  1
#define TYPE_GET  2
#define TYPE_INFO 3
#define TYPE_CRYPTO 4

#define UN_CRYPTO_LEN       1024*2      //������������ܳ���          
#define EN_CRYPTO_LEN       1024*3      //���ܺ�����ܳ���
#define UN_CRYPTO_PART_LEN  1024        //���ܺ����������֧�ּ������ĳ���
#define EN_CRYPTO_PART_LEN  1024+512    //�������1024�ֽ����ļ����곤�ȴ����1.5����
#define CRYPTO_SPLIT_FLAG   "###"       //����ķָ��ʶ����
#define STOP_SEND_CNT       300         //5mins count,if recv 50002,reset 5mins
#define MTU_DATA_LEN        1400        //UDP��MTU���1500�ֽڣ�����ͷռ��һЩ�ֽڣ����Ե��ξͷ�1400�ֽ�       

#define PWDLEN          	20
#define PWDF            	"RjYkh"
#define PWDS            	"wzx$20"
#define PWDFALSE1       	"S@alwXCuc2ZzPw"
#define PWDFALSE2       	"Yf&j8ceh6yxLmI"
#define PWDT            	"18!"

