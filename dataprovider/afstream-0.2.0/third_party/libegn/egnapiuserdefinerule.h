/*
 ******************************************************************************
 ��Ȩ���� (C), 2008-2009, ��Ϊ�������޹�˾
 ******************************************************************************
  �� �� ��   : egnapiuserdefinerule.h
  �� �� ��   : ����
  ��    ��   : EGN��Ŀ��
  ��������   : 2012��12��6��
  ����޸�   :
  ��������   : �����궨��
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2012��12��6��
    ��    ��   : EGN��Ŀ��
    �޸�����   : �����ļ�

******************************************************************************/
/**@file  egnapiuserdefinerule.h
  *    �����궨��
*******************************************************/
/**
 * @defgroup egn  EGN�Զ������ģ���API
 */

#ifndef __EGN_API_USER_DEFINE_RULE_H__
#define __EGN_API_USER_DEFINE_RULE_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/*MACRO<  �Զ��嵥������֧�ֵ�������� >*/
#define EGN_UD_SINGLE_PKT_RULE_MAX_NUM  1024

/*MACRO<  �Զ�����Ϊ����֧�ֵ�������� >*/
#define EGN_UD_BEHA_RULE_MAX_NUM  64

/*MACRO<  �Զ���Ȳ����֧�ֵ�������� >*/
#define EGN_UD_ARITH_RULE_MAX_NUM  16

/*MACRO<  �Զ���HTTP���ع���֧�ֵ�������� >*/
#define EGN_UD_HTTP_BEAR_RULE_MAX_NUM  64

/*MACRO< �Զ������������󳤶� >*/
#define EGN_USER_RULE_NAME_MAX_LEN      31

/*MACRO< �Զ������֧��������ָ�����ַ��������ĸ��� >*/
#define EGN_USER_STRING_PATTERN_MAX_NUM      6

/*MACRO< �Զ������֧��������ָ����pcre�����ĸ��� >*/
#define EGN_USER_PCRE_PATTERN_MAX_NUM      1

/*MACRO< �Զ������֧�ֵ�pcre��������󳤶� >*/
#define EGN_USER_PCRE_PATTERN_MAX_LEN      63

/*MACRO< ֧�ֵ��Զ�������Э�顢Ӧ�á�����id��Сֵ >*/
#define EGN_UD_ID_MIN  0x10000000

/*MACRO< ֧�ֵ��Զ�������Э�顢Ӧ�á�����id���ֵ >*/
#define EGN_UD_ID_MAX  0x1FFFFFFF

/*MACRO< ֧�ֵ��Զ����ַ������������ƫ��ֵ >*/
#define EGN_UD_STR_CONDITION_OFFSET_MAX  63

/*MACRO< �Զ���Ȳ�������ģʽ������� >*/
#define EGN_USER_ARITH_PATTERN_MAX_NUM 2

/*MACRO< �Զ���Ȳ����Ȳ��ֶε���󳤶� >*/
#define EGN_USER_ARITH_FIELD_MAX_LEN    4

/*MACRO< �Զ���Ȳ����ʶ���м�״̬������ƥ����Ϣ�ڵ��� >*/
#define EGN_USER_ARITH_MATCH_NODE_NUM    32

/*MACRO< �Զ���Ȳ����ģʽ�������ƫ�� >*/
#define EGN_USER_ARITH_PATTERN_MAX_OFFSET 1500

/*MACRO< ֧�ֵ��Զ����ַ�����������С���� >*/
#define EGN_UD_STR_CONDITION_LEN_MIN  3

/*MACRO< ֧�ֵ��Զ����ַ�����������󳤶� >*/
#define EGN_UD_STR_CONDITION_LEN_MAX  31

/*MACRO< �Զ��嵥�������ַ��������������ĳ��� >*/
#define EGN_UD_SINGLE_PKT_STR_BUF_LEN  63

/*MACRO< �Զ���HTTP���ع����ַ��������������ĳ��� >*/
#define EGN_UD_HTTP_BEAR_STR_BUF_LEN  80

/*ENUM< �Զ����ַ�����������ʼλ�� >*/
typedef enum
{
    EGN_UD_STRING_BASE_BEGIN          = EGN_EN_INVALID,
    EGN_UD_STRING_BASE_LOAD_BEGIN     = 0,   /* ������ʼλ�� */
    EGN_UD_STRING_BASE_LOAD_END       = 1,   /* ���ؽ���λ�� */
    EGN_UD_STRING_BASE_HTTP_FIRST     = 2,   /* ����λ��,ֻ��HTTP���زŻ���Ч */
    EGN_UD_STRING_BASE_HTTP_HEADER    = 3,   /* ͷ��λ��,ֻ��HTTP���زŻ���Ч */
    EGN_UD_STRING_BASE_LOAD_BODY      = 4,   /* ��Ϣ��λ��,ֻ��HTTP���زŻ���Ч */
    EGN_UD_STRING_BASE_END,

    EGN_UD_STRING_BASE_BOTTOM = EGN_EN_BUTT
}EGN_UD_STRING_BASE_EN;

/*ENUM< �Զ����ַ��������Ĵ�С�� >*/
typedef enum
{
    EGN_UD_BYTE_ORDER_BEGIN    = EGN_EN_INVALID,
    EGN_UD_BYTE_ORDER_UNKNOWN  = 0,   /* δ֪ */
    EGN_UD_BYTE_ORDER_BIG      = 1,   /* ��� */
    EGN_UD_BYTE_ORDER_LITTLE   = 2,   /* С�� */
    EGN_UD_BYTE_ORDER_END,

    EGN_UD_BYTE_ORDER_BOTTOM = EGN_EN_BUTT
}EGN_UD_BYTE_ORDER_EN;

/*ENUM< �Զ����ַ�����ʽ >*/
typedef enum
{
    EGN_UD_CONTENT_TYPE_BEGIN   = EGN_EN_INVALID,
    EGN_UD_CONTENT_TYPE_STR     = 0,              /* ��ͨ�ַ�������Сд������  */
    EGN_UD_CONTENT_TYPE_HEX     = 1,              /* ʮ�������ַ�������Сд���� */
    EGN_UD_CONTENT_TYPE_END,

    EGN_UD_CONTENT_TYPE_BOTTOM  = EGN_EN_BUTT
}EGN_UD_CONTENT_TYPE_EN;

/*ENUM< �Զ������������е����� >*/
typedef enum
{
    EGN_UD_DEPTH_TYPE_BEGIN          = EGN_EN_INVALID,
    EGN_UD_DEPTH_TYPE_RANGE          = 0,   /* ��Χ */
    EGN_UD_DEPTH_TYPE_DISTANCE       = 1,   /* ȷ���ĸ��� */
    EGN_UD_DEPTH_TYPE_END,

    EGN_UD_DEPTH_TYPE_BOTTOM = EGN_EN_BUTT
}EGN_UD_DEPTH_TYPE_EN;

/*ENUM< �Զ������������е����� >*/
typedef enum
{
    EGN_UD_BEAR_SAME_PKT_BEGIN     = EGN_EN_INVALID,
    EGN_UD_BEAR_SAME_PKT_SAME      = 0,    /* �ͳ���Э����ͬһ������ȡ��ֵʱ�����ֵucBearDepth����Ϊ0 */
    EGN_UD_BEAR_SAME_PKT_NOTSAME   = 1,    /* �ͳ���Э���ڲ�ͬ�İ���ȡ��ֵʱ�����ֵucBearDepth���벻Ϊ0 */
    EGN_UD_BEAR_SAME_PKT_ALL       = 2,    /* �ͳ���Э�������ͬһ������Ҳ�����ڲ�ͬ�İ�����ȡ��ֵʱ�����ֵucBearDepth���벻Ϊ0 */
    EGN_UD_BEAR_SAME_PKT_END,

    EGN_UD_BEAR_SAME_PKT_BOTTOM    = EGN_EN_BUTT
}EGN_UD_BEAR_SAME_PKT_EN;

/*ENUM< �Զ��������Ԫ����Ϣ�е�IP�汾�� >*/
typedef enum
{
    EGN_UD_IP_VERSION_BEGIN         = EGN_EN_INVALID,
    EGN_UD_IP_VERSION_V4            = 0,   /* IPV4 */
    EGN_UD_IP_VERSION_V6            = 1,   /* IPV6 */
    EGN_UD_IP_VERSION_ANY           = 2,   /* any */
    EGN_UD_IP_VERSION_END,

    EGN_UD_IP_VERSION_BOTTOM = EGN_EN_BUTT
}EGN_UD_IP_VERSION_EN;

/*ENUM< �Զ���������� >*/
typedef enum
{
    EGN_UD_RULE_TYPE_BEGIN          = EGN_EN_INVALID,
    EGN_UD_RULE_TYPE_SINGLE_PACKET  = 0,               /* �Զ��嵥������ */
    EGN_UD_RULE_TYPE_BEHA           = 1,               /* �Զ�����Ϊͳ�ƹ��� */
    EGN_UD_RULE_TYPE_ARITH          = 2,               /* �Զ���Ȳ���� */
    EGN_UD_RULE_TYPE_HTTP_BEAR      = 3,               /* �Զ�����ع��� */
    EGN_UD_RULE_TYPE_ALL            = 4,               /* �����Զ������ */
    EGN_UD_RULE_TYPE_END,

    EGN_UD_RULE_TYPE_BOTTOM            = EGN_EN_BUTT
}EGN_UD_RULE_TYPE_EN;

/*STRUCT< �Զ�����������Ϣ >*/
typedef struct _EgnUDRuleBearInfo
{
    EGN_UINT32  ulBearID;           /* ����Э��ID������HTTP���ع����ֵ��Ч����idֻ����ϵͳ����Э���Ӧ��id���������Զ�������Э��id��Ϊ0ʱ��ʾ�޳��ع�ϵ�����ulBearID����ʶ�����Զ�������ܱ�ʶ�� */
    EGN_UINT16  usBearDepth;        /* ���ص���ȣ�ȡֵ���ڵ���0��С�ڵ���65535��������Ϊ65535 */
    EGN_UINT8   ucSamePacket;       /* �Ƿ�ͳ���Э����ͬһ������EGN_UD_BEAR_SAME_PKT_EN */
    EGN_UINT8   ucReserved;         /* ����4��8�ֽڶ��뱣���ֽ� */
}EgnUDRuleBearInfo;

/*STRUCT< �Զ�����򹫹���Ϣ >*/
typedef struct _EgnUDRuleBaseInfo
{
    EGN_UINT32          ulProtocolId;       /* С��Э��ID����ϵͳ֪ʶ���е�Э��id���֣���СȡֵEGN_UD_ID_MIN�����ȡֵEGN_UD_ID_MAX */
    EGN_UINT32          ulAppID;            /* Ӧ��ID����СȡֵEGN_UD_ID_MIN�����ȡֵEGN_UD_ID_MAX */
    EGN_UINT32          ulSrvID;            /* ����Э��ID����СȡֵEGN_UD_ID_MIN�����ȡֵEGN_UD_ID_MAX */
    EGN_UINT32          ulRuleID;           /* �����ţ���ϵͳ֪ʶ���еĹ��������֣���СȡֵEGN_UD_ID_MIN�����ȡֵEGN_UD_ID_MAX */
    EGN_UINT8           ucWeight;           /* ����Ȩ�أ�ȡֵ��ΧΪ���ڵ���1��С�ڵ���99��ֵԽ��Ȩ��Խ�ߣ�Ϊ0ʱ��ȡĬ��Ȩ��13 */
    EGN_UINT8           ucL4Proto;          /* 4��Э�飺EGN_TRANS_TYPE_EN */
    EGN_UINT8           aucReserved[6];     /* ����4��8�ֽڶ��뱣���ֽ� */
    EGN_UCHAR           aucRuleName[EGN_USER_RULE_NAME_MAX_LEN + 1];  /* ����Name����󳤶�ΪEGN_USER_RULE_NAME_MAX_LEN������ĸ�����֡�'-'��'_'��� */
}EgnUDRuleBaseInfo;

/*STRUCT< �û�pcre�������� >*/
typedef struct _EgnUDCondPcre
{
    EGN_UINT8   ucPcreLen;          /* PCRE���ȣ��û���Ҫ��֤�����ݶ�Ӧ */
    EGN_UINT8   ucKeyNo;            /* �ؼ���usKeyLoc��ƫ�����ͣ�EGN_UD_STRING_BASE_EN����ͨ��������������ֶ������壬http���ع���������ֶ�ȡ���л�ͷ���body */
    EGN_UINT8   aucReserved[6];     /* ����4��8�ֽڶ��뱣���ֽ� */
    EGN_UINT8   aucPcre[EGN_USER_PCRE_PATTERN_MAX_LEN + 1];    /* PCRE������󳤶�Ϊ63���û���Ҫ��֤�ͳ��ȶ�Ӧ */
}EgnUDCondPcre;

/*STRUCT< �û��ַ����������� >*/
typedef struct _EgnUDCondStr
{
    EGN_UINT16 usKeyLoc;            /* �ؼ��ֳ���ƫ�ƣ�ȡֵ[0,63]�������65535������65535ʱ��ucKeyNoֻ��ΪEGN_UD_STRING_BASE_LOAD_BEGIN����ʾƫ��Ϊ������ �������������HTTP���أ����ֶ���Ч��*/
    EGN_UCHAR  ucKeyNo;             /* �ؼ���usKeyLoc��ƫ�����ͣ�EGN_UD_STRING_BASE_EN */
    EGN_UINT8  ucKeyLen;            /* �ؼ��ֳ���(����ؼ�����16�������ʾת����ĳ���)��ȡֵ[3,31]���û���Ҫ��֤��������� */
    EGN_UINT8  ucKeyType;           /* ��ʾ�ؼ��ָ�ʽ��EGN_UD_CONTENT_TYPE_EN */
    EGN_UINT8  aucReserved[3];      /* �����ֶ� */
    EGN_UCHAR  aucKeyInfo[EGN_UD_SINGLE_PKT_STR_BUF_LEN];  /* �ؼ��֣���ͨ�ַ�����󳤶�Ϊ31��ʮ�����Ƹ�ʽ���Ϊ62���û���Ҫ��֤�ͳ������ */
    EGN_UINT8  aucReserved1;         /* �����ֶ� */
}EgnUDCondStr;

/*STRUCT< �Զ�����Ԫ����Ϣ >*/
typedef struct _EgnUDCondFiveTuple
{
    EGN_UINT16      usSrcPort;      /* Դ�˿ڣ�Ϊ0��ʾû��Դ�˿����� */
    EGN_UINT16      usDstPort;      /* Ŀ�Ķ˿ڣ�Ϊ0��ʾû��Ŀ�Ķ˿����� */
    EGN_UINT16      usSrcPortEnd;   /* Դ�˿ڷ�Χ���ޣ���ȥԴ�˿ڵĲ�ֵ������ڵ���0��С��128��Ϊ0ʱ��ʾ��Դ�˿���� */
    EGN_UINT16      usDstPortEnd;   /* Ŀ�Ķ˿ڷ�Χ���ޣ���ȥĿ�Ķ˿ڵĲ�ֵ������ڵ���0��С��128��Ϊ0ʱ��ʾ��Ŀ�Ķ˿���� */
    EgnIpAddrCond   stSrcIp;        /* ԴIP��ַ, ֧��ipv4��ipv6��֧�����Σ��������˱�ʾ��Ϊȫ0ʱ��ʾû��SrcIP���� */
    EgnIpAddrCond   stDstIp;        /* Ŀ��IP��ַ, ֧��ipv4��ipv6��֧�����Σ��������˱�ʾ��Ϊȫ0ʱ��ʾû��DstIP���� */
}EgnUDCondFiveTuple;

/*STRUCT< �Զ����������� >*/
typedef struct _EgnUDCondDepth
{
    EGN_UINT32   ulDepthType;      /* ʹ�þ��뻹�Ƿ�Χ����EGN_UD_DEPTH_TYPE_EN */
    EGN_UINT32   ulMaxDepth;       /* ��ȣ����ȡֵ254��Ϊ0��ʾ��������� */
}EgnUDCondDepth;

/*STRUCT< �Զ��嵥��������Ϣ >*/
typedef struct _EgnUDSinglePacketRule
{
    EgnUDRuleBaseInfo   stRuleBaseInfo;     /* ���������Ϣ */
    EgnUDRuleBearInfo   stBearInfo;         /* ���������Ϣ */
    EGN_UINT8           ucCondPcreNum;      /* ���������е�����ʽ�������� */
    EGN_UINT8           ucCondStrNum;       /* ���������е��ַ����������� */
    EGN_UINT8           aucReserved[6];     /* ����4��8�ֽڶ��뱣���ֶ� */
    EgnUDCondPcre       astCondPcre[EGN_USER_PCRE_PATTERN_MAX_NUM];   /* ������ʽ������Ϣ��������䣬��֤��Ա������ucCondPcreNum��Ӧ */
    EgnUDCondStr        astCondStr[EGN_USER_STRING_PATTERN_MAX_NUM];  /* �ַ���������Ϣ��������䣬��֤��Ա������ucCondStrNum��Ӧ */
    EgnUDCondFiveTuple  stCondFiveTuple;    /* ��Ԫ��������Ϣ */
    EgnUDCondDepth      stCondDepth;        /* ���������Ϣ */
}EgnUDSinglePacketRule;

/*MACRO< �Զ���HTTP���ع�����ַ�����������С���� >*/
#define EGN_USER_HTTP_BEAR_RULE_STR_MIN_LEN      7

/*MACRO< �Զ���HTTP���ع�����ַ�����������󳤶� >*/
#define EGN_USER_HTTP_BEAR_RULE_STR_MAX_LEN      40

/*MACRO< �Զ���HTTP���ع���֧��������ָ�����ַ��������ĸ��� >*/
#define EGN_USER_HTTP_BEAR_STRING_PATTERN_MAX_NUM      4

/*MACRO< �Զ���HTTP���ع���֧��������ָ����pcre�����ĸ��� >*/
#define EGN_USER_HTTP_BEAR_PCRE_PATTERN_MAX_NUM      2

/*STRUCT< �û�HTTP�����ַ����������� >*/
typedef struct _EgnUDHttpBearCondStr
{
    EGN_UINT16 usKeyLoc;            /* ͷ���ַ�����ͷ��ֵ����ǰ��Ŀո�������ͷ������ƫ�ƣ��������С���Ϣ���ַ�����֧��ƫ�� */
    EGN_UCHAR  ucKeyNo;             /* �ؼ���usKeyLoc��ƫ�����ͣ�EGN_UD_STRING_BASE_EN */
    EGN_UINT8  ucKeyLen;            /* �ؼ���ת��Ϊ��ͨ�ַ�����ĳ��ȣ���ȥ��ʽͷ("URL:"��"HEADER:"��"BODY:")�⣬��Ч�ؼ��ֵ�ȡֵ���ڵ���EGN_UD_STR_CONDITION_LEN_MIN��С�ڵ���EGN_UD_STR_CONDITION_LEN_MAX */
    EGN_UINT8  ucKeyType;           /* �ؼ�����ʽ���ַ�����ʮ������ EGN_UD_CONTENT_TYPE_EN*/
    EGN_UINT8  aucReserved[3];      /* �����ֶ� */
    EGN_UCHAR  aucKeyInfo[EGN_UD_HTTP_BEAR_STR_BUF_LEN];  /* �ؼ��֣���󳤶�Ϊ31,��Ч������ucKeyLenָ����������ΪHTTP���ع�����ָ������λ�õ�˵�������Լӳ� */
}EgnUDHttpBearCondStr;

/*STRUCT< �Զ���HTTP���ع�����Ϣ >*/
typedef struct _EgnUDHTTPBearRule
{
    EgnUDRuleBaseInfo       stRuleBaseInfo;     /* ���������Ϣ */
    EgnUDRuleBearInfo       stBearInfo;         /* ���������Ϣ */
    EGN_UINT8               ucCondPcreNum;      /* ���������е�����ʽ�������� */
    EGN_UINT8               ucCondStrNum;       /* ���������е��ַ����������� */
    EGN_UINT8               aucReserved[6];     /* �����ֶ� */
    EgnUDCondPcre           astCondPcre[EGN_USER_HTTP_BEAR_PCRE_PATTERN_MAX_NUM];     /* ������ʽ������Ϣ */
    EgnUDHttpBearCondStr    astCondStr[EGN_USER_HTTP_BEAR_STRING_PATTERN_MAX_NUM];    /* �ַ���������Ϣ */
    EgnUDCondFiveTuple      stCondFiveTuple;    /* ��Ԫ��������Ϣ */
    EgnUDCondDepth          stCondDepth;        /* ���������Ϣ */
}EgnUDHTTPBearRule;

/*MACRO< �Զ�����Ϊͳ�ƹ���֧��������ָ��pattern���� >*/
#define EGN_USER_BEHA_PATTERN_MAX_NUM   8

/*MACRO< �Զ�����Ϊͳ�ƹ���֧�ְ������������  >*/
#define EGN_USER_BEHA_PKT_MAX_NUM 64

/*MACRO< �Զ�����Ϊͳ�ƹ���֧�ְ�������С����  >*/
#define EGN_USER_BEHA_PKT_MIN_NUM 1

/* ģʽͳ��ֵ���ֵ: Ŀǰռ��14 λ*/
#define EGN_STAT_MATCH_VALUE_MAX    EGN_STAT_MAX_PACKET_LOADLEN

/*STRUCT< �Զ�����Ϊͳ�Ʒ�Χ����Ķ��� >*/
typedef struct _EgnRange
{
    EGN_UINT16  usStart;        /* ���ޣ���ʼֵ */
    EGN_UINT16  usEnd;          /* ���ޣ���ֵֹ */
    EGN_UINT8   aucReserved[4]; /* ���� */
} EgnRange;

/*ENUM< �Զ�����Ϊ�������ģʽ������ >*/
typedef enum
{
    EGN_UD_BEHA_PTN_TYPE_BEGIN      = EGN_EN_INVALID,
    EGN_UD_BEHA_PTN_TYPE_AVG        = 0,   /* ����ƽ��ֵ */
    EGN_UD_BEHA_PTN_TYPE_RATIO      = 1,   /* �����շ��� */
    EGN_UD_BEHA_PTN_TYPE_NUM        = 2,   /* ������ĳ����Χ�ڵİ����� */
    EGN_UD_BEHA_PTN_TYPE_SEQ        = 3,   /* �������� */
    EGN_UD_BEHA_PTN_TYPE_END,

    EGN_UD_BEHA_PTN_TYPE_BOTTOM = EGN_EN_BUTT
}EGN_UD_BEHA_PTN_TYPE_EN;

/*ENUM< �Զ�����Ϊ�������ģʽ�����ķ��� >*/
typedef enum
{
    EGN_UD_DIR_BEGIN         = EGN_EN_INVALID,
    EGN_UD_DIR_BI            = 0,   /* ˫�� */
    EGN_UD_DIR_UP            = 1,   /* ���� */
    EGN_UD_DIR_DOWN          = 2,   /* ���� */
    EGN_UD_DIR_END,

    EGN_UD_DIR_BOTTOM = EGN_EN_BUTT
}EGN_UD_DIR_EN;

/*STRUCT< �Զ�����Ϊͳ�ƹ���ģʽ�� >*/
typedef struct _EgnUDBehaPattern
{
    EGN_UINT8   ucType;             /* ģʽ����:EGN_UD_BEHA_PTN_TYPE_EN */
    EGN_UINT8   ucDirection;        /* ����������շ���ģʽ������˫��ģ�EGN_UD_DIR_EN */

    /* Ҫͳ�Ƶ����ݰ�λ�÷�Χ��ȡֵ��Χ1-64 */
    EGN_UINT8   ucPKTStartPos;      /* Ҫͳ�Ƶ����ݰ�����ʼλ�á�ȡֵ��Χ1-64 */
    EGN_UINT8   ucPKTEndPos;        /* Ҫͳ�Ƶ����ݰ��Ľ���λ�á�ȡֵ��Χ1-64 */
    EGN_UINT8   aucReserved[4];     /* ���� */

    /* ֵ�ķ�Χ��ƽ��ֵ���շ��ȡ�������ʹ�ô��ֶ� */
    EgnRange stValueRange;  /*ֵ��Χ��[1,EGN_STAT_MATCH_VALUE_MAX]*/

    /* ������ģʽ��Ҫ�õ��İ�����Χ */
    EgnRange stPKTLenRange; /*ֵ��Χ����EGN_UD_BEHA_PTN_TYPE_NUMģʽ��[1, EgnUDBehaPattern]��[1,EGN_STAT_MATCH_VALUE_MAX]��*/

    /* ��������ʹ�ô��ֶΣ����64����С��64�����������0��ʾ���еĽ���������������Ϊ0�� */
    EGN_UINT16   ausPKTLenSeq[EGN_USER_BEHA_PKT_MAX_NUM]; /* �������е�ֵ�����ֵΪEGN_STAT_MATCH_VALUE_MAX��������� */
} EgnUDBehaPattern;

/*STRUCT< �Զ�����Ϊͳ�ƹ�����Ϣ >*/
typedef struct _EgnUDBehaRule
{
    EgnUDRuleBaseInfo   stRuleBaseInfo;     /* ���������Ϣ */
    EGN_UINT8           ucUDBehaPtnNum;     /* ��Ϊͳ��ģʽ������ */
    EGN_UINT8           ucReserved[3];      /* �����ֶ� */
    EGN_UINT16          usPort;             /* �˿�����,���ָ���˿ڣ��򲻿���Ϊ0����������Դ�Ļ���Ŀ��*/
    EGN_UINT16          usPortEnd;          /* �˿�����,���ڵ��ڶ˿�����,�˿�����ֵΪ0ʱ����Ϊ0 */
    EgnUDBehaPattern    astBehaPtn[EGN_USER_BEHA_PATTERN_MAX_NUM]; /* ģʽ����Ϣ��������䣬��֤��Ա������ucUDBehaPtnNum��Ӧ */
} EgnUDBehaRule;

/*STRUCT< �Զ���Ȳ�ģʽ����Ϣ >*/
typedef struct _EgnUDArithPattern
{
    EGN_UINT32  ulDelta;        /* �Ȳ���ֵ�������ֵδ֪����д0xFFFFFFFF����֧�ֵȲ�ֵΪ�������(����-2��תΪ0xFFFFFFFE)��ʹ��ʱ��ע���Լ�� */
    EGN_UINT16  usOffsetLoc;    /* �Ȳ��ֶ�ƫ��λ�ã�ȡֵ���ڵ���0��С�ڵ���1500 */
    EGN_UINT8   ucOffsetDir;    /* �Ȳ��ֶ�ƫ�Ʒ���ֻ��ȡֵ����ͷEGN_UD_STRING_BASE_LOAD_BEGIN����βEGN_UD_STRING_BASE_LOAD_END */
    EGN_UINT8   ucByteOrder;    /* �Ȳ��ֶ��ֽ���ֻ��ȡֵEGN_UD_BYTE_ORDER_BIG��EGN_UD_BYTE_ORDER_LITTLE */
    EGN_UINT8   ucLen;          /* �Ȳ��ֶγ��ȣ�ȡֵ���ڵ���1С�ڵ���4 */
    EGN_UINT8   aucReserved[7]; /* ���� */
}EgnUDArithPattern;

/*STRUCT< �Զ���Ȳ������Ϣ >*/
typedef struct _EgnUDArithRule
{
    EgnUDRuleBaseInfo   stRuleBaseInfo;   /* ���������Ϣ */
    EGN_UINT8           ucUDArithPtnNum;  /* �Ȳ�ģʽ��������ֻ��ȡֵ1����2 */
    EGN_UINT8           ucReserved[3];    /* �����ֶ� */
    EGN_UINT16          usPort;           /* �˿�, ��ָ����Դ�Ļ���Ŀ�ģ�Ϊ0��ʾû�ж˿����� */
    EGN_UINT16          usPortEnd;        /* �˿ڷ�Χ���ޣ���ȥԴ�˿ڵĲ�ֵ������ڵ���0��Ϊ0ʱ��ʾ�Ͷ˿���ȣ�Ϊ�̶��˿� */
    EgnUDArithPattern   astArithPtn[EGN_USER_ARITH_PATTERN_MAX_NUM];  /* ģʽ����Ϣ���������ֵ����֤��Ա������ucUDArithPtnNum��Ӧ */
}EgnUDArithRule;

/*******************************************************************************
*    Func Name: EgnApiUDAddSinglePktRule
*      Purpose: ����Զ��嵥������
*  Description: ���սṹ�巽ʽ����Զ��嵥�����򣬴�����������Ч���ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲�����ӹ���
*        Input: EgnUDSinglePacketRule  *pstUDSinglePacketRule:��������ṹ��ָ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1���Զ��嵥������ĸ�ֻ��ΪЭ�飬��ֻ��Ϊϵͳ����
                2��Э��ID�͹���ID:[0x10000000, 0x1FFFFFFF]
                3��֧�ֵ��Զ��嵥�������������Ϊ1024
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDAddSinglePktRule
(
   IN     EgnUDSinglePacketRule  *pstUDSinglePacketRule
);

/*******************************************************************************
*    Func Name: EgnApiUDAddArithRule
*      Purpose: ����Զ���Ȳ����
*  Description: ���սṹ�巽ʽ����Զ���Ȳ���򣬴�����������Ч���ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲�����ӹ���
*        Input: EgnUDArithRule *pstUDArithRule:�Ȳ����ṹָ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1���Զ���Ȳ�Զ�����Ϊʶ��֧�ֳ���ʶ����Ϊ�����Ӷ���֧�֣�
                2��Э��ID�͹���ID:[0x10000000, 0x1FFFFFFF]
                3��֧�ֵ��û��Զ���Ȳ�����������Ϊ16
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDAddArithRule
(
   IN     EgnUDArithRule *pstUDArithRule
);

/*******************************************************************************
*    Func Name: EgnApiUDAddBehaRule
*      Purpose: ����Զ���ͳ�ƹ���
*  Description: ���սṹ�巽ʽ����Զ���Ȳ���򣬴�����������Ч���ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ��غ�ͳ��ʶ�𿪹�
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE;EgnInitCfgParam.bStatInspectSwitchΪEGN_TRUE����
                    �ҳ�ʼ���ɹ��󣬲�����ӹ���
*        Input: EgnUDBehaRule *pstUDBehaRule:ͳ�ƹ���ṹָ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �Զ���ͳ�ƹ������֧��64��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDAddBehaRule
(
    IN  EgnUDBehaRule   *pstUDBehaRule
);

/*******************************************************************************
*    Func Name: EgnApiUDActiveRule
*      Purpose: �����Զ������
*  Description: ����ӻ�ɾ���Զ������󣬵��ñ��ӿڼ��ʹ��ӻ�ɾ��������Ч��
                ����һ���൱�ڶ�֪ʶ����һ������/���ˣ���ϵͳ֪ʶ�������������߻��˹��̲��ܽ����Զ�����򼤻
                �����������ã���Ҫ�ȴ�����֪ʶ���л���ɺ�����ٴε��á�
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDActiveRule
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiUDAddHTTPBearRule
*      Purpose: ����Զ���HTTP���ع���
*  Description: ���սṹ�巽ʽ����Զ���HTTP���ع��򣬴�����������Ч���ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲�����ӹ���
*        Input: EgnUDHTTPBearRule  *pstUDHTTPBearRule:�ļ��ڴ�ָ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1��HTTP���ع����ڹ���ͷ�ϲ���Ҫ��ָ������ID����ʹָ��Ҳ��Ч
                2��HTTP���ع�����ַ���offset�������ƣ���Ϊ�������һ������ƥ��
                3��HTTP���ع�����ַ���������PCRE�ַ����е�ucKeyNo�ַ��α�ʾ�ĺ����ǣ�ָ�����ַ�����Ҫƥ���λ����
                   ���С�ͷ������Ϣ�壬��������ַ���������ַ���ָ������Ϣ������������ʧ��
                   ���磺�ַ�����URL��get*��ucKeyNo��ֵӦ��Ϊ����
                4��HTTP�����ַ����У����뱣֤��Ч�����������ڵ���3��С�ڵ���31��
                   ��url����body������ַ�������ǰ��ո��ʣ��ĳ��ȱ�����ڵ���3��С�ڵ���31��
                   header:ͷ���������ͷ��ֵ����ȥǰ��ո��ʣ��ĳ��ȱ�����ڵ���3��С�ڵ���31��
                5��˵���ַ�����λ�õ�"url:"��"body:"��"header:"���ַ����ֲ����ִ�Сд�������ַ���":"��һ��ģ��м䲻���пո�

*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDAddHTTPBearRule
(
    IN   EgnUDHTTPBearRule  *pstUDHTTPBearRule
);

/*******************************************************************************
*    Func Name: EgnApiUDGetHTTPBearRuleById
*      Purpose: ��ѯ�Զ���HTTP���ع���
*  Description: ����Э��ID�͹���ID, ��ѯ�Զ���HTTP���ع��򡣸ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ�����ܲ�ѯ����
*        Input: EGN_UINT32  ulProtolId:����ѯ�Ĺ����Ӧ��Э��ID:[0x10000000, 0x1FFFFFFF]���� 0.
                                        Ϊ��ʱ��ʾ��ulRuleId����.
*               EGN_UINT32  ulRuleId:����ѯ�Ĺ����Ӧ�Ĺ���ID:[0x10000000, 0x1FFFFFFF]���� 0.
                                        Ϊ��ʱ��ʾ��ulProtolId����.
*        InOut: EGN_UINT32               *pulItemNum:���:�����ѯ���������Ĵ�С<����>
                                                     ����: ϵͳ�з��ϲ�ѯ���������ʵ�ʸ���
*       Output: EgnUDHTTPBearRule  *pstHTTPBearRule:�����ѯ�������Զ��������Ϣ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ulProtolId��ulRuleId����ͬʱΪ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetHTTPBearRuleById
(
    IN    EGN_UINT32          ulProtolId,
    IN    EGN_UINT32          ulRuleId,
    OUT   EgnUDHTTPBearRule  *pstHTTPBearRule,
    INOUT EGN_UINT32         *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiUDDelHTTPBearRuleById
*      Purpose: ɾ���Զ���HTTP���ع���
*  Description: ����Э��ID�͹���ID, ɾ���Զ���HTTP���ع��򡣸ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ������ɾ������
*        Input: EGN_UINT32  ulProtolId:��ɾ���Ĺ����Ӧ��Э��ID:[0x10000000, 0x1FFFFFFF]
*               EGN_UINT32  ulRuleId:��ɾ���Ĺ����Ӧ�Ĺ���ID:[0x10000000, 0x1FFFFFFF]
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDDelHTTPBearRuleById
(
    IN  EGN_UINT32          ulProtolId,
    IN  EGN_UINT32          ulRuleId
);

/*******************************************************************************
*    Func Name: EgnApiUDGetSinglePKTRuleById
*      Purpose: ��ѯ�Զ��嵥������
*  Description: ����Э��ID�͹���ID, ��ѯ�Զ��嵥�����򡣸ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ�����ܲ�ѯ����
*        Input: EGN_UINT32  ulProtolId:����ѯ�Ĺ����Ӧ��Э��ID:[0x10000000, 0x1FFFFFFF]���� 0.
                                        Ϊ��ʱ��ʾ��ulRuleId����.
*               EGN_UINT32  ulRuleId:����ѯ�Ĺ����Ӧ�Ĺ���ID:[0x10000000, 0x1FFFFFFF]���� 0.
                                        Ϊ��ʱ��ʾ��ulProtolId����.
*        InOut: EGN_UINT32               *pulItemNum:���:�����ѯ���������Ĵ�С<����>
                                                     ����: ϵͳ�з��ϲ�ѯ���������ʵ�ʸ���
*       Output: EgnUDSinglePacketRule  *pstSinglePKTRule:�����ѯ�������Զ��������Ϣ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ulProtolId��ulRuleId����ͬʱΪ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetSinglePKTRuleById
(
    IN    EGN_UINT32               ulProtolId,
    IN    EGN_UINT32               ulRuleId,
    OUT   EgnUDSinglePacketRule    *pstSinglePKTRule,
    INOUT EGN_UINT32               *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiUDDelSinglePKTRuleById
*      Purpose: ɾ���Զ��嵥������
*  Description: ����Э��ID�͹���ID, ɾ���Զ��嵥�����򡣸ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ������ɾ������
*        Input: EGN_UINT32  ulProtolId:��ɾ���Ĺ����Ӧ��Э��ID:[0x10000000, 0x1FFFFFFF]
*               EGN_UINT32  ulRuleId:��ɾ���Ĺ����Ӧ�Ĺ���ID:[0x10000000, 0x1FFFFFFF]
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiUDDelSinglePKTRuleById
(
    IN  EGN_UINT32               ulProtolId,
    IN  EGN_UINT32               ulRuleId
);

/*******************************************************************************
*    Func Name: EgnApiUDGetArithRuleById
*      Purpose: ��ѯ�Զ���Ȳ����
*  Description: ����Э��ID�͹���ID, ��ѯ�Զ���Ȳ���򡣸ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ�����ܲ�ѯ����
*        Input: EGN_UINT32  ulProtolId:����ѯ�Ĺ����Ӧ��Э��ID:[0x10000000, 0x1FFFFFFF]���� 0.
                                        Ϊ��ʱ��ʾ��ulRuleId����.
*               EGN_UINT32  ulRuleId:����ѯ�Ĺ����Ӧ�Ĺ���ID:[0x10000000, 0x1FFFFFFF]���� 0.
                                        Ϊ��ʱ��ʾ��ulProtolId����.
*        InOut: EGN_UINT32              *pulItemNum:���:�����ѯ���������Ĵ�С<����>.
                                                    ����: ϵͳ�з��ϲ�ѯ���������ʵ�ʸ���
*       Output: EgnUDArithRule pstArithRule����ѯ�������Զ��������Ϣ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ulProtolId��ulRuleId����ͬʱΪ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetArithRuleById
(
    IN      EGN_UINT32               ulProtolId,
    IN      EGN_UINT32               ulRuleId,
    OUT     EgnUDArithRule          *pstArithRule,
    INOUT   EGN_UINT32              *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiUDDelArithRuleById
*      Purpose: ɾ���Զ���Ȳ����
*  Description: ����Э��ID�͹���ID, ɾ���Զ���Ȳ���򡣸ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ���
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ������ɾ������
*        Input: EGN_UINT32  ulProtolId:��ɾ���Ĺ����Ӧ��Э��ID:[0x10000000, 0x1FFFFFFF]
*               EGN_UINT32  ulRuleId:��ɾ���Ĺ����Ӧ�Ĺ���ID:[0x10000000, 0x1FFFFFFF]
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiUDDelArithRuleById
(
    IN  EGN_UINT32               ulProtolId,
    IN  EGN_UINT32               ulRuleId
);

/*******************************************************************************
*    Func Name: EgnApiUDGetSinglePKTRules
*      Purpose: ��ѯһ��������Զ��嵥������
*  Description: 1����ѯһ��������Զ��嵥������,�ò�ѯ��ʽ�����ڿ����Զ�������ܿ���
                 ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�������ҳ�ʼ���������Ч
                2�����pulItemNum�����������Ϊ1024ʱ����ѯ���е�������
                3�����pulItemNum�����������Ϊ0ʱ����ѯʧ��
*        Input: NA
*        InOut: EgnUDSinglePacketRule   *pstUdRuleList:�����ѯ����Ĺ�������<�ǿ�>
                EGN_UINT32              *pulItemNum:����Ϊ��������Ĵ�С�����Ϊϵͳ���Զ��嵥����������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: NA
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetSinglePKTRules
(
    INOUT   EgnUDSinglePacketRule   *pstUdRuleList,
    INOUT   EGN_UINT32              *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiUDGetHttpBearRules
*      Purpose: ��ѯһ��������Զ���HTTP���ع���
*  Description: 1����ѯһ��������Զ���HTTP���ع���,�ò�ѯ��ʽ�����ڿ����Զ�������ܿ���
                 ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�������ҳ�ʼ���������Ч
                2�����pulItemNum�����������Ϊ64ʱ����ѯ����HTTP���ع���
                3�����pulItemNum�����������Ϊ0ʱ����ѯʧ��
*        Input: NA
*        InOut: EgnUDHTTPBearRule   *pstUdRuleList:�����ѯ����Ĺ�������<�ǿ�>
                EGN_UINT32     *pulItemNum:����Ϊ��������Ĵ�С�����Ϊϵͳ���Զ���HTTP���ع�������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: NA
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetHttpBearRules
(
    INOUT   EgnUDHTTPBearRule   *pstUdRuleList,
    INOUT   EGN_UINT32          *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiUDGetArithRules
*      Purpose: ��ѯһ��������Զ���Ȳ����
*  Description: 1����ѯһ��������Զ���Ȳ����,�ò�ѯ��ʽ�����ڿ����Զ�������ܿ���
                 ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�������ҳ�ʼ���������Ч
                2�����pulItemNum�����������Ϊ16ʱ����ѯ���еȲ����
                3�����pulItemNum�����������Ϊ0ʱ����ѯʧ��
*        Input: NA
*        InOut: EgnUDArithRule   *pstUdRuleList:�����ѯ����Ĺ�������<�ǿ�>
                EGN_UINT32       *pulItemNum:����Ϊ��������Ĵ�С�����Ϊϵͳ���Զ���Ȳ��������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: NA
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetArithRules
(
    INOUT   EgnUDArithRule      *pstUdRuleList,
    INOUT   EGN_UINT32          *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiUDGetBehaRules
*      Purpose: ��ѯһ��������Զ�����Ϊͳ�ƹ���
*  Description: 1����ѯһ��������Զ�����Ϊͳ�ƹ���,�ò�ѯ��ʽ�����ڿ����Զ�������ܿ���
                 ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE�������ҳ�ʼ���������Ч
                2�����pulItemNum�����������Ϊ64ʱ����ѯ������Ϊͳ�ƹ���
                3�����pulItemNum�����������Ϊ0ʱ����ѯʧ��
*        Input: NA
*        InOut: EgnUDArithRule   *pstUdRuleList:�����ѯ����Ĺ�������<�ǿ�>
                EGN_UINT32       *pulItemNum:����Ϊ��������Ĵ�С�����Ϊϵͳ���Զ�����Ϊͳ�ƹ�������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: NA
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetBehaRules
(
    INOUT   EgnUDBehaRule       *pstUdRuleList,
    INOUT   EGN_UINT32          *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiUDGetRuleNumByType
*      Purpose: �����Զ���������ͣ���ѯ���������µĹ��������
*  Description: 1�������Զ���������ͣ���ѯ���������µĹ�������������ڿ����Զ�������ܿ��أ����ҳ�ʼ���������Ч
                2����������:EGN_UD_RULE_TYPE_ALL��ʾ��ѯ���е��Զ������ĸ���
*        Input: EGN_UINT32     ulUdRuleType:��Ҫ��ѯ���Զ����������<EGN_UD_RULE_TYPE_SINGLE_PACKET:�Զ��嵥������
                                                                     EGN_UD_RULE_TYPE_BEHA���Զ���ͳ�ƹ���
                                                                     EGN_UD_RULE_TYPE_HTTP_BEAR���Զ���HTTP���ع���
                                                                     EGN_UD_RULE_TYPE_ARITH���Զ���Ȳ����
                                                                     EGN_UD_RULE_TYPE_ALL�������Զ������>
*        InOut: EGN_UINT32     *pulRuleNum:�������µĹ������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32����ѯ�ɹ���ʧ�ܣ���μ�EGN_RET_RESULT_EN��
*      Caution: NA
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetRuleNumByType
(
    IN     EGN_UINT32     ulUdRuleType,
    INOUT  EGN_UINT32     *pulRuleNum
);

/*******************************************************************************
*    Func Name: EgnApiUDIsNeedActiveRule
*      Purpose: ��ѯ�Զ�������Ƿ���Ҫ����
*  Description: ��ѯ�Զ�������Ƿ���Ҫ��������ڿ����Զ�������ܿ��أ����ҳ�ʼ���������Ч
                ����Ҫ����ʱ����Ҫ���㼤��������������Ȼ�ἤ��ʧ��
*        Input: EGN_BOOL    *pbIsNeedActive:�Ƿ���Ҫ���EGN_TRUE��Ҫ���EGN_FALSE����Ҫ����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDIsNeedActiveRule
(
    OUT EGN_BOOL    *pbIsNeedActive
);

/*******************************************************************************
*    Func Name: EgnApiUDDelRuleByType
*      Purpose: �����Զ���������ͣ�ɾ���������µ����й���
*  Description: 1�������Զ���������ͣ�ɾ���������µ����й��򣬱����ڿ����Զ�������ܿ��أ����ҳ�ʼ���������Ч��
                2����������ΪEGN_UD_RULE_TYPE_ALLʱ��ɾ�������Զ������
                3��ɾ���������Ҫ���¼��������ʶ���������Ч
*        Input: EGN_UINT32     ulUdRuleType:��Ҫɾ�����Զ�����������<EGN_UD_RULE_TYPE_SINGLE_PACKET:�Զ��嵥������
                                                                       EGN_UD_RULE_TYPE_BEHA���Զ���ͳ�ƹ���
                                                                       EGN_UD_RULE_TYPE_HTTP_BEAR���Զ���HTTP���ع���
                                                                       EGN_UD_RULE_TYPE_ARITH���Զ���Ȳ����
                                                                       EGN_UD_RULE_TYPE_ALL�������Զ������>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32����ѯ�ɹ���ʧ�ܣ���μ�EGN_RET_RESULT_EN��
*      Caution: NA
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDDelRuleByType
(
    IN     EGN_UINT32     ulUdRuleType
);

/*******************************************************************************
*    Func Name: EgnApiUDDelRuleByProtolID
*      Purpose: ɾ��ָ��Э���µ������Զ������
*  Description: 1������ָ����Э��ID���������е��Զ�������Э�鼯�ϣ�������ҵ���
                    ����Э���µĹ�����Ϊ��Ҫɾ��������Ҳ�������֪ͨ�û���Э�鲻���ڡ�
                2���ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ��أ�����EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE����
                    �ҳ�ʼ���ɹ������ɾ������
*        Input: EGN_UINT32  ulProtolId:��ɾ��Э���ID:[0x10000000, 0x1FFFFFFF]
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬Э�鲻���ڷ���EGN_RET_UD_PROTOCOL_ID_NO_EXIST��
                ����������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiUDDelRuleByProtolID
(
    IN  EGN_UINT32               ulProtolId
);

/*******************************************************************************
*    Func Name: EgnApiUDGetBehaRuleById
*      Purpose: ��ѯ�Զ���ͳ�ƹ���
*  Description: ����Э��ID�͹���ID, ��ѯ�Զ���ͳ�ƹ��򡣸ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ��غ�ͳ��ʶ�𿪹�
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE;EgnInitCfgParam.bStatInspectSwitchΪEGN_TRUE����
                    �ҳ�ʼ���ɹ�����ܲ�ѯ����
*        Input: EGN_UINT32  ulProtolId:����ѯ�Ĺ����Ӧ��Э��ID:[0x10000000, 0x1FFFFFFF]���� 0.
                                        Ϊ��ʱ��ʾ��ulRuleId����.
*               EGN_UINT32  ulRuleId:����ѯ�Ĺ����Ӧ�Ĺ���ID:[0x10000000, 0x1FFFFFFF]���� 0.
                                        Ϊ��ʱ��ʾ��ulRuleId����.
*        InOut: EGN_UINT32  *pulItemNum:���:�����ѯ���������Ĵ�С<����>
                                        ����: ϵͳ�з��ϲ�ѯ���������ʵ�ʸ���
*       Output: EgnUDBehaRule pstBehaRule����ѯ�������Զ��������Ϣ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ulProtolId��ulRuleId����ͬʱΪ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiUDGetBehaRuleById
(
    IN      EGN_UINT32       ulProtolId,
    IN      EGN_UINT32       ulRuleId,
    OUT     EgnUDBehaRule   *pstBehaRule,
    INOUT   EGN_UINT32      *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiUDDelBehaRuleById
*      Purpose: ɾ���Զ���ͳ�ƹ���
*  Description: ����Э��ID�͹���ID, ɾ���Զ���ͳ�ƹ��򡣸ýӿڱ����ڳ�ʼ��ʱ�����Զ�������ܿ��غ�ͳ��ʶ�𿪹�
                    ������EgnInitCfgParam.bUDRuleSwitchΪEGN_TRUE;EgnInitCfgParam.bStatInspectSwitchΪEGN_TRUE����
                    �ҳ�ʼ���ɹ������ɾ������
*        Input: EGN_UINT32  ulProtolId:��ɾ���Ĺ����Ӧ��Э��ID:[0x10000000, 0x1FFFFFFF]
*               EGN_UINT32  ulRuleId:��ɾ���Ĺ����Ӧ�Ĺ���ID:[0x10000000, 0x1FFFFFFF]
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiUDDelBehaRuleById
(
    IN  EGN_UINT32               ulProtolId,
    IN  EGN_UINT32               ulRuleId
);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __EGN_API_USER_DEFINE_RULE_H__ */

