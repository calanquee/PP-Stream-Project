/*
 ******************************************************************************
 ��Ȩ���� (C), 2008-2009, ��Ϊ�������޹�˾
 ******************************************************************************
  �� �� ��   : egnapingfwuserdefineapp.h
  �� �� ��   : ����
  ��    ��   : EGN��Ŀ��
  ��������   : 2013��01��10��
  ����޸�   :
  ��������   : �����궨��
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2013��01��10��
    ��    ��   : EGN��Ŀ��
    �޸�����   : �����ļ�

******************************************************************************/
/**@file  egnapingfwuserdefineapp.h
  *    �����궨��
*******************************************************/
/**
 * @defgroup egn  EGN�Զ������ģ���API
 */

#ifndef __EGN_API_NGFW_USER_DEFINE_APP_H__
#define __EGN_API_NGFW_USER_DEFINE_APP_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/*MACRO< NGFW�Զ���Ӧ����֧�ֵ���󳤶� >*/
#define EGN_NGFW_UD_APP_NAME_LEN_MAX  32

/*MACRO< NGFW�Զ���Ӧ��֧�ֵ�����ģ����󳤶� >*/
#define EGN_NGFW_UD_MODEL_NAME_LEN_MAX  32

/*MACRO< NGFW�Զ��������֧�ֵ���󳤶� >*/
#define EGN_NGFW_UD_RULE_NAME_LEN_MAX  32

/*MACRO< NGFW�Զ����������֧�ֵ���󳤶� >*/
#define EGN_NGFW_UD_RULE_DESC_LEN_MAX  128

/*MACRO< NGFW�Զ���Ӧ������֧�ֵ���󳤶� >*/
#define EGN_NGFW_UD_APP_DESC_LEN_MAX  128

/*MACRO< NGFW�Զ��������֧�ֵ�ip���������� >*/
#define EGN_NGFW_UD_RULE_IP_COND_MAX  4

/*MACRO< NGFW�Զ��������֧�ֵ�port���������� >*/
#define EGN_NGFW_UD_RULE_PORT_COND_MAX  4

/*MACRO< NGFW�Զ��������֧�ֵ�ģʽ����������С���� >*/
#define EGN_NGFW_UD_RULE_PATTERN_COND_LEN_MIN  3

/*MACRO< NGFW�Զ��������֧�ֵ�ģʽ����������󳤶� >*/
#define EGN_NGFW_UD_RULE_PATTERN_COND_LEN_MAX  128

/* ֧�ֵ�Ngfw�Զ���Ӧ�õ�AppId��Сֵ >*/
#define EGN_NGFW_UD_APP_ID_MIN  60000

/*ENUM< NGFW�Զ������ļ�ⷽ�� >*/
typedef enum
{
    EGN_NGFW_CHECK_DIR_BEGIN = EGN_EN_INVALID,
    EGN_NGFW_CHECK_DIR_REQ   = 0,   /* ���� */
    EGN_NGFW_CHECK_DIR_RES   = 1,   /* ��Ӧ */
    EGN_NGFW_CHECK_DIR_BOTH  = 2,   /* ˫�� */
    EGN_NGFW_CHECK_DIR_END,

    EGN_NGFW_CHECK_DIR_BOTTOM = EGN_EN_BUTT
}EGN_NGFW_CHECK_DIR_EN;

/*ENUM< NGFW�Զ�������ʶ��ģʽ >*/
typedef enum
{
    EGN_NGFW_INSPECT_MOD_BEGIN = EGN_EN_INVALID,
    EGN_NGFW_INSPECT_MOD_NONE   = 0,   /* δ֪����ʼ״̬ */
    EGN_NGFW_INSPECT_MOD_PACKET = 1,   /* ��ʽʶ�� */
    EGN_NGFW_INSPECT_MOD_FLOW   = 2,   /* ��ʽʶ�� */
    EGN_NGFW_INSPECT_MOD_END,

    EGN_NGFW_INSPECT_MOD_BOTTOM = EGN_EN_BUTT
}EGN_NGFW_INSPECT_MOD_EN;

/*ENUM< NGFW�Զ�������ģʽ������ >*/
typedef enum
{
    EGN_NGFW_PATTERN_TYPE_BEGIN = EGN_EN_INVALID,
    EGN_NGFW_PATTERN_TYPE_NONE  = 0,   /* δ֪����ʼ״̬ */
    EGN_NGFW_PATTERN_TYPE_STR   = 1,   /* �ַ��� */
    EGN_NGFW_PATTERN_TYPE_PCRE  = 2,   /* ���� */
    EGN_NGFW_PATTERN_TYPE_END,

    EGN_NGFW_PATTERN_TYPE_BOTTOM = EGN_EN_BUTT
}EGN_NGFW_PATTERN_TYPE_EN;

/*ENUM< Ngfw�Զ���Ӧ�õ�״̬ >*/
typedef enum
{
    EGN_NGFW_APP_STATUS_BEGIN               = EGN_EN_INVALID,
    EGN_NGFW_APP_STATUS_INIT                = 0,   /* ��ʼ��       */
    EGN_NGFW_APP_STATUS_MODIFIED_NOTACTIVED = 1,   /* �޸�,δ����  */
    EGN_NGFW_APP_STATUS_DELETE_NOTACTIVED   = 2,   /* ɾ��, δ���� */
    EGN_NGFW_APP_STATUS_ACTIVE              = 3,   /* ����         */
    EGN_NGFW_APP_STATUS_END,
    EGN_NGFW_APP_STATUS_BOTTOM              = EGN_EN_BUTT
} EGN_NGFW_APP_STATUS_EN;

/*ENUM<Ngfw�Զ���Ӧ�õĲ�ѯ��ʽ> */
typedef enum
{
    EGN_NGFW_APP_QUERY_MODEL_BEGIN           = EGN_EN_INVALID,
    EGN_NGFW_APP_QUERY_MODEL_ONLY_ACTIVED    = 0,   /* ֻ��ѯ����APP         */
    EGN_NGFW_APP_QUERY_MODEL_ONLY_NOTACTIVED = 1,   /* ��ѯδ�����APP       */
    EGN_NGFW_APP_QUERY_ALL                   = 2,   /* ��ѯ�����δ�����APP */
    EGN_NGFW_APP_QUERY_MODEL_END,
    EGN_NGFW_APP_QUERY_MODEL_BOTTOM          = EGN_EN_BUTT
} EGN_NGFW_APP_QUERY_MODEL_EN;

/*ENUM<Ӧ�������ֶ����� >*/
typedef enum
{
    EGN_NGFW_APP_ATTR_TYPE_BEGIN           = EGN_EN_INVALID,
    EGN_NGFW_APP_ATTR_TYPE_CATEGORY        = 0,   /* �������   */
    EGN_NGFW_APP_ATTR_TYPE_DATAMODEL       = 1,   /* ����ģ��   */
    EGN_NGFW_APP_ATTR_TYPE_RISK            = 2,   /* ���յȼ�   */
    EGN_NGFW_APP_ATTR_TYPE_DESC            = 3,   /* ��Ӣ������ */
    EGN_NGFW_APP_ATTR_TYPE_ALL             = 4,   /* �����ֶ�   */
    EGN_NGFW_APP_ATTR_TYPE_END,
    EGN_NGFW_APP_ATTR_TYPE_BOTTOM          = EGN_EN_BUTT
}EGN_NGFW_APP_ATTR_TYPE_EN;

/*ENUM< NGFW�Զ�������еĳ�Ա���ͣ�����ɾ�����޸� >*/
typedef enum
{
    EGN_NGFW_UD_RULE_CONTENT_TYPE_BEGIN         = EGN_EN_INVALID,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_TRANS_TYPE    = 1,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_IPV4          = 2,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_IPV6          = 3,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_PORT          = 4,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_SIGNATURE     = 5,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_DESC          = 6,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_IPV4_ALL      = 7,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_IPV6_ALL      = 8,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_PORT_ALL      = 9,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_ALL           = 10,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_END,
    EGN_NGFW_UD_RULE_CONTENT_TYPE_BOTTOM        = EGN_EN_BUTT
}EGN_NGFW_UD_RULE_CONTENT_TYPE_EN;

/*STRUCT< NGFW�Զ���Ӧ����Ϣ >*/
typedef struct _EgnNgfwUDApp
{
    EGN_UINT32  ulAppId;                                     /* Ӧ��ID */
    EGN_UINT16  usCategoryId;                                /* ����ID */
    EGN_UINT16  usSubCategoryId;                             /* С��ID */
    EGN_UINT16  usVfwId;                                     /* �������ǽID */

    EGN_UINT16  usEnable:1;                                  /* ʹ�ܱ�ʶ */
    EGN_UINT16  usIsTransportSig:1;                          /* �Ƿ����Ӧ�ã�Ĭ�ϣ�NO */

    EGN_UINT16  usRiskValue:5;                               /* ���յȼ� */
    EGN_UINT16  usRiskType:7;                                /* �������� */

    EGN_UINT16  ucStatus:3;                                  /* Ӧ��״̬�����δ���� */
    EGN_UCHAR   aucReserved1[2];

    EGN_UCHAR   aucName[EGN_NGFW_UD_APP_NAME_LEN_MAX + 1];   /* Ӧ���� */
    EGN_UCHAR   aucDataModel[EGN_NGFW_UD_MODEL_NAME_LEN_MAX + 1];   /* ����ģ�� */

    EGN_UCHAR   aucAppDesc[EGN_NGFW_UD_APP_DESC_LEN_MAX + 1]; /* APP���� */
    EGN_UCHAR   aucReserved2[1];

#ifdef EGN_64
    EGN_UCHAR   aucReserved3[4];
#endif
} EgnNgfwUDApp;

/*STRUCT< NGFW�Զ���Ӧ����Ϣ >*/
typedef struct _EgnNgfwUDAppS
{
    EgnNgfwUDApp stNotActivedApp;    /* δ�����App */
    EgnNgfwUDApp stActivedApp;       /* �Ѽ����App */
}EgnNgfwUDAppS;

/*STRUCT< NGFW�Զ�������е�signature��Ϣ >*/
typedef struct _EgnNgfwUDSignature
{
    EGN_UCHAR  ucPatternLen;    /* �ַ��������򳤶ȣ���С����ΪEGN_NGFW_UD_RULE_PATTERN_COND_LEN_MIN, ��󳤶�ΪEGN_NGFW_UD_RULE_PATTERN_COND_LEN_MAX */
    EGN_UCHAR  ucMode;          /* ʶ��ģʽ����ʶ����ʶ��ģʽ��������EGN_NGFW_INSPECT_MOD_EN */
    EGN_UCHAR  ucDir;           /* ģʽ���ļ�ⷽ�򣬶���ʽʶ����Ч��������Ӧ���������Ӧ����EGN_NGFW_CHECK_DIR_EN */
    EGN_UCHAR  ucPatternType;   /* �ַ����������򣬼�EGN_NGFW_PATTERN_TYPE_EN */
#ifdef EGN_64
    EGN_UCHAR  aucReserved[4];  /* 8�ֽڶ��뱣�� */
#endif
    EGN_UCHAR  aucPattern[EGN_NGFW_UD_RULE_PATTERN_COND_LEN_MAX]; /* ģʽ������ucPatternLenΪ���� */
} EgnNgfwUDSignature;

/*ENUM< ĳ��NGFW�Զ������Ĵ������Ͷ��� >*/
typedef enum
{
    EGN_NGFW_TRANS_TYPE_BEGIN = EGN_EN_INVALID,
    EGN_NGFW_TRANS_TYPE_ANY   = 0X0,    /* δָ�����ͣ�TCP��UDP */
    EGN_NGFW_TRANS_TYPE_TCP   = 0x6,    /* TCP  ���� */
    EGN_NGFW_TRANS_TYPE_UDP   = 0x11,   /* UDP  ���� */
    EGN_NGFW_TRANS_TYPE_END,

    EGN_NGFW_TRANS_TYPE_BOTTOM = EGN_EN_BUTT
}EGN_NGFW_TRANS_TYPE_EN;

/*ENUM< NGFW�Զ������ķ��յȼ����� >*/
typedef enum
{
    EGN_NGFW_APP_RISK_TYPE_VALUE_BEGIN           =  EGN_EN_INVALID,
    EGN_NGFW_APP_RISK_TYPE_VALUE_UNKNOWN         =  0x0000U,
    EGN_NGFW_APP_RISK_TYPE_VALUE_EXPLOITABLE     =  0x0001U,
    EGN_NGFW_APP_RISK_TYPE_VALUE_MAL_VEHICLE     =  0x0002U,
    EGN_NGFW_APP_RISK_TYPE_VALUE_PROD_LOSS       =  0x0004U,
    EGN_NGFW_APP_RISK_TYPE_VALUE_DATA_LEAK       =  0x0008U,
    EGN_NGFW_APP_RISK_TYPE_VALUE_BANDWIDTH       =  0x0010U,
    EGN_NGFW_APP_RISK_TYPE_VALUE_EVASIVE         =  0x0020U,
    EGN_NGFW_APP_RISK_TYPE_VALUE_TUNNELING       =  0x0040U,
    EGN_NGFW_APP_RISK_TYPE_VALUE_END,
    EGN_NGFW_APP_RISK_TYPE_VALUE_BOTTOM          = EGN_EN_BUTT
}EGN_NGFW_APP_RISK_TYPE_VALUE_EN;

/*STRUCT< NGFW�Զ��������Ϣ >*/
typedef struct _EgnNgfwUDRule
{
    EGN_UCHAR  aucName[EGN_NGFW_UD_RULE_NAME_LEN_MAX + 4];    /* �������ƣ���Ч����Ϊ32����\0��Ϊ������ */
    EGN_UINT32 ulAppID;           /* Ӧ��ID */
    EGN_UINT32 ulRuleId;          /* ����ID */
    EGN_UINT16 usVfwId;           /* �������ǽID */
    EGN_UCHAR  ucTransType;       /* �����Э�飬��ӦEGN_NGFW_TRANS_TYPE_EN */
    EGN_UCHAR  ucDescLen;         /* �����������ȣ���󳤶�ΪEGN_NGFW_UD_RULE_DESC_LEN_MAX */
    EGN_UCHAR  ucIPNum;           /* IP������������ΪEGN_NGFW_UD_RULE_IP_COND_MAX */
    EGN_UCHAR  ucPortNum;         /* �˿ڸ�����������ΪEGN_NGFW_UD_RULE_PORT_COND_MAX */
    EGN_UCHAR  ucNeedAddPeerList; /* �Ƿ��Ҫ�����·���0����Ҫ��1��Ҫ*/
    EGN_UCHAR  ucReserved;        /* �ֽڶ��� */
#ifdef EGN_64
    EGN_UCHAR  aucReserved2[4];   /* �ֽڶ��� */
#endif
    EgnNgfwUDSignature stSignature; /* signature��Ϣ */
    EgnIpAddrCond      astIPCond[EGN_NGFW_UD_RULE_IP_COND_MAX];      /* ip�����б� */
    EgnPortCond        astPortCond[EGN_NGFW_UD_RULE_PORT_COND_MAX];  /* �˿������б�ע��:ֻ����Ŀ�Ķ˿� */
    EGN_UCHAR          aucDesc[EGN_NGFW_UD_RULE_DESC_LEN_MAX];       /* ��������ucDescLenΪ���ȣ���󳤶�ΪEGN_NGFW_UD_RULE_DESC_LEN_MAX */
} EgnNgfwUDRule;

/*******************************************************************************
*    Func Name: EgnApiNgfwUDAddApp
*      Purpose: ���NGFW�Զ���Ӧ��
*  Description: ���NGFW�Զ���Ӧ�ã����սṹ�巽ʽ����Զ���Ӧ�ã�������������Ч��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲������Ӧ�á�
*        Input: NA
*        InOut: EgnNgfwUDApp  *pstNgfwUDApp:�Զ���Ӧ�ýṹ��ָ��<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1��EGN�ڲ�Ϊ�Զ���Ӧ�÷���ID��ͨ���޸Ĳ��������ulAppId������AppID��Χ:[0x10000000, 0x1FFFFFFF]
                2��֧�ֵ��Զ���Ӧ��������� 1024
                3��֧�ֵ��Զ���Ӧ��������󳤶�Ϊ39
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDAddApp
(
   INOUT     EgnNgfwUDApp  *pstNgfwUDApp
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetAppState
*      Purpose: ��ѯNGFW�Զ���Ӧ��״̬
*  Description: ����AppId��ѯ��Ӧ�Զ���Ӧ�õ�״̬��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܲ�ѯӦ��״̬��
*        Input: EGN_UINT32   ulAppId:   AppId
*        InOut:
*       Output: EGN_UINT16  *pusStatus: Ҫ��ѯ��Ӧ�õ�״̬<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: Ӧ��״ֵ̬�ĺ�����μ�EGN_NGFW_APP_STATUS_EN
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetAppState
(
   IN   EGN_UINT32  ulAppId,
   OUT  EGN_UINT16 *pusStatus
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetAppIDByName
*      Purpose: ��ѯ�Զ���Ӧ�õ�Appid
*  Description: ����Ӧ�����Լ��������ǽID��ѯ��Ӧ�Զ���Ӧ�õ�AppId��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ
*        Input: EGN_UCHAR   *pucAppName:   �Զ���Ӧ����
                EGN_UINT16   usVfwId:      �������ǽID
*        InOut: EGN_UINT32  *pulAppId:     ��ѯ���:AppId
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN�
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetAppIDByName
(
    IN    EGN_UCHAR          *pucAppName,      /* �Զ���Ӧ����  */
    IN    EGN_UINT16          usVfwId,         /* �������ǽID  */
    INOUT EGN_UINT32         *pulAppId         /* ��ѯ���AppId */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetCommitedAppIDByName
*      Purpose: ��ѯ����Ч���Զ���Ӧ�õ�Appid
*  Description: ����Ӧ�����Լ��������ǽID��ѯ����Ч���Զ���Ӧ�õ�AppId��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ��
*        Input:   EGN_UCHAR   *pucAppName:   �Զ���Ӧ����<�ǿ�>
                  EGN_UINT16   usVfwId:      �������ǽID
*        InOut:   EGN_UINT32  *pulAppId:     ��ѯ���:AppId<�ǿ�>
*       Output:
*       Return:   EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetCommitedAppIDByName
(
    IN    EGN_UCHAR          *pucAppName,      /* �Զ���Ӧ����  */
    IN    EGN_UINT16          usVfwId,         /* �������ǽID  */
    INOUT EGN_UINT32         *pulAppId         /* ��ѯ���AppId */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetAppCount
*      Purpose: ��ѯ�Զ���Ӧ������
*  Description: �����������ǽID��ѯδ������Զ���Ӧ�������Լ��Ѽ�����Զ���Ӧ��������
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ��
*        Input: EGN_UINT16   usVfwId:              �������ǽID
*       Output: EGN_UINT32  *pulAppNum:            ����App����<�ǿ�>
                EGN_UINT32  *pulNotActivedAppNum:  δ�����App����<�ǿ�>
                EGN_UINT32  *pulActivedAppNum:     �Ѿ������App����<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetAppCount
(
    IN   EGN_UINT16          usVfwId,               /* �������ǽID      */
    OUT  EGN_UINT32         *pulAppNum,             /* ����App����       */
    OUT  EGN_UINT32         *pulNotActivedAppNum,   /* δ�����App����   */
    OUT  EGN_UINT32         *pulActivedAppNum       /* �Ѿ������App���� */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetAppInfoByID
*      Purpose: ͨ��AppId�����Զ���App��Ϣ
*  Description: ͨ��AppId�����Զ���App��Ϣ
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNGFWUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ��
*        Input: EGN_UINT32    ulAppId:       AppId
*       Output: EgnNgfwUDApp  *pstAppInfo:    App��Ϣ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetAppInfoByID
(
    IN     EGN_UINT32         ulAppId,      /* AppId   */
    INOUT  EgnNgfwUDApp      *pstAppInfo    /* App��Ϣ */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetCommitedAppInfoByID
*      Purpose: ͨ��AppId���Ҽ���״̬�µ��Զ���App��Ϣ
*  Description: ͨ��AppId���Ҽ���״̬�µ��Զ���App��Ϣ��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNGFWUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ��
*        Input: EGN_UINT32    ulAppId:        AppId
*       Output: EgnNgfwUDApp  *pstAppInfo:    App��Ϣ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetCommitedAppInfoByID
(
    IN     EGN_UINT32         ulAppId,      /* AppId */
    INOUT  EgnNgfwUDApp      *pstAppInfo    /* App��Ϣ */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetAppInfoByName
*      Purpose: ͨ��Ӧ�����Լ�����ǽID�������Զ���App��Ϣ
*  Description: ͨ��Ӧ�����Լ�����ǽID�������Զ���App��Ϣ��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ��
*        Input: EGN_UCHAR    *pucAppName  :    �Զ���Ӧ����<�ǿ�>
                EGN_UINT16    usVfwId     :    �������ǽID
*        InOut: EgnNgfwUDApp *pstAppInfo  :    App��Ϣ<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetAppInfoByName
(
    IN     EGN_UCHAR     *pucAppName,  /* �Զ���Ӧ���� */
    IN     EGN_UINT16     usVfwId,     /* �������ǽID */
    INOUT  EgnNgfwUDApp  *pstAppInfo   /* App��Ϣ      */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetAllAppInfo
*      Purpose: ����ͬһ����ǽ�µ������Զ���Ӧ����Ϣ
*  Description: ����ͬһ����ǽ�µ������Զ���Ӧ����Ϣ�����ؽ����δ�����App��Ϣ�����Ѽ����App��Ϣ��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ��
*        Input: EGN_UINT16                     usVfwId             :  �������ǽID
                EGN_UINT32                     ulQueryFlag         :  ��ѯģʽ<EGN_NGFW_APP_QUERY_MODEL_EN>
*        InOut: EgnNgfwUDAppS                 *pstUserDefineAppS   :  App��Ϣ����<�ǿ�>
                EGN_UINT32                    *pulItemNum          :  App��Ϣ�����С<�ǿ�>
                EGN_UINT32                    *pulNotActivedAppNum :  δ�����App����<�ǿ�>
                EGN_UINT32                    *pulActivedAppNum    :  �Ѿ������App����<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetAllAppInfo
(
    IN    EGN_UINT16      usVfwId,              /* �������ǽID */
    IN    EGN_UINT32      ulQueryFlag,          /* ��ѯģʽ���ǲ鼤��Ļ���δ����Ļ������߶��� */
    INOUT EgnNgfwUDAppS  *pstUserDefineAppS,    /* App��Ϣ���� */
    INOUT EGN_UINT32     *pulItemNum,           /* App��Ϣ�����С */
    INOUT EGN_UINT32     *pulNotActivedAppNum,  /* δ�����App����  */
    INOUT EGN_UINT32     *pulActivedAppNum      /* �Ѿ������App���� */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDModifyApp
*      Purpose: �޸��Զ���Ӧ�õ���Ϣ(Ӧ��������)
*  Description: �޸����Ҫ���������Ч
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ�޸ġ�
*        Input: EgnNgfwUDApp    *pstNgfwUDApp       :      Ҫ�޸ĵ�Ӧ��<�ǿ�>
                EGN_UINT32      ulModifyAppType     :      �޸�Ӧ�õ��ֶ�<��ӦEGN_NGFW_APP_ATTR_TYPE_ENö��>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDModifyApp
(
    IN    EgnNgfwUDApp   *pstNgfwUDApp,
    IN    EGN_UINT32      ulModifyAppType
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDModifyAppName
*      Purpose: �޸��Զ���Ӧ����
*  Description: �޸��Զ���Ӧ�������޸����Ҫ���������Ч��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ�޸ġ�
*        Input: EGN_UINT32    ulAppId          :    Ҫ�޸ĵ�Ӧ�õ�ID
                EGN_UCHAR    *pucNewAppName    :    Ӧ����<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDModifyAppName
(
    IN     EGN_UINT32 ulAppId,         /* AppId */
    IN     EGN_UCHAR *pucNewAppName    /* �µ��Զ���Ӧ����  */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDDelAllApps
*      Purpose: ɾ��ͬһ����ǽID�µ������Զ���Ӧ��
*  Description: ɾ��ͬһ����ǽID�µ������Զ���Ӧ�ã�ɾ����Ҫ���������Ч��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼɾ����
*        Input: EGN_UINT16      usVfwId : �������ǽID
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDDelAllApps
(
    IN     EGN_UINT16 usVfwId   /* �������ǽID  */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDDeleteApp
*      Purpose: ɾ��һ���Զ���Ӧ�û���ɾ��һ���Զ���Ӧ�õ�ĳ���ֶ�(�޸�ΪĬ��ֵ)
*  Description: ɾ��һ���Զ���Ӧ�û���ɾ��һ���Զ���Ӧ�õ�ĳ���ֶΣ�ɾ����Ҫ���������Ч��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼɾ����
*        Input: EgnNgfwUDApp   *pstNgfwUDApp        :      Ҫɾ����Ӧ��<�ǿ�>
                EGN_UINT32      ulDelAttrAppType    :      Ҫɾ��Ӧ�õ��ֶ�<��ӦEGN_NGFW_APP_ATTR_TYPE_ENö��>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDDeleteApp
(
    IN EGN_CONST EgnNgfwUDApp   *pstNgfwUDApp,
    IN           EGN_UINT32      ulDelAttrAppType
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDMngIncAppRefCount
*      Purpose: �����Զ���Ӧ�õ����ü���(������ʹ��)
*  Description: �����Զ���Ӧ�õ����ü�����
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ�޸ġ�
*        Input: EGN_UCHAR   *pucModuleName  : ����ģ����<�ǿ�>
                EGN_UINT32   ulAppId        : AppId
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDMngIncAppRefCount
(
    IN EGN_CONST EGN_UCHAR     *pucModuleName,    /* ����ģ���� */
    IN           EGN_UINT32     ulAppId           /* AppId */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDNgeIncAppRefCount
*      Purpose: �����Զ���Ӧ�õ����ü���(NGEƽ��ʹ��)
*  Description: �����Զ���Ӧ�õ����ü�����
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ�޸�
*        Input: EGN_UCHAR   *pucModuleName  : ����ģ����<�ǿ�>
                EGN_UINT32   ulAppId        : AppId
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDNgeIncAppRefCount
(
    IN EGN_CONST EGN_UCHAR  *pucModuleName,    /* ����ģ���� */
    IN           EGN_UINT32  ulAppId           /* AppId */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDMngDecAppRefCount
*      Purpose: �����Զ���Ӧ�õ����ü���(����ƽ��ʹ��)
*  Description: �����Զ���Ӧ�õ����ü�����
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ�޸�
*        Input: EGN_UCHAR   *pucModuleName :  ����ģ����<�ǿ�>
                EGN_UINT32  ulAppId        :  AppId
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDMngDecAppRefCount
(
    IN EGN_CONST EGN_UCHAR  *pucModuleName,    /* ����ģ���� */
    IN           EGN_UINT32  ulAppId           /* AppId */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDNgeDecAppRefCount
*      Purpose: �����Զ���Ӧ�õ����ü���(Ngeƽ��ʹ��)
*  Description: �����Զ���Ӧ�õ����ü�����
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ�޸�
*        Input: EGN_UCHAR   *pucModuleName  : ����ģ����<�ǿ�>
                EGN_UINT32  ulAppId         : AppId
*       Output:
*       Return:   EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDNgeDecAppRefCount
(
    IN EGN_CONST EGN_UCHAR     *pucModuleName,    /* ����ģ���� */
    IN           EGN_UINT32     ulAppId           /* AppId */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDNeedCommit
*      Purpose: �жϷ���ǽ���Ƿ�����Ҫ�ύ���Զ���Ӧ��
*  Description: �����������ǽID���жϸ÷���ǽ���Ƿ�����Ҫ�ύ���Զ���Ӧ�á�
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ��
*        Input: EGN_UINT16   usVfwId      : �������ǽID
*        InOut: EGN_BOOL    *bIsNeedCommit: �Ƿ���Ҫ�ύ <1:��Ҫ�ύ
                                                          0:����Ҫ�ύ>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDNeedCommit
(
    IN    EGN_UINT16  usVfwId,        /* �������ǽID */
    INOUT EGN_BOOL   *pbIsNeedCommit  /* �Ƿ���Ҫ�ύ */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDNeedReCompile
*      Purpose: �ж����з���ǽ���Ƿ�����Ҫ���±�����Զ���Ӧ��
*  Description: �ж����з���ǽ���Ƿ�����Ҫ���±�����Զ���Ӧ��,�����µ��Զ���Ӧ����Ҫ����ʱ����Ҫ���±��롣
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ��ѯ��
*        InOut: EGN_BOOL  *pbIsNeedReCompile       �Ƿ���Ҫ����<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDNeedReCompile
(
    INOUT EGN_BOOL *pbIsNeedReCompile  /* �Ƿ���Ҫ���� */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDSetCompileFlag
*      Purpose: �����������ǽ�Ƿ��ύ�����־
*  Description: �����������ǽ�Ƿ��ύ�����־��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲��ܿ�ʼ�޸�
*        Input: EGN_UCHAR  *paucCompFlagArray : ����������<�ǿ�>
                EGN_UINT32  ulArraySize       : �����С
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDSetCompileFlag
(
    IN  EGN_UCHAR  *paucCompFlagArray,  /* ���������� */
    IN  EGN_UINT32  ulArraySize         /* �����С */
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDAddAppForceID
*      Purpose: ����Զ���Ӧ����Ϣ��ǿ��ָ��Ӧ��ID
*  Description: ���սṹ�巽ʽ����Զ���Ӧ�ã�������������Ч���ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲������Ӧ��
                    �ýӿڽ���ϵͳ����������ʹ�á�
*        Input: EgnNgfwUDApp  *pstNgfwUDApp:�Զ���Ӧ�ýṹ��ָ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1��AppID��Χ:[0x10000000, 0x1FFFFFFF]
                2��֧�ֵ��Զ���Ӧ��������� 1024
                3��֧�ֵ��Զ���Ӧ��������󳤶�Ϊ39
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDAddAppForceID
(
   IN EgnNgfwUDApp *pstNgfwUDApp
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDNgeActiveAllApps
*      Purpose: ���������Զ���Ӧ��( ��Nge��ʹ��)
*  Description: ���������Զ���Ӧ�á�
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲������Ӧ�á�
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDNgeActiveAllApps
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDMngActiveAllApps
*      Purpose: ���������Զ���Ӧ��( ����������ʹ��)
*  Description: ���������Զ���Ӧ��
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲������Ӧ�á�
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDMngActiveAllApps
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDNgeActiveRule
*      Purpose: ���������Զ���Ӧ���µĹ���(Ngeƽ��ʹ��)
*  Description: ���������Զ���Ӧ���µĹ���
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲������Ӧ�á�
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDNgeActiveRule
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDMngActiveRule
*      Purpose: ���������Զ���Ӧ���µĹ���(����ƽ��ʹ��)
*  Description: ���������Զ���Ӧ���µĹ���
                �ýӿڱ����ڳ�ʼ��ʱ����NGFW�Զ��幦�ܿ���
                    ������EgnInitCfgParam.bNgfwUserDefineSwitchΪEGN_TRUE�����ҳ�ʼ���ɹ��󣬲������Ӧ�á�
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDMngActiveRule
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDAddRule
*      Purpose: ����Զ������
*  Description: �����Զ���Ӧ��ID������Զ������
                �����ʼ����ɣ���֪ʶ��������Ϣ����󣬲��ܵ��á�
*        Input: EGN_UINT32      ulAppId        :  ����ӵ��Զ�������Ӧ���Զ���Ӧ��
                EgnNgfwUDRule  *pstUdRule      :  ����ӵ��Զ������<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDAddRule
(
    IN   EGN_UINT32     ulAppId,
    IN   EgnNgfwUDRule *pstUdRule
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDModifyRule
*      Purpose: �޸��Զ������
*  Description: �����Զ���Ӧ��ID���Զ�������޸����ͣ��޸���Ӧ���Զ������
                �����ʼ����ɣ���֪ʶ��������Ϣ����󣬲��ܵ��á�
*        Input: EGN_UINT32     ulAppId      : ���޸ĵ��Զ�������Ӧ���Զ���Ӧ��
                EgnNgfwUDRule  *pstUdRule   : ���޸ĵ��Զ������<�ǿ�>
                EGN_UINT32     ulModifyType : �޸ĵ�����<EGN_NGFW_UD_RULE_CONTENT_TYPE_EN>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDModifyRule
(
    IN   EGN_UINT32     ulAppId,
    IN   EgnNgfwUDRule *pstUdRule,
    IN   EGN_UINT32     ulModifyType
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDModifyRuleName
*      Purpose: �޸Ĺ�������
*  Description: �����Զ���Ӧ��ID���Զ����������֣��޸��Զ��������Ϊ�µ����֡�
                �����ʼ����ɣ���֪ʶ��������Ϣ����󣬲��ܵ��á�
*        Input: EGN_UINT32     ulAppId    : �Զ���Ӧ��ID
                EGN_UCHAR     *pucOldName : ���޸ĵ��Զ�����������<�ǿ�>
                EGN_UCHAR     *pucNewName : �޸ĺ���Զ�����������<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDModifyRuleName
(
    IN   EGN_UINT32     ulAppId,
    IN   EGN_UCHAR     *pucOldName,
    IN   EGN_UCHAR     *pucNewName
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDDelAllRule
*      Purpose: ɾ�������Զ������
*  Description: �����Զ���Ӧ��ID��ɾ�����Ӧ�������Զ������
                �����ʼ����ɣ���֪ʶ��������Ϣ����󣬲��ܵ��á�
*        Input: EGN_UINT32     ulAppId   :  �Զ���Ӧ��ID
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDDelAllRule
(
    IN   EGN_UINT32     ulAppId
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDDelOneRule
*      Purpose: ɾ���Զ������
*  Description: �����Զ���Ӧ��ID���Զ�����򣬸���ɾ�����ͣ�ɾ�����Ӧ���Զ������
                �����ʼ����ɣ���֪ʶ��������Ϣ����󣬲��ܵ���
*        Input: EGN_UINT32      ulAppId        :  ��ɾ�����Զ�������Ӧ���Զ���Ӧ��ID
*               EgnNgfwUDRule  *pstUdRule      :  ��ɾ�����Զ������<�ǿ�>
*               EGN_UINT32      ulDeleteType   :  ɾ��������<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDDelOneRule
(
    IN   EGN_UINT32     ulAppId,
    IN   EgnNgfwUDRule *pstUdRule,
    IN   EGN_UINT32     ulDeleteType
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetRuleNum
*      Purpose: ���ҹ������
*  Description: �����Զ���Ӧ��ID�����Ҷ�Ӧ�Ĺ��������
                �����ʼ����ɣ���֪ʶ��������Ϣ����󣬲��ܵ��á�
*        Input: EGN_UINT32     ulAppId       :    ����ѯ���Զ���Ӧ��ID
*       Output: EGN_UINT32    *pulRuleNum    :    �Զ���������<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetRuleNum
(
    IN   EGN_UINT32     ulAppId,
    OUT  EGN_UINT32    *pulRuleNum
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetRuleInfo
*      Purpose: ���ҹ�����Ϣ�͸���
*  Description: �����Զ���Ӧ��ID�����Ҷ�Ӧ�Ĺ�����Ϣ�͸�����
                �����ʼ����ɣ���֪ʶ��������Ϣ����󣬲��ܵ��á�
*        Input: EGN_UINT32     ulAppId         :  ����ѯ���Զ���Ӧ��ID
*        Inout: EGN_UINT32    *pulRuleNum      :  �Զ��������Ϣ����<�ǿ�>
*               EgnNgfwUDRule *pstUdRuleArray  :  �Զ���������<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetRuleInfo
(
    IN     EGN_UINT32     ulAppId,
    INOUT  EGN_UINT32    *pulRuleNum,
    INOUT  EgnNgfwUDRule *pstUdRuleArray
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetOneRule
*      Purpose: ���ҹ�����Ϣ
*  Description: �����Զ���Ӧ��ID�͹����������Ҷ�Ӧ�Ĺ�����Ϣ��
                �����ʼ����ɣ���֪ʶ��������Ϣ����󣬲��ܵ��á�
*        Input: EGN_UINT32      ulAppId       :   ����ѯ���Զ���Ӧ��ID
                EGN_UCHAR      *pucRuleName   :   �Զ��������<�ǿ�>
*       Output: EgnNgfwUDRule  *pstUdRule     :   �Զ��������Ϣ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwUDGetOneRule
(
    IN   EGN_UINT32     ulAppId,
    IN   EGN_UCHAR     *pucRuleName,
    OUT  EgnNgfwUDRule *pstUdRule
);

/*******************************************************************************
*    Func Name: EgnApiNgfwUDGetRiskValue
*      Purpose: ����Ӧ�õķ��գ���������ռ���
*  Description: ��API�ӿڻ���ݷ������������������Ӧ�ķ��յȼ���
                   �������͸���Ŀǰ�����7�������û�����������7���������
*               ����ԭ������:
*               �������͸���     ���յȼ�
*               6 or 7       ->     5
*               5            ->     4
*               4 or 3       ->     3
*               2            ->     2
*               1 or 0       ->     1
*        Input: EGN_UINT16      usRiskType  :    �������ͣ���7λ��Ч���õ�7λ����־7�ֲ�ͬ�ķ�������
*       Output:
*       Return: EGN_UINT16      ��Ӧ�ķ��ռ���
*      Caution:
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT16 EgnApiNgfwUDGetRiskValue
(
    IN EGN_UINT16 usRiskType
);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __EGN_API_USER_DEFINE_RULE_H__ */

