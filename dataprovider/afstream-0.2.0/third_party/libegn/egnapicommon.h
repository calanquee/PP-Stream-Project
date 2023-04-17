/*
 ******************************************************************************
 ��Ȩ���� (C), 2008-2009, ��Ϊ�������޹�˾
 ******************************************************************************
  �� �� ��   : egnapicommon.h
  �� �� ��   : ����
  ��    ��   : EGN��Ŀ��
  ��������   : 2008��12��18��
  ����޸�   :
  ��������   : �����궨��
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2009��2��2��
    ��    ��   : EGN��Ŀ��
    �޸�����   : �����ļ�

******************************************************************************/
/**@file  egnapicommon.h
  *    �����궨��
*******************************************************/
/**
 * @defgroup egn  EGNЭ��ʶ��ģ���API
 */

#ifndef __EGN_API_COMMON_H__
#define __EGN_API_COMMON_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/** EGN�����Ʒ�汾���� */
#define EGN_SOFTWARE_EX_VER "NSE V300R006C00SPC201"

/** EGN����ڲ��Ӱ汾���� */
#define EGN_INNER_VER "B501"

/** EGN����ڲ��汾�� */
#define EGN_SOFTWARE_IN_VER EGN_SOFTWARE_EX_VER/**/""EGN_INNER_VER""/**/EGN_PRODUCT\
 "/"/**/EGN_OSVER"/"/**/EGN_CPU" ["__DATE__" "__TIME__"][BinChkKK]"

/** EGN������ݰ汾 */
#define EGN_COMPATI_VERSION 0002

/** EGN Rule Ver */
#define EGN_RULEINFO_VERSION 0005

/** ��ѯ֪ʶ����Ϣ�� */
#define EGN_UNKNOW_CLASS_ID     0xffffffff      /* ��Ч��ClassID */
#define EGN_UNKNOW_APP_ID       0xffffffff      /* ��Ч��AppID */
#define EGN_UNKNOW_PROTO_ID     0xffffffff      /* ��Ч��ProtocolID */

#define EGN_SYSINFO_BUF_LEN     12288           /*  ��ȡ������Ϣʱ���������Ϣ������ڴ��С */

/** ��ʼ������Magic��Ч���� */
#define EGN_INIT_PUB_PARA_MAGIC_VALID   (0x6C)

/** Protocol��PPID������ */
#define EGN_MAX_PARENT_PID         8

/** �ڴ�ҳ��ʼ��������� */
#define EGN_MEMCP_INIT_MAX_COUNT   (10)

/** �������ά����Ŀ */
#define EGN_MAX_ATTRIBUTE_NUM  (64)

/** ֧�����ÿ����ϻ�ʱ��������� */
#define EGN_RELATION_MIN_AGING_TIME     3   /* �������ϻ�ʱ�����Сֵ */

/** ֧�����ÿ����ϻ�ʱ��������� */
#define EGN_RELATION_MAX_AGING_TIME     30  /* �������ϻ�ʱ������ֵ */

/** ֧�ֵ����ͬ����peer�� */
#define EGN_SYN_PEER_MAX_NUM 20

/* ͳ��ʶ����ı��ĸ�����󳤶� */
#define EGN_STAT_MAX_PACKET_LOADLEN     1600

/* һ��ƥ����෵�ض��ٸ�ƥ���� */
#define EGN_HA_RETURN_PATT_MAX  256

#ifdef EGN_GREEDY_MATCH

/* ��฽��ʶ��Э����� */
#define EGN_MAX_APPEND_RESULT_NUM   64
#endif

/** ��һ����ѯά������ */
#define EGN_DBG_QUERY_ENGINE_VERSION        0x01     /* ��ѯ����汾�� */
#define EGN_DBG_QUERY_DETECT_THRESHOLD      0x02     /* ��ѯʶ��ֵ */
#define EGN_DBG_QUERY_RULELIB_VERSION       0x04     /* ��ѯ֪ʶ��汾�� */
#define EGN_DBG_QUERY_PEER_INFO             0x08     /* ��ѯpeer��Ϣ */
#define EGN_DBG_QUERY_RELTBL_INFO           0x10     /* ��ѯ������״̬ */
#define EGN_DBG_QUERY_PKT_STAT_INFO         0x20     /* ��ѯ����ͳ����Ϣ */
#define EGN_DBG_QUERY_STATICBP_INFO         0x40     /* ��ѯ��̬�ڴ������Ϣ */
#define EGN_DBG_QUERY_STATBP_INFO           0x80     /* ��ѯͳ���ڴ������Ϣ */
#define EGN_DBG_QUERY_ALL_INFO              0xff     /* ��ѯ����������Ϣ */

#define  EGN_MAX_DISABLED_PROTO_NUM 15000   /* ���ȥʹ��Э����� */

/** ϵͳЭ��ID���ֵ(С��,���ܵ������ֵ) */
#define EGN_SYS_PROTO_ID_MAX    60000

/*STRUCT< �ַ����ṹ�� >*/
typedef struct _EgnString
{
    EGN_UCHAR  *pucString;       /*  �ַ���ָ�� */
    EGN_UINT32  ulLen;           /*  �ַ������� */
#ifdef EGN_64
    EGN_UINT8   aucReserved[4];  /* 64λ���뱣���ֽ�  */
#endif
}EgnString;

/*ENUM< ��ַ���Ͷ��� >*/
typedef enum
{
    EGN_ADDR_TYPE_INVALID   = EGN_EN_INVALID,
    EGN_ADDR_TYPE_IPV4      = 0,    /* IPV4 */
    EGN_ADDR_TYPE_IPV6      = 1,    /* IPV6 */
    EGN_ADDR_TYPE_ANY       = 2,    /* Any */
    EGN_ADDR_TYPE_END,

    EGN_ADDR_TYPE_BOTTOM     =  EGN_EN_BUTT
}EGN_ADDR_TYPE_EN;

/*ENUM< ���ķ��� >*/
typedef enum
{
    EGN_PACKET_DIRECTION_BEGIN    = EGN_EN_INVALID,
    EGN_PACKET_DIRECTION_UP       = 0,  /* ���еı��� */
    EGN_PACKET_DIRECTION_DOWN     = 1,  /* ���еı��� */
    EGN_PACKET_DIRECTION_ANY      = 2,  /* UpLink and DownLink */
    EGN_PACKET_DIRECTION_END,

    EGN_PACKET_DIRECTION_BOTTOM   = EGN_EN_BUTT
}EGN_PACKET_DIRECTION_EN;

#ifdef EGN_HA
/*ENUM< HAʶ���� >*/
typedef enum
{
    EGN_HA_INPUT_PACKET_BEGIN       = EGN_EN_INVALID,
    EGN_HA_INPUT_PACKET_STOP        = 0,    /* ֹͣ */
    EGN_HA_INPUT_PACKET_SOFT        = 1,    /* ����� */
    EGN_HA_INPUT_PACKET_HARD        = 2,    /* ��Ӳ������ */
    EGN_HA_INPUT_PACKET_END,
    EGN_HA_INPUT_PACKET_BOTTOM = EGN_EN_BUTT
}EGN_HA_INSPECT_PACKET_EN;
#endif

/*ENMU< Ӳ������ģʽ�������Ͷ��� >*/
typedef enum
{
    EGN_HA_PATTERN_SET_TYPE_BEGIN   = EGN_EN_INVALID,
    EGN_HA_PATTERN_SET_TYPE_INVALID = 0,
    EGN_HA_PATTERN_SET_TYPE_TCP     = 1,
    EGN_HA_PATTERN_SET_TYPE_UDP     = 2,
    EGN_HA_PATTERN_SET_TYPE_HTTP    = 3,
    EGN_HA_PATTERN_SET_TYPE_SOFT    = 4,
    EGN_HA_PATTERN_SET_TYPE_END,

    EGN_HA_PATTERN_SET_TYPE_BOTTOM  = EGN_EN_BUTT
} EGN_HA_PATTERN_SET_TYPE_EN;

/*ENMU< Ӳ������ģʽ������> */
typedef enum
{
    EGN_HA_PATTERN_TYPE_BEGIN           = EGN_EN_INVALID,
    EGN_HA_PATTERN_TYPE_CONTENT_STRING  = 0,
    EGN_HA_PATTERN_TYPE_PCRE            = 1,
    EGN_HA_PATTERN_TYPE_END,

    EGN_HA_PATTERN_TYPE_BOTTOM          = EGN_EN_BUTT
} EGN_HA_PATTERN_TYPE_EN;

/*MACRO< δʹ�õĲ��������������PC-LINT�澯. >*/
#define EGN_UNUSED(_x) ((_x) = (_x))

/*STRUCT< IP��ַ >*/
typedef struct _EgnIpAddr
{
    EGN_UINT32   ulIpType;       /* IP����#EGN_ADDR_TYPE_EN */
#ifdef EGN_64
    EGN_UINT8    aucReserved[4]; /* 64λ���뱣���ֽ� */
#endif
    union
    {
        EGN_UINT32   ulIpv4Addr;        /* IPv4��ַ������Ϊ��� */
        EGN_UINT8    aucIpv4Addr[4];    /* IPv4��ַ������Ϊ��� */
        EGN_UINT32   aulIpv6Addr[4];    /* IPv6��ַ������Ϊ��� */
        EGN_UINT8    aucIpv6Addr[16];   /* IPv6��ַ������Ϊ��� */
    }u;
}EgnIpAddr;

/*STRUCT< ������Ϣ >*/
typedef struct _EgnSuperClassInfo
{
    EGN_UINT32  ulSuperClassID;    /* ����ID */
    EGN_UINT32  ulIsUserDefine;    /* EGN_SYS_DEFINE:ϵͳЭ��#EGN_USER_DEFINE���Զ���Э��,Ϊ�����汾��չ������ */
    EgnString   stSuperClassName;  /* �������� */
    EgnString   stSuperClassDesc;  /* �������� */
}EgnSuperClassInfo;

/*STRUCT< ������Ϣ >*/
typedef struct _EgnClassInfo
{
    EGN_UINT32  ulClassID;      /* ����ID */
    EGN_UINT32  ulSuperClassID; /* ��Ӧ�Ĵ���ID */
    EGN_UINT32  ulIsUserDefine; /* EGN_SYS_DEFINE:ϵͳЭ��#EGN_USER_DEFINE���Զ���Э��,Ϊ�����汾��չ������ */
#ifdef EGN_64
    EGN_UINT8   aucReserved[4]; /* 64λ���뱣���ֽ� */
#endif
    EgnString   stClassName;    /* �������� */
    EgnString   stClassDesc;    /* �������� */
}EgnClassInfo;

/*STRUCT< Ӧ����Ϣ >*/
typedef struct _EgnAppInfo
{
    EGN_UINT32  ulAppID;        /* Ӧ��ID */
    EGN_UINT32  ulIsUserDefine; /* EGN_SYS_DEFINE:ϵͳЭ��#EGN_USER_DEFINE���Զ���Э��,Ϊ�����汾��չ������ */
    EgnString   stAppName;      /* Ӧ������ */
    EgnString   stAppDesc;      /* Ӧ������ */
}EgnAppInfo;

/*STRUCT< Э����Ϣ >*/
typedef struct _EgnProtoInfo
{
    EGN_UINT32  ulSuperClassID;     /* ����ID */
    EGN_UINT32  ulClassID;          /* ����ID */
    EGN_UINT32  ulProtoID;          /* Э��ID */
    EGN_UINT32  ulAppID;            /* Ӧ��ID */
    EGN_UINT32  ulParentPIDNum;     /* ParentID���� */
    EGN_UINT8   ucIsUserDefine;     /* EGN_SYS_DEFINE:ϵͳЭ�飬#EGN_USER_DEFINE���Զ���Э�� */
    EGN_UINT8   aucReserved[3];     /* �ֽڶ��뱣�� */
    EgnString   stProtoName;        /* Э������ */
    EgnString   stProtoDesc;        /* Э������ */
    EGN_UINT32  aulParentPID[EGN_MAX_PARENT_PID];   /* ParentID���� */
}EgnProtoInfo;

/*STRUCT< IP��Ƭ >*/
typedef struct _EgnIpFrag
{
    struct _EgnIpFrag      *pstNext;            /* ��һ����Ƭ */
    EGN_UCHAR              *pucLoadData;        /* ָ���Ƭ���Ĵ�����غɵ�ָ�� */
    EGN_UINT16              usLoadLen;          /* ��Ƭ���Ĵ�����غɳ��� */
    EGN_UINT8               aucReserved[2];     /* �����ֽ�  */
#ifdef EGN_64
    EGN_UINT8               aucReserved2[4];    /* 64λ���뱣���ֽ� */
#endif
} EgnIpFrag;

/*STRUCT< ʶ�����ݰ� >*/
typedef struct _EgnPacket
{
    EGN_UINT8 *pucIpData;       /* IPͷָ�� */
    EGN_UINT8 *pucTpData;       /* �����ͷָ�� */
    EgnIpFrag *pstIpFrag;       /* IP��Ƭ������غ����� */
    EGN_UINT8  ucDirection;     /* ��Ӧ��#EGN_PACKET_DIRECTION_EN */
    EGN_UINT8  ucProto;         /* �����Э�����ͣ���Ӧ��#EGN_TRANS_TYPE_EN */
    EGN_UINT8  aucReserved[2];
#ifdef EGN_64
    EGN_UINT8  aucReserved2[4]; /* 64λ���뱣���ֽ� */
#endif
    EgnIpAddr  stSrcIp;         /* ԴIP��ַ */
    EgnIpAddr  stDstIp;         /* Ŀ��IP��ַ */
    EGN_UINT16 usSrcPort;       /* Դ�˿� */
    EGN_UINT16 usDstPort;       /* Ŀ�Ķ˿� */
    EGN_UINT32 ulTunnelId;      /* Ӧ�ò�ָ����VPN ID��Tunnel ID���������й���ʶ�� */
    EGN_VOID * pvFlowHandle;    /* ���ݰ������������ */
}EgnPacket;

#ifdef EGN_GREEDY_MATCH
/* ̰��ʶ���ʶ���� */
typedef struct _EgnGreedyResult
{
    EGN_UINT32  ulRuleID;               /* ����ID */
    EGN_UINT32  ulProtocol;             /* Э��ID��ֻ��Ҫ����һ�� */
}EgnGreedyResult;
#endif

/*STRUCT< ʶ���� >*/
typedef struct _EgnResult
{
    EGN_UINT32      ulResult;              /* ʶ�������ο�#EGN_INSPECT_EN */
    EGN_UINT32      ulProtoID;             /* ʶ��Э��ID����Ӧ����������"֪ʶ��-���Ӧ��Э��ID.XLS"��ҳ��"Э��_��Э���ϵ"��sub_prot */
    EGN_BOOL        bIsContinue;           /* �Ƿ���Ҫ������� */
    EGN_UINT32      ulCarrierNum;          /* ����Э����� */
    EGN_UINT32      aulCarrierProtoID[4];  /* ����Э��ID�б�0Ϊ��ײ㣬�������ϵ��� */
    EGN_VOID       *pvFlowHandle;          /* ��������ͨ������������ʶ��� */
    EGN_UINT32      aulAttribute[EGN_MAX_ATTRIBUTE_NUM]; /* �����ľ���������Ϣ */
    #ifdef EGN_GREEDY_MATCH
    EGN_UINT32      ulFirstProtoID;         /* �״�ʶ���Э��ID */
    EGN_UINT32      ulAppendResultCnt;      /* ����ʶ��Э����� */
    EgnGreedyResult astAppendResult[EGN_MAX_APPEND_RESULT_NUM]; /* ����ʶ��Э����Ϣ */
    #endif
    EGN_UINT32      ulSuperClassId;        /* ʶ�������ϲ�Ĵ���id */
    EGN_UINT32      ulClassId;             /* ʶ�������ϲ������id */
    EGN_UINT32      ulAppId;               /* ʶ�������ϲ��Ӧ��id */
#ifdef EGN_64
    EGN_UINT8       aucReserved[4];        /* 8�ֽڶ��뱣�� */
#endif
}EgnResult;

#ifdef EGN_HA
/*STRUCT< Ӳ��ʶ���� >*/
typedef struct _EgnHAResult
{
    EGN_UINT32      ulContinue;     /* �Ƿ���Ҫ�����������ݰ�, EGN_HA_INSPECT_PACKET_EN */
    EGN_UINT32      ulResult;       /* ʶ����,��Ӧ��#EGN_INSPECT_EN */
    EGN_UINT32      ulProtoID;      /* Э��ID */
#ifdef EGN_64
    EGN_UINT8       aucReserved[4]; /* 64λ���뱣���ֽ� */
#endif
    EGN_VOID       *pvFlowHandle;   /* ����ʶ�����ݰ������Ŀ��������  */
}EgnHAResult;
#endif

/*STRUCT< ʶ����չ���������ں�����չ >*/
typedef struct _EgnInspectAuxData
{
    EGN_UINT32     ulAuxData;       /* ��չ���� */
    EGN_UINT32     ulReserved;      /* �����ֽ� */
} EgnInspectAuxData;

/*STRUCT< ��ʼ���������� >*/
typedef struct _EgnInitCfgParam
{
    /* �ڲ�ʹ�ã���Ʒ�����ע */
    EGN_UCHAR   ucCfgValidMagic;            /* Cfg������ЧMagic,�û������ע,�벻Ҫ�޸� */
    EGN_UINT8   aucReserved[3];             /* �����֣����ֽڶ��롣  */

    /* �����ڴ�������ò��� */
    EGN_BOOL    bIsCfgParaShared;           /* ������Ϣ�Ƿ���EGN_FALSE: ��EGN_TRUE : �ǣ� Ĭ��: �� */
    EGN_BOOL    bIsRuleLibShared;           /* ֪ʶ���Ƿ���  EGN_FALSE: ��EGN_TRUE : �ǣ� Ĭ��: �� */
    EGN_BOOL    bIsMemShared;               /* �Ƿ����ڴ棬  EGN_FALSE: ��EGN_TRUE : �ǣ� Ĭ��: �� */

    EGN_UINT16  usMaxInstance;              /* ����ʵ������, ��ʵ��ʱʵ����Ϊ1����ʵ��ʱʵ�������32 */
    EGN_UINT8   aucReserved1[2];            /* �����֣����ֽڶ��롣  */
    EGN_UINT32  ulMemPolicy;                /* �ڴ���ԣ�ȡֵEGN_MEM_POLICY_EN  */
    EGN_UINT32  ulFlowScale;                /* ����ģ  */
    EGN_UINT32  ulRelationCBCountIPv4;      /* IPv4����ʶ��CB�����Ŀ */
    EGN_UINT32  ulRelationCBCountIPv6;      /* IPv6����ʶ��CB�����Ŀ */
    EGN_UINT32  ulDnsRelCBCountIPv4;        /* DNS����ʶ��IPv4��CB�����Ŀ */
    EGN_UINT32  ulDnsRelCBCountIPv6;        /* DNS����ʶ��IPv6��CB�����Ŀ */

    /* ���޿����ò��� */
    EGN_UINT32  ulMaxDetectCount;           /* ʶ��ֵ���� */
    EGN_UINT32  ulMaxRelAgeNum;             /* �������ϻ����� */
    EGN_BOOL    bIsNeedSuperClass;          /* �Ƿ���Ҫ��ʶ�����з���Ӧ�á�����ʹ���id��Ϣ��EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */

    EGN_UINT32  ulFastRelationAgingTime;    /* �����ϻ���ʹ�õ�ʱ�䣬��λ  ���� */
    EGN_UINT32  ulRollBackKeepTime;         /* ���˱���ʱ������λ�룬Ĭ��28800  */
    EGN_UINT32  ulIpFlowAgedTime;           /* �����ϻ�ʱ������λ�룬Ĭ��20����С3�룬���2Сʱ */
    EGN_UINT16  usScanInterval;             /* �ϻ�ɨ���ʱ��������λ���룬Ĭ��200���� */
    EGN_UINT8   aucReserved4[2];            /* �����֣����ֽڶ��롣  */

    /* �����ù��ܿ��� */
    EGN_BOOL    bFastRelationSwitch;        /* ���ٹ������أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bUseWellKnownPortInspect;   /* ֪���˿�ģ��ƥ�书���Ƿ�������,EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bHierInspectSwitch;         /* �㼶ʶ�����з�ͬ��ʶ����ȫ�ֿ��أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bBehaviorInspect;           /* ��Ϊ����ʶ�𿪹أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bStatSwitch;                /* ͳ�ƹ��ܿ��أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bIsNotFirstPKTRelInspect;   /* �Ƿ�֧�ַ��װ�����ʶ�𿪹أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bUnsymmetricalInspect;      /* �Ƿ�֧�ַǶԳ�ʶ�𿪹أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bIsStatInspectSwitch;       /* ͳ��ʶ���ܿ��أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bUDRuleSwitch;              /* �Ƿ��Զ�����򿪹أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bNgfwUserDefineSwitch;      /* �Ƿ�NGFW�Զ��忪�أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bDnsRelSwitch;              /* DNS����ʶ�𿪹أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bFragSwitch;                /* �Ƿ��Ƭʶ�𿪹أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bIsHardwareAccelerate;      /* �Ƿ�ʹ��Ӳ�����ٹ��ܣ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
    EGN_BOOL    bWeakRelationSwitch;        /* �Ƿ�ʹ��������ʶ�𿪹أ�EGN_FALSE: �أ�EGN_TRUE : ���� Ĭ��: �� */
}EgnInitCfgParam;

/*STRUCT< ����ͳ����Ϣ >*/
typedef struct _EgnRuleStatRd
{
    EGN_UINT32   ulRuleId;       /* ����id */
    EGN_UINT32   ulMatchCnt;     /* ����ƥ����� */
    EGN_UINT32   ulSuccCnt;      /* ����ƥ��ɹ����� */
#ifdef EGN_64
    EGN_UINT8    ucReserved[4];  /* Ϊ64λ���� */
#endif
}EgnRuleStatRd;

/*ENUM< �ڴ���Լ��㷽ʽ���� >*/
typedef enum
{
    EGN_MEM_POLICY_BEGIN                 = EGN_EN_INVALID,
    EGN_MEM_POLICY_UNLIMIT               = 0,                /* Ĭ��ֵ; ��֤EGNʹ�õ��ڴ� */
    EGN_MEM_POLICY_LIMIT                 = 1,                /* �����ڴ��С����֤�м�״̬�ڴ� */
    EGN_MEM_POLICY_ONLY_LOAD_TXT_RULELIB = 2,                /* ֻ�������Ŀ��ڴ�ģʽ */
    EGN_MEM_POLICY_END,
    EGN_MEM_POLICY_BOTTOM       = EGN_EN_BUTT
}EGN_MEM_POLICY_EN;

/*ENUM< ĳ�����������Ͷ��� >*/
typedef enum
{
    EGN_TRANS_TYPE_BEGIN = EGN_EN_INVALID,
    EGN_TRANS_TYPE_TCP   = 0x6,            /* TCP  ���� */
    EGN_TRANS_TYPE_UDP   = 0x11,           /* UDP  ���� */
    EGN_TRANS_TYPE_END,

    EGN_TRANS_TYPE_BOTTOM = EGN_EN_BUTT
}EGN_TRANS_TYPE_EN;

/*ENUM< ͳ�Ƶ�Ԫ >*/
typedef enum
{
    EGN_STAT_UNIT_BEGIN      = EGN_EN_INVALID,
    EGN_STAT_UNIT_INSPECT    = 0,      /* ��Ӧͳ�Ʋ���:�����ͳ���� */
    EGN_STAT_UNIT_RELTBL     = 1,      /* ��Ӧͳ�Ʋ���:���������ͳ���� */
    EGN_STAT_UNIT_END,

    EGN_STAT_UNIT_BOTTOM     = EGN_EN_BUTT
}EGN_STAT_UNIT_EN;

/*ENUM< ͳ���� >*/
typedef enum
{
    EGN_STAT_ENTITY_BEGIN                   = EGN_EN_INVALID,
    EGN_STAT_ENTITY_PACKET_COUNT            = 0,                /* ͳ�����а� */
    EGN_STAT_ENTITY_SUCCESS_COUNT           = 1,                /* ͳ��ʶ��ɹ��İ� */
    EGN_STAT_ENTITY_UNKNOWN_COUNT           = 2,                /* ͳ��δʶ��İ� */
    EGN_STAT_ENTITY_RELITEM_ADDED_COUNT     = 3,                /* ͳ��ָ��Э����ӵĹ���������� */
    EGN_STAT_ENTITY_RELITEM_DESTROYED_COUNT = 4,                /* ͳ��ָ��Э������������ٸ��� */
    EGN_STAT_ENTITY_RELITEM_HITED_COUNT     = 5,                /* ͳ��ָ��Э�����еĹ���������� */
    EGN_STAT_ENTITY_RELITEM_HITED_TIMES     = 6,                /* ָ��Э�����ٵĺͱ��滻�ı�����еĴ���֮�� */
    EGN_STAT_ENTITY_RELITEM_LIFE_SUM        = 7,                /* ͳ��ָ��Э�������������ʱ���е�ʱ���֮�� */
    EGN_STAT_ENTITY_REL_QUERY_TIMES         = 8,                /* ͳ������Э��������ѯ���� */
    EGN_STAT_ENTITY_REL_QUERY_SUCCESS_TIMES = 9,                /* ͳ������Э��������ѯ�ɹ����� */
    EGN_STAT_ENTITY_FINISH_COUNT            = 10,               /* ͳ��ʶ����ɵİ� */
    EGN_STAT_ENTITY_RELATION_COUNT          = 11,               /* ͳ����Ҫ����ʶ��İ� */

    EGN_STAT_ENTITY_END,

    EGN_STAT_ENTITY_BOTTOM              = EGN_EN_BUTT
}EGN_STAT_ENTITY_EN;

/*ENUM< ����ͳ�Ƶ�ͳ���� >*/
typedef enum
{
    EGN_STAT_ERR_BEGIN               = EGN_EN_INVALID,
    EGN_ERR_ALLOC_FAILED                 = 0,                    /* �����ڴ�ʧ�� */
    EGN_ERR_MM_REPEAT_FREE               = 1,                    /* bufmem�ظ��ͷ� */
    EGN_ERR_RELOAD                       = 2,                    /* �ظ����� */
    EGN_ERR_RELEASE_IS_GOING             = 3,                    /* ��֪ʶ�������ͷ��� */
    EGN_ERR_CREAT_BUF_MEM_FAILED         = 4,                    /* ����bufmemʧ�� */
    EGN_ERR_THREAD_ID_INCON_INSTANCE     = 5,                    /* �ϲ������߳�ID��ʵ���б���Ĳ�һ�� */
    EGN_ERR_THREAD_ID_INCON_CTX          = 6,                    /* �ϲ������߳�ID���м�״̬����Ĳ�һ�� */
    EGN_ERR_PEERLIST_IS_FULL             = 7,                    /* peerlist�������ǿ� */
    EGN_ERR_PEERSET_CACHE_NOT_ENOUGH     = 8,                    /* ���������Ԫ��ʱ��cache�Ŀռ䲻�� */
    EGN_ERR_INSPECT_TIME_OUT             = 9,                    /* ʶ��ʱ���������صĴ����� */
    EGN_ERR_ALLOC_OVERWRITE_FAILED       = 10,                   /* �ڴ��������з���дԽ����� */
    EGN_ERR_PEERLIST_FLOW_PEER_IS_MAX    = 11,                   /* ����������������ӹ���������Ѿ��ﵽ���� */
    EGN_ERR_PEERLIST_MAX_COLLISION       = 12,                   /* peerlist��ͻ�ﵽ������ */
    EGN_ERR_STAT_DETECT_ALLOC_FAILED     = 13,                   /* ͳ��ʶ���ڴ����ʧ�� */
    EGN_ERR_STAT_DETECT_CREATE_BUF_FAILED = 14,                  /* ͳ��ʶ�𴴽��ڴ�bufmemʧ�� */

    EGN_STAT_ERR_END,
    EGN_STAT_ERR_BOTTOM              = EGN_EN_BUTT
}EGN_STAT_ERROR_EN;

/*ENUM< ��������ͳ�ƿ���ѡ�� >*/
typedef enum
{
    EGN_STAT_CTRL_BEGIN     = EGN_EN_INVALID,
    EGN_STAT_ONOFF_SWITCH   = 0,             /* ͳ�ƿ��أ�����Ϊһ��BOOLֵ��1��ʾ����0��ʾ�� */
    EGN_STAT_PROTOID_SET    = 1,             /* ָ��Э��ID������Ϊһ��UINT32���͵�Э��ID */
    EGN_STAT_CTRL_END,

    EGN_STAT_CTRL_BOTTOM    = EGN_EN_BUTT
}EGN_STAT_CTRL_EN;

/*STRUCT< ����ͳ����ṹ�� >*/
typedef struct _EgnRelStatInfo
{
    EGN_UINT32  ulRelItemAddedCnt;      /* ָ��Э����ӵĹ���������� */
    EGN_UINT32  ulRelItemDestroyedCnt;  /* ָ��Э������������ٸ��� */
    EGN_UINT32  ulRelItemHitedCnt;      /* ָ��Э�����еĹ���������� */
    EGN_UINT32  ulRelItemHitedTimes;    /* ָ��Э�����ٵĺͱ��滻�ı�����еĴ���֮�� */
    EGN_UINT32  ulRelItemLifeSum;       /* ָ��Э�������������ʱ���е�ʱ���֮��,��ͳ�����Թ����ϻ���ʱ������Ϊ��λ */
    EGN_UINT32  ulRelQueryTimes;        /* ����Э��������ѯ���� */
    EGN_UINT32  ulRelQuerySuccessTimes; /* ����Э��������ѯ�ɹ����� */
    EGN_UINT32  ulTotalRelItemAddedCnt;      /* ��ͨ��������ӵĹ���������� */
    EGN_UINT32  ulTotalRelItemDestroyedCnt;  /* ��ͨ���������ٵĹ���������� */
#ifdef EGN_64
    EGN_UINT8   aucReserved[4];         /* 64λ���뱣���ֽ� */
#endif
}EgnRelStatInfo;

/*STRUCT< ͳ����ڲ�ʹ�� >*/
typedef struct _EgnStatInfo
{
    EGN_UINT32      ulPacketCount;      /* ʶ�����ݰ������� */
    EGN_UINT32      ulSuccessCount;     /* ʶ��ɹ��İ��ĸ��� */
    EGN_UINT32      ulUnknownCount;     /* δʶ��İ��ĸ��� */
    EGN_UINT32      ulFinishCnt;        /* ʶ����Ϊfinish�İ����� */
    EGN_UINT32      ulRelCnt;           /* ʶ����Ϊrelation�İ����� */
#ifdef EGN_64
    EGN_UINT8       aucReserved[4];     /* 64λ���뱣���ֽ� */
#endif
    EgnRelStatInfo  stRelStatInfo;      /* ���������ͳ���� */
}EgnStatInfo;

/*STRUCT< ��̬�ڴ�ͳ���ARʹ�� >*/
typedef struct _EgnDynMemStatInfo
{
    EGN_UINT32      ulMemCpAllocTimes;        /* ֪ʶ��ȳ�פ MemCp ������� */
    EGN_UINT32      ulMemCpAllocSize;         /* ֪ʶ��ȳ�פ MemCp �����С */
    EGN_UINT32      ulDynAllocTimes;          /* DynAlloc ������� */
    EGN_UINT32      ulDynAllocDisableSize;    /* DynAlloc ȥʹ���ڴ��С */
    EGN_UINT32      ulDynAllocEnableSize;     /* DynAlloc ʹ���ڴ������С */
    EGN_UINT32      ulDynAllocInsSize;        /* DynAlloc ��ʶ����̳�ʼ����������ڴ� */
    EGN_UINT32      ulDynAllocInsTmpSize;     /* DynAlloc ��ʶ����̳�ʼ����������ڴ���ʱ���� */
    EGN_UINT32      ulFlowCtxMemCpAllocTimes; /* �м�״̬ MemCp ������� */
    EGN_UINT32      ulFlowCtxMemCpAllocSize;  /* �м�״̬ MemCp �����С */
    EGN_UINT32      ulFlowCtxMemMaxSize;      /* �м�״̬��ʹ�õ��ڴ����� */
}EgnDynMemStatInfo;

/*STRUCT<  ��������ṹ >*/
typedef struct _EgnPeerTuple
{
    EGN_UINT8     ucTransProtocol;  /* �����Э�飬����ȡֵ��EGN_TRANS_TYPE_EN */
    EGN_UINT8     ucWeakFlag;       /* ������ʶ���־λ */
    EGN_UINT16    usPort;           /* �˿� */
    EGN_UINT32    ulTunnelId;       /* ͨ��ID,�����Ŀ��Ը�0 */
    EgnIpAddr     stIpAddr;         /* IP��ַ */
}EgnPeerTuple;

/*STRUCT<  �ϻ�ʱ��ṹ >*/
typedef struct _EgnPeerTime
{
    EGN_UINT32   ulTriggerTimeout;      /* �����ϻ�ʱ�� */
    EGN_UINT32   ulPersistenceTimeout;  /* �����ϻ�ʱ�� */
}EgnPeerTime;

/*STRUCT< ͬ��������Ķ�Ӧ�Ĺ�����������Ϣ >*/
typedef struct _EgnPeerDataFlowInfo
{
    EGN_VOID            *pvFlowHandle;              /* ����ʶ�������ID */
    EGN_UINT32           ulProtocol;                /* �μ�EGN_PROTO_ID_EN */
#ifdef EGN_64
    EGN_UINT8           aucReserved[4];             /* 64λ���뱣���ֽ� */
#endif
} EgnPeerDataFlowInfo;

/*STRUCT< ͬ��������ʱ�������������Ϣ�ṹ >*/
typedef struct _EgnPeerInfoSetItem
{
    EgnPeerTuple            stTuple;            /* ��ͬ������Ԫ����Ϣ */
    EgnPeerDataFlowInfo     stPeerSetDataInfo;  /* ��ͬ����������Ϣ */
    EgnPeerTime             stTimeout;          /* �ϻ�ʱ�� */
}EgnPeerInfoSetItem;

/*STRUCT< ��Ҫͬ����peer��Ϣ >*/
typedef struct _EgnPeerSet
{
    EgnPeerInfoSetItem  astPeerItem[EGN_SYN_PEER_MAX_NUM];  /* ��ͬ����peer */
    EGN_UINT32          ulPeerSetPeerNum;                   /* ��ͬ����peer���� */
#ifdef EGN_64
    EGN_UINT8           aucReserved[4];                     /* 64λ���뱣���ֽ� */
#endif
}EgnPeerSet;

/*STRUCT< ������ѯ�����Ϣ >*/
typedef struct _EgnRelResult
{
    EGN_UINT32  ulLeftAgingTime;        /* �ù��������Ӧ��ʣ���ϻ�ʱ�䣬����������Ҫ�೤ʱ���ϻ� */
    EGN_UINT32  ulProtocol;             /* �ù��������Ӧ��Э�� */
    EGN_VOID    *pvFlowHandle;          /* ����ʶ�������ID */
} EgnRelResult;

/*ENUM< ʶ���� >*/
typedef enum
{
    EGN_INSPECT_BEGIN       = EGN_EN_INVALID,
    EGN_INSPECT_UNKNOWN     = 0,    /* δ֪ */
    EGN_INSPECT_FINISH      = 1,    /* ʶ����� */
    EGN_INSPECT_RELATION    = 2,    /* ����ʶ�� */
    EGN_INSPECT_DOUBT       = 3,    /* ����ʶ�𣬿�����ĳ��Э�� */
    EGN_INSPECT_END,

    EGN_INSPECT_BOTTOM = EGN_EN_BUTT
}EGN_INSPECT_EN;

/*ENUM< �ڲ���ʹ�õķ���ֵ >*/
typedef enum
{
    EGN_RET_BEGIN                   = EGN_EN_INVALID,

    /* ----------------------- ������ ---------------------------------------- */
    EGN_RET_SUCCESS                                  = 0,       /* �ɹ� */
    EGN_RET_FAILURE                                  = 1,       /* ͨ��ʧ�� */
    EGN_RET_ALLOC_FAILED                             = 2,       /* �����ڴ�ʧ�� */
    EGN_RET_INVALID_PARAM                            = 3,       /* ��Ч����� */
    EGN_RET_INVALID_DATA                             = 4,       /* ��Ч���������� */
    EGN_RET_INVALID_PROTOCOL                         = 5,       /* ��Ч��Э������ */
    EGN_RET_NULL_PTR                                 = 6,       /* ��ָ����� */
    EGN_RET_MM_REPEAT_FREE                           = 7,       /* bufmem�ظ��ͷ� */
    EGN_RET_CREATE_RULE_FAILED                       = 8,       /* ����������� */
    EGN_RET_ERR_BUF_MORE                             = 9,       /* ��Ҫ����Ĵ洢�ռ� */
    EGN_RET_ERR_ID_NOT_EXIST                         = 10,      /* û��ID��Ӧ����Ϣ */
    EGN_RET_ERR_NAME_NOT_EXIST                       = 11,      /* û�����ֶ�Ӧ����Ϣ */
    EGN_RET_REINIT                                   = 12,      /* �ظ���ʼ�� */
    EGN_RET_REDEINIT                                 = 13,      /* �ظ�ȥ��ʼ�� */
    EGN_RET_RELOAD                                   = 14,      /* �ظ����� */
    EGN_RET_PARSER_OVERFLOW                          = 15,      /* ���Ȳ���,����Խ�� */
    EGN_RET_PARSER_FAILURE                           = 16,      /* ����ʶ��ʱ,����Э��ʧ�� */
    EGN_RET_ITEM_NO_EXIST                            = 17,      /* ���ڹ�������ʾ�ü�¼������ */
    EGN_RET_RULE_CHECK_FAILURE                       = 18,      /* ������Ч�Լ��ʧ�� */
    EGN_RET_RELEASE_IS_GOING                         = 19,      /* ��֪ʶ�������ͷ��� */
    EGN_RET_ALREADY_INSPECTED                        = 20,      /* һ�����Ѿ���ʶ���ΪFINISH����UNKNOW,���������ʶ�� */
    EGN_RET_REACH_BUFF_END                           = 22,      /* ���ؽ��� */
    EGN_RET_AC_STATE_OVERFLOW                        = 23,      /* AC״ֵ̬��� */
    EGN_RET_CREAT_BUF_MEM_FAILED                     = 24,      /* ����bufmemʧ�� */
    EGN_RET_MD5_FAILED                               = 25,      /* MD5��صĴ��� */
    PCREX_RET_RESUME_REGEX_NOT_EXIST                 = 26,      /* resume��PCREX���ʽ������ */
    PCREX_RET_RESUME_REGEX_NOT_SUSPENDED             = 27,      /* resume��PCREX���ʽû�б�suspend */
    PCREX_RET_COMPILE_FAIURE                         = 28,      /* PCREX���ʽ����ʧ�� */
    PCREX_RET_RESUME_REGEX_NOT_SUSPENDED_OR_CONTINUE = 29,      /* resume��PCREX���ʽû�б�suspend ���� cont */
    PCREX_RET_GET_RELATION_PARSE_REGEX_FAILED        = 30,      /* ��ȡ����������PCREX����ʧ�� */
    PCREX_RET_PCRE_EXEC_ERROR                        = 31,      /* PCREִ�д��� */
    PCREX_RET_REGEX_CTX_STATE_EXCEPTION              = 32,      /* PCREX������м�״̬�쳣 */
    PCREX_RET_RELATION_PARSE_FAILED                  = 33,      /* PCREX���ʽ��������ʧ�� */
    PCREX_RET_PUSHALLOC_FAILURE                      = 34,      /* PCREXѹջʧ�� */
    PCREX_RET_INVALID_VAR                            = 35,      /* PCREX���ʽ�б����Ƿ� */
    PCREX_RET_REACH_NAME_TABLE_MAX_SIZE              = 36,      /* PCREX���ʽ���ִﵽ������������ֵ */
    PCREX_RET_REGEX_NAME_DUPLICATED                  = 37,      /* PCREX���ʽ�����ظ� */
    PCREX_RET_REGEX_PCRE_COMPILE_FAILED              = 38,      /* PCRE����compileʶ�� */
    PCREX_RET_REGEX_PCRE_STUDY_FAILED                = 39,      /* PCRE����studyʶ�� */
    PCREX_RET_REGEX_VARIABLE_MISUSED                 = 40,      /* PCREX���ʽ����ʹ���˷��Լ��ı��� */
    PCREX_RET_REGEX_MISUSED_IN_RESUME                = 41,      /* PCREX���ʽresume��ʹ�ô��� */
    PCREX_RET_REGEX_SUSPENDED_BUT_NOT_RESUMED        = 42,      /* PCREX���ʽsuspend ����û��resume */
    PCREX_RET_REGEX_RESUMED_BUT_NOT_SUSPENDED        = 43,      /* PCREX���ʽresume ����û��suspend */
    PCREX_RET_VARIABLE_DECLARED_TWICE                = 44,      /* PCREX���ʽ����������2�� */
    PCREX_RET_REGEX_SUSPEND_TWICE                    = 45,      /* PCREX���ʽsuspend�˴� */
    PCREX_RET_REGEX_RESET_WITHOUT_RESUME             = 46,      /* PCREX���ʽreset��û��resume�ı��ʽ */
    PCREX_RET_REGEX_RESET_TWICE                      = 47,      /* PCREX���ʽreset��2�� */
    PCREX_RET_REGEX_RESUME_TWICE                     = 48,      /* PCREX���ʽresume��2�� */
    PCREX_RET_CALLOUT_SYNTAX_ERROR                   = 49,      /* PCREX���ʽcallout�﷨���� */
    PCREX_RET_CLONE_VARIABLE_STACK_FAILED            = 50,      /* PCREX���ʽclone ����ջʧ�� */
    PCREX_RET_CREATE_TOKEN_STACK_FAILED              = 51,      /* PCREX���ʽ����tokenջʧ�� */
    PCREX_RET_CLONE_TOKEN_STACK_FAILED               = 52,      /* PCREX���ʽclone tokenջʧ�� */
    PCREX_RET_UNKNOWN_TOKEN_TYPE                     = 53,      /* PCREX���ʽ��unkonwn token���� */
    PCREX_RET_GET_CAPTURE_VALUE_FAILED               = 54,      /* PCREX���ʽ��ȡ�����valueʧ�� */
    PCREX_RET_REGEX_PAYLOAD_FORMAT_ERROR             = 55,      /* PCREX���ʽpayload��ʽ���� */
    PCREX_RET_REGEX_PAYLOAD_INDEX_INVAILD            = 56,      /* PCREX���ʽpayload index���� */
    PCREX_RET_GET_TOKEN_STACK_ELEMENT_FAILED         = 57,      /* PCREX���ʽ��ȡtokenԪ�ش��� */
    PCREX_RET_CAPTURE_IP_STRING_CONVERT_FAILED       = 58,      /* PCREX���ʽ����IP����ת������ */
    PCREX_RET_GET_BIT_VALUE_BIT_RANGE_INVALID        = 59,      /* PCREX���ʽ��ȡbit�ķ�Χ�Ƿ� */
    PCREX_RET_REGEX_MEMTABLE_INDEX_INVAILD           = 60,      /* PCREX���ʽmemtable index�Ƿ� */
    PCREX_RET_TOKEN_VALUE_NOT_INTEGER_COMPATIBLE     = 61,      /* PCREX���ʽtoken value�������� */
    PCREX_RET_REGEX_IS_NULL                          = 62,      /* PCREX���ʽ��NULL */
    PCREX_RET_ARRAY_OFFSET_ERR                       = 63,      /* PCREX���ʽ����OFFET���� */
    PCREX_RET_STACK_FLIP_ARRAY                       = 64,      /* PCREX���ʽstack flip to array */
    PCREX_RET_PIPELINE                               = 65,      /* ����Ϊ����ִ��PIPELINE */
    PCREX_RET_CALLOUT_NOT_SUPPORT_FRO_CUR_REGEX      = 66,      /* ��ǰCALLOUT�ڵ�ǰ�������в�֧�� */
    PCREX_RET_FLOW_CACHE_IS_NULL                     = 67,      /* ����cacheΪNULL */
    PCREX_RET_FLOW_CACHE_IS_NOT_ENOUGH               = 68,      /* ����cache�Ŀռ䲻�� */
    PCREX_RET_CONVERT_STRING_TO_UINT32_FAILED        = 69,      /* ���ַ���ת��ΪUINT32ʧ�� */
    PCREX_RET_REGEX_RESUME_DEAD_LOOP                 = 70,      /* resume��PCREX���ʽ��ѭ�� */
    PCREX_RET_NAME_DUPLICATED                        = 71,      /* PCREX���ʽ�����ظ� */

    EGN_RET_IPF_NO_IDLE_HASH_NODE                    = 72,      /* û�п��е�hash�ڵ� */
    EGN_RET_IPF_ITEM_NO_EXIST                        = 73,      /* ���������� */
    EGN_RET_IPF_NO_IDLE_IDX_NODE                     = 74,      /* û�п��е����������ڵ� */
    EGN_RET_IPF_HASH_MAGIC_ERR                       = 75,      /* �����Ӧ��hash�ڵ��magicֵ���� */
    EGN_RET_IPF_ABN_PACKET_ERR                       = 76,      /* ����������쳣���� */

    EGN_RET_THREAD_ID_INCONSISTENT_INSTANCE          = 77,      /* �ϲ������߳�ID��ʵ���б���Ĳ�һ�� */
    EGN_RET_THREAD_ID_INCONSISTENT_CTX               = 78,      /* �ϲ������߳�ID���м�״̬����Ĳ�һ�� */
    EGN_RET_PEERLIST_TIMEOUT_VALUE_BEYOND_CAPABILITY = 79,      /* ��ʱʱ�����ó�����Χ */
    EGN_RET_PEERLIST_PEER_NOT_FOUND                  = 80,      /* PEERû���ҵ� */
    EGN_RET_PEERLIST_IS_FULL                         = 81,      /* peerlist�������ǿ� */
    EGN_RET_PEERLIST_CONFIGURE_ERROR                 = 82,      /* PeerList���ô��� */
    EGN_RET_PEERSET_CACHE_IS_NOT_ENOUGH              = 83,      /* ���������Ԫ��ʱ��cache�Ŀռ䲻�� */

    EGN_RET_ADAPTER_LOCK_CRT_FAILURE                 = 84,      /* ����������ʧ�� */
    EGN_RET_ADAPTER_LOCK_ADD_FAILURE                 = 85,      /* ��д������ʧ�� */
    EGN_RET_ADAPTER_TIMERGRP_CRT_FAILURE             = 86,      /* ������ʱ������ʧ�� */
    EGN_RET_ADAPTER_TIMERGRP_START_FAILURE           = 87,      /* ������ʱ������ʧ�� */

    EGN_RET_CONTEXT_WITH_EXCEPTION                   = 88,      /* ������м�״̬���Ѿ����ֹ��쳣���м�״̬������ʶ�� */

    EGN_RET_INSPECT_TIME_OUT                         = 89,      /* ʶ��ʱ���������صĴ����� */
    EGN_RET_ENABLEMAGIC_INCONSISTENT_CTX             = 90,      /* ȫ��ʹ��magicֵ���м�״̬����Ĳ�һ�� */
    EGN_RET_ALLOC_OVERWRITE_FAILED                   = 91,      /* �ڴ��������з���дԽ����� */
    EGN_RET_PEERLIST_FLOW_PEER_IS_MAX                = 92,      /* ����������������ӹ���������Ѿ��ﵽ���� */
    EGN_RET_BYTE_CACHE_CTX_ABNORMAL                  = 93,      /* ȡ�ֽڻ��������쳣 */
    EGN_RET_NOT_SUPPORT_PROTOCOL_CTRL_STATE          = 94,      /* ��Э�鲻֧���û�������Ϣ */
    EGN_RET_FLOWCHANG_PROTOCOL_NOT_FOUND             = 95,      /* ֪ʶ����û�и������Э�� */
    EGN_RET_PEERLIST_NO_EXIST                        = 96,      /* ��ǰҪʹ�õĹ�������ʱ������ */
    EGN_RET_UD_PROTOCOL_ID_ERR                       = 97,      /* �Զ���Э��id���� */
    EGN_RET_UD_RULE_ID_ERR                           = 98,      /* �Զ������id���� */
    EGN_RET_UD_BEAR_ID_ERR                           = 99,      /* �Զ������id���� */
    EGN_RET_UD_WEIGHT_ERR                            = 100,     /* �Զ������Ȩ�ش��� */
    EGN_RET_UD_TRANS_TYPE_ERR                        = 101,     /* �Զ���������Э����� */
    EGN_RET_UD_RULE_NAME_ERR                         = 102,     /* �Զ���������ƴ��� */
    EGN_RET_UD_BEAR_INFO_ERR                         = 103,     /* �Զ�����������Ϣ���� */
    EGN_RET_UD_COND_LESS_ERR                         = 104,     /* �Զ����������������� */
    EGN_RET_UD_COND_NUM_ERR                          = 105,     /* �Զ������������������ */
    EGN_RET_UD_PCRE_COND_ERR                         = 106,     /* �Զ������pcre�������� */
    EGN_RET_UD_STR_COND_ERR                          = 107,     /* �Զ�������ַ����������� */
    EGN_RET_UD_DEPTH_COND_ERR                        = 108,     /* �Զ����������������� */
    EGN_RET_UD_PORT_COND_ERR                         = 109,     /* �Զ������˿ڴ��� */
    EGN_RET_UD_IP_VER_ERR                            = 110,     /* �Զ������ip�汾�Ŵ��� */
    EGN_RET_UD_IP_COND_ERR                           = 111,     /* �Զ������ip�������� */
    EGN_RET_UD_RULE_ID_REPEAT                        = 112,     /* �Զ�������ظ� */
    EGN_RET_UD_RULE_FULL                             = 113,     /* �Զ���������� */
    EGN_RET_UD_RULE_SWITCH_OFF                       = 114,     /* �Զ�������ܵĿ���Ϊ�ر� */
    EGN_RET_UD_NO_RULE_NEED_ACTIVE                   = 115,     /* �Զ��������Ҫ���� */
    EGN_RET_UD_RULE_NO_EXIST                         = 116,     /* ���Զ�����򲻴��� */
    EGN_RET_UD_RULE_BE_DELETED                       = 117,     /* �û��Զ�������Ѿ���ɾ�� */
    EGN_RET_UD_RULE_PATTERN_INVALID                  = 118,     /* �Զ���Ȳ����ģʽ���ﵽ���޻�Ϊ0 */
    EGN_RET_UD_ARITH_ENDIAN_INVALID                  = 119,     /* �Զ���Ȳ����ģʽ���ֽ������ */
    EGN_RET_UD_ARITH_FIELD_INVALID                   = 120,     /* �Զ���Ȳ����ģʽ�еȲ��ֶγ��ȴﵽ���޻�Ϊ0 */
    EGN_RET_UD_ARITH_OFFSETBASE_INVALID              = 121,     /* �Զ���Ȳ����ģʽ��ƫ�Ʒ������ */
    EGN_RET_UD_ARITH_OFFSET_IS_MAX                   = 122,     /* �Զ���Ȳ����ģʽ�е�ƫ�ƴﵽ���� */
    EGN_RET_UD_BEHA_RULE_PTN_PKTLENSEQ_INVALID       = 123,     /* �Զ���ͳ�ƹ���ģʽ������ֵ��Ч */
    EGN_RET_UD_PROTOCOL_ID_NO_EXIST                  = 124,     /* �Զ���Э��ID������ */
    EGN_RET_UD_BEAR_ID_NO_EXIST                      = 125,     /* �Զ������ID������ */
    EGN_RET_UD_APP_ID_ERR                            = 126,     /* �Զ���Ӧ��id���� */
    EGN_RET_UD_SRV_ID_ERR                            = 127,     /* �Զ������id���� */
    EGN_RET_STAT_INSPECT_SWITCH_OFF                  = 128,     /* ͳ��ʶ�𿪹�Ϊ�ر� */
    EGN_RET_NGFW_UD_APP_FULL                         = 129,     /* NGFW�Զ���Ӧ������ */
    EGN_RET_NGFW_UD_APP_NOT_EXIST                    = 130,     /* NGFW�Զ���Ӧ�ò����� */
    EGN_RET_NGFW_UD_RULE_NAME_COMFLICT               = 131,     /* NGFW�Զ���������� */
    EGN_RET_NGFW_UD_APP_RULE_FULL                    = 132,     /* NGFW�Զ��壬һ��Ӧ���µĹ������� */
    EGN_RET_NGFW_UD_ALL_RULE_FULL                    = 133,     /* NGFW�Զ��壬���й������� */
    EGN_RET_NGFW_UD_APP_NAME_REPEAT                  = 134,     /* NGFW�Զ���Ӧ���������ظ� */
    EGN_RET_NGFW_UD_APP_SOME_IN_USE                  = 135,     /* NGFW�Զ���Ӧ�ñ������û�ʹ�� */
    EGN_RET_NGFW_UD_APP_NO_RULE                      = 136,     /* NGFW�Զ���Ӧ����û�й��� */
    EGN_RET_NGFW_UD_APP_NO_SAMENAME_RULE             = 137,     /* NGFW�Զ���Ӧ����û����ͬ���ƵĹ��� */
    EGN_RET_DNS_PROTOCOL_INFO_ERR                    = 138,     /* �����DNS��Ϣ���� */
    EGN_RET_DNS_ANSWER_NOT_INSPECT                   = 139,     /* �����DNS��Ϣ��ʶ�� */
    EGN_RET_DNS_IP_IS_INEXISTENCE                    = 140,     /* �����IP������ */
    EGN_RET_NGFW_UD_APP_NO_SAME_PORT                 = 141,     /* NGFW�Զ���Ӧ����û����ͬ���ƵĹ��� */
    EGN_RET_NGFW_UD_APP_INVALID_IPV4                 = 142,     /* NGFW�Զ���Ӧ���¹����ipv4�����Ƿ� */
    EGN_RET_NGFW_UD_APP_INVALID_IPV6                 = 143,     /* NGFW�Զ���Ӧ���¹����ipv6�����Ƿ� */
    EGN_RET_NGFW_UD_APP_INVALID_PORT                 = 144,     /* NGFW�Զ���Ӧ���¹���Ķ˿������Ƿ� */
    EGN_RET_NGFW_UD_APP_INVALID_PATTERN              = 145,     /* NGFW�Զ���Ӧ���¹����ģʽ�������Ƿ� */
    EGN_RET_NGFW_UD_APP_INVALID_RULE_DESC            = 146,     /* NGFW�Զ���Ӧ���¹���������Ƿ� */
    EGN_RET_NGFW_UD_APP_INVALID_IP_NUM               = 147,     /* NGFW�Զ���Ӧ���¹����IP���������Ƿ� */
    EGN_RET_NGFW_UD_APP_INVALID_PORT_NUM             = 148,     /* NGFW�Զ���Ӧ���¹����Port���������Ƿ� */
    EGN_RET_NGFW_UD_BEING_ACTIVATED                  = 149,     /* �ڼ����Զ������󣬻�δ����Ӧ�ã��ͳ��Խ�����/ɾ/�Ĳ���;�����ظ��ļ����Զ������ */
    EGN_RET_NGFW_UD_APP_INVALID_TRANSTYPE            = 150,     /* NGFW�Զ���Ӧ���¹���Ĵ����Э��Ƿ� */
    EGN_RET_PROTO_DISABLE_CFG_FULL                   = 151,     /* Э��ȥʹ��������������EGN_MAX_DISABLED_PROTO_NUM */
    EGN_RET_PROTO_NOT_BE_UD_ID                       = 152,     /* Э��ȥʹ�����ò�֧���Զ���Э������� */
    EGN_RET_PROTO_INFO_RULE_LIB_NOT_INITED           = 153,     /* ����֪ʶ��δ��ʼ�� */
    EGN_RET_DNS_PARSE_OR_MATCH_NODE_IS_MAX           = 154,     /* ������DNS�еĻش���������Ѿ��ﵽ���� */
    EGN_RET_FRAG_INSPECT_PACKET_FRAG                 = 155,     /* ���ݰ�����Ƭ */
    EGN_RET_HA_INVALID_CONDITION_ID                  = 156,     /* Ӳ�������������ַǷ�����ID */
    EGN_RET_HA_INVALID_PATTERN_ID                    = 157,     /* Ӳ�������������ַǷ�ģʽ��ID */
    EGN_RET_NGFW_HA_SWITCH_OFF                       = 158,     /* Ӳ�����ٿ���û�д� */
    EGN_RET_NGFW_UD_RULE_IPV4_REPEAT                 = 159,     /* NGFW�Զ���Ӧ��������ͬ��ipv4���� */
    EGN_RET_NGFW_UD_RULE_IPV4_FULL                   = 160,     /* NGFW�Զ���Ӧ���µ�ipv4������������ */
    EGN_RET_NGFW_UD_RULE_IPV6_REPEAT                 = 161,     /* NGFW�Զ���Ӧ��������ͬ��ipv6����   */
    EGN_RET_NGFW_UD_RULE_IPV6_FULL                   = 162,     /* NGFW�Զ���Ӧ���µ�ipv6������������ */
    EGN_RET_NGFW_UD_RULE_PORT_REPEAT                 = 163,     /* NGFW�Զ���Ӧ���µ�����ͬ�Ķ˿����� */
    EGN_RET_NGFW_UD_RULE_PORT_FULL                   = 164,     /* NGFW�Զ���Ӧ���µĶ˿������������� */
    EGN_RET_NGFW_HA_MATCH_NUM_INVALID                = 165,     /* Ӳ������ƥ�䷵�ص�Ӳ��ƥ���������Ƿ� */
    EGN_RET_RULE_NUM_TO_MAX                          = 166,     /* ��������ﵽ��󣬰���ϵͳ���Զ���Ĺ��� */
    EGN_RET_END,

    EGN_RET_BOTTOM             = EGN_EN_BUTT
} EGN_RET_RESULT_EN;

/*ENUM< ֪ʶ��״̬���� >*/
typedef enum
{
    EGN_RULE_LIB_STATE_BEGIN          = EGN_EN_INVALID,
    EGN_RULE_LIB_STATE_INIT           = 0,                /* ֪ʶ���ʼ */
    EGN_RULE_LIB_STATE_ACTIVE         = 1,                /* ����״̬ */
    EGN_RULE_LIB_STATE_FROZEN         = 2,                /* ����״̬ */
    EGN_RULE_LIB_STATE_DEACTIVE       = 3,                /* ȥ����״̬ */
    EGN_RULE_LIB_STATE_END,

    EGN_RULE_LIB_STATE_BOTTOM       = EGN_EN_BUTT
}EGN_RULE_LIB_STATE_EN;

/*STRUCT< ReleaseDate�������� >*/
typedef struct _EgnReleaseDate
{
    EGN_UINT16  usYear;     /* �� */
    EGN_UINT8   ucMonth;    /* �� */
    EGN_UINT8   ucDay;      /* �� */
    EGN_UINT8   ucHour;     /* Сʱ */
    EGN_UINT8   ucMinute;   /* ���� */
    EGN_UINT8   ucSec;      /* �� */
    EGN_UINT8   ucReserved; /* �����ֽ� */
} EgnReleaseDate;

/*STRUCT< ����˵��:�汾��Version:01.0001.0054.01 >*/
typedef struct _EgnRuleLibVersionNum
{
    EGN_UINT16  usMajorVersion;         /* ��汾��AA,��Ӧ�����е�01 */
    EGN_UINT16  usCompatibleVersion;    /* �����԰汾��XXXX,��Ӧ�����е�0001 */
    EGN_UINT16  usSnapShotVersion;      /* ֪ʶ����հ汾BBBB,��Ӧ�����е�0054 */
    EGN_UINT16  usSnapShotSubVersion;   /* ֪ʶ������������Ӱ汾��CC,��Ӧ�����е�01 */
} EgnRuleLibVersionNum;

/*STRUCT< ����˵��:01.0001.0054.01.20090530.14:48:50 >*/
typedef struct _EgnRuleLibVersion
{
    EgnReleaseDate          stReleaseDate;      /* ��������,��Ӧ�����е�20090530.14:48:50 */
    EgnRuleLibVersionNum    stLibVersionNum;    /* �汾�ţ�������ṹ�� */
} EgnRuleLibVersion;

/*STRUCT< Э�鵼�����ýṹ >*/
typedef struct _EgnProtoImportCfgInfo
{
    EGN_UINT32  ulProtoID;      /* Э��ID */
    EGN_BOOL    bIsImport;      /* �Ƿ���Ҫ���룬0��ʾ�����룬����ʾ���� */
} EgnProtoImportCfgInfo;

/*STRUCT< ���������ýṹ >*/
typedef struct _EgnRuleImportCfgInfo
{
    EGN_UINT32  ulRuleID;      /* ����ID */
    EGN_BOOL    bIsImport;      /* �Ƿ���Ҫ���룬0��ʾ�����룬����ʾ���� */
} EgnRuleImportCfgInfo;

/*STRUCT< Э������������ýṹ >*/
typedef struct _EgnProtoRelParseCfgInfo
{
    EGN_UINT32   ulProtoId;    /* Э��ID */
    EGN_BOOL     bIsEnable;    /* �Ƿ���Ҫ����������Э��,EGN_FALSE��ʾ�Ѿ����ùرո�Э��Ľ������� */
    EGN_BOOL     bIsInCrtRuleLib;    /* ��Э���Ƿ��ڵ�ǰ֪ʶ���д��� */
#ifdef EGN_64
    EGN_UINT8    aucReserved[4];     /* 64λ���뱣���ֽ� */
#endif
} EgnProtoRelParseCfgInfo;

/*ENUM< �㼶���װ�ʶ�𿪹ص�״̬ >*/
typedef enum
{
    EGN_HIER_DET_STATE_OFF      = 0,     /* �رղ㼶���װ�ʶ�� */
    EGN_HIER_DET_STATE_DEFAULT  = 2,     /* Ĭ��״̬����ȫ�ֲ㼶ʶ�����з�ͬ��ʶ����ȫ�ֿ���(EgnInitCfgParam�е�bHierInspectSwitch)Ϊ׼ */
    EGN_HIER_DET_STATE_ON       = 0xffff,/* �򿪲㼶���װ�ʶ�� */
    EGN_HIER_DET_STATE_END,

    EGN_HIER_DET_STATE_BOTTOM   = EGN_EN_BUTT
}EGN_HIER_DET_STATE;

/*STRUCT< �㼶���װ�ʶ�𿪹�״̬��Ϣ�ṹ >*/
typedef struct _EgnHierMaxDetCntInfo
{
    EGN_UINT32  ulProtoID;             /* �����ò㼶���װ�ʶ�𿪹ص�״̬��Э��ID */
    EGN_UINT16  usHierMaxDetCnt;        /* ulProtoID��Ӧ�Ĳ㼶���װ�ʶ�𿪹ص�״̬����ӦEGN_HIER_DET_STATE */
    EGN_UINT8   ucIsInCrtRuleLib;      /* ��Э���Ƿ��ڵ�ǰ֪ʶ���д��ڣ�EGN_PROTOCOL_VALIDE_STATE_EN */
    EGN_UINT8   ucReserved;            /* ���뱣���ֽ� */
} EgnHierMaxDetCntInfo;

/*STRUCT< �㼶���װ�ʶ�𿪹�״̬�ṹ >*/
typedef struct _EgnHierMaxDetCnt
{
    EGN_UINT32  ulProtoID;             /* �����ò㼶���װ�ʶ�𿪹ص�״̬��Э��ID */
    EGN_UINT16  usHierMaxDetCnt;       /* ulProtoID��Ӧ�Ĳ㼶���װ�ʶ�𿪹ص�״̬����ӦEGN_HIER_DET_STATE */
    EGN_UINT8   aucReserved[2];        /* ���뱣���ֽ� */
} EgnHierMaxDetCnt;

/*STRUCT< �ڴ��ͳ����Ϣ >*/
typedef struct _EgnBufStatPoolMemInfo
{
    EGN_UINT32  ulBlockSize;     /* ���С */
    EGN_UINT32  ulListSize;      /* ������� */
    EGN_UINT32  ulNoOfFreeElmnt; /* ���ʣ����� */
    EGN_UINT32  ulFirstOccLoc;   /* ��һ�����п��λ�� */
    EGN_UINT32  ulLastOccLoc;    /* ���һ�����п��λ�� */
#ifdef EGN_64
    EGN_UINT8              aucReserved[4];     /* 64λ���뱣���ֽ� */
#endif
}EgnBufStatPoolMemInfo;

/*STRUCT< �ڴ����Ϣ >*/
typedef struct _EgnBufStatInfo
{
    EGN_UINT32             ulBufPoolNum;       /* �ڴ����Ŀ */
#ifdef EGN_64
    EGN_UINT8              aucReserved[4];     /* 64λ���뱣���ֽ� */
#endif
    EgnBufStatPoolMemInfo  stMemInfo[EGN_MEMCP_INIT_MAX_COUNT];  /* �ڴ���Ϣ */
}EgnBufStatInfo;

/*ENUM< ֧�ֵĸ澯��ֵ���ඨ�� >*/
typedef enum
{
    EGN_RESALARMTHRESHOLD_BEGIN       = EGN_EN_INVALID,
    EGN_RESALARMTHRESHOLD_RULELIB     = 0,                /* EGN֪ʶ�ֵⷧ���� */
    EGN_RESALARMTHRESHOLD_CTX         = 1,                /* EGN�м�״̬��ֵ���� */
    EGN_RESALARMTHRESHOLD_PEERLIST    = 2,                /* EGN������ֵ���� */
    EGN_RESALARMTHRESHOLD_END,

    EGN_RESALARMTHRESHOLD_BOTTOM      = EGN_EN_BUTT
}EGN_RESALARMTHRESHOLD_EN;

/*MACRO< ֧�ֵĸ澯ֵ���� >*/
#define EGN_RESALARMTHRESHOLD_MAX_SIZE   (95)

/*MACRO< ֧�ֵĸ澯ֵ���� >*/
#define EGN_RESALARMTHRESHOLD_MIN_SIZE   (50)

/*MACRO< �ַ�����󳤶� >*/
#define  EGN_UNITE_QUERY_STRING_LEN_MAX   512

/*ENUM< ��ȡ��Ϣ�����ͣ��������ͷ����ڴ� >*/
typedef enum
{
    EGN_UNITE_GET_SET_BEGIN           = EGN_EN_INVALID,
    EGN_UNITE_GET_SET_ENGINE_VERSION  = 0,                  /* ����汾��,ֻ�ܲ�ѯ��EGN_UCHAR */
    EGN_UNITE_GET_SET_RULELIB_VERSION,                      /* ֪ʶ��汾�ţ�ֻ�ܲ�ѯ��EGN_UCHAR */
    EGN_UNITE_GET_SET_PEER_INFO,                            /* PEER��Ϣ��ֻ�ܲ�ѯ��EgnPeerInfo */
    EGN_UNITE_GET_SET_EGN_STATE,                            /* EGN״̬��Ϣ��ֻ�ܲ�ѯ��EGN_UINT32��0:δ��ʼ����1:ʹ�ܣ�2:����ȥʹ�ܣ�3:ȥʹ�ܣ�4:ȥ��ʼ���� */
    EGN_UNITE_GET_SET_CTX_STATIC_INFO,                      /* �м�״̬��Ŀ��ֻ�ܲ�ѯ��EgnCtxNumInfo */
    EGN_UNITE_GET_SET_PACKET_STATIC_INFO,                   /* ����ͳ����Ϣ��ֻ�ܲ�ѯ��EgnPacketStatInfo */
    EGN_UNITE_GET_SET_HEALTH_INFO,                          /* ������Ϣ��ֻ�ܲ�ѯ��EGN_UCHAR */
    EGN_UNITE_GET_SET_RULELIB_BLOCK_INFO,                   /* ֪ʶ���ڴ��ʹ�����(��̬ģʽ��)��ֻ�ܲ�ѯ��EgnRuleLibBlockInfo */
    EGN_UNITE_GET_SET_STATIC_ERR_INFO,                      /* ����ͳ����Ϣ��ֻ�ܲ�ѯ��EgnErrInfo */
    EGN_UNITE_GET_SET_RUEL_LIB_STATE_INFO,                  /* ֪ʶ��״̬��Ϣ��ֻ�ܲ�ѯ��EgnRuleLibState */
    EGN_UNITE_GET_SET_DYNMEM_INFO,                          /* AR������ڴ���Ϣ��ֻ�ܲ�ѯ��EgnDynMemInfo */
    EGN_UNITE_GET_SET_STATIC_BLOCK_INFO,                    /* ȫ�־�̬�ڴ����ֻ�ܲ�ѯ��EgnStaticMemBlockInfo */
    EGN_UNITE_GET_SET_CB_STATIC_INFO,                       /* CB������Ϣ��ֻ�ܲ�ѯ��EgnCBStaticInfo */
    EGN_UNITE_GET_SET_MATCHED_RULE_INFO,                    /* ��ǰ�������еĹ�����Ϣ��ֻ�ܲ�ѯ��EGN_UINT32 */
    EGN_UNITE_GET_SET_SYSMEMMODE_INFO,                      /* ϵͳ�ڴ�ģʽ��Ϣ��ֻ�ܲ�ѯ��EGN_UINT32��0:��̬��1:��̬ */
    EGN_UNITE_GET_SET_OPTIMAL_RESULT_MODE_SWITCH_INFO,      /* ����ʶ����ģʽ���أ�ֻ�ܲ�ѯ��EGN_UINT32 */
    EGN_UNITE_GET_SET_RULE_STAT_INFO,                       /* ����ͳ����Ϣ��ֻ�ܲ�ѯ��EgnGetRuleStatInfo */
    EGN_UNITE_GET_SET_STAT_INFO,                            /* �ڲ�ͳ����Ϣ��ֻ�ܲ�ѯ��EgnStatInfo */
    EGN_UNITE_GET_SET_DETECT_THRESHOLD,                     /* ʶ��ֵ���ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_FAST_RELSWITCH_INFO,                  /* ���ٹ���������Ϣ���ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_ROLLBACK_TIME,                        /* ���˱���ʱ�����ɲ�ѯ����̬����̬���ã�EGN_UINT32,��λ:�� */
    EGN_UNITE_GET_SET_WELLKNOWN_PORT_SWITCH,                /* ֪���˿ڿ�����Ϣ���ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_STATINSPECT_SWITCH,                   /* ͳ��ʶ�𿪹���Ϣ���ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_NOTFIRSTPKT_RELINSPECT_SWITCH_INFO,   /* ���װ�����ʶ�𿪹���Ϣ���ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_HIERINSPECT_SWITCH,                   /* �㼶ʶ�����з��װ����أ��ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_UNSYMMETRICAL_INSPECT_SWITCH_INFO,    /* �ǶԳ�ʶ�𿪹���Ϣ���ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_BEHAVIOR_INSPECT_STATE,               /* ��Ϊ����ʶ���ܿ���״̬���ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_IP_FLOW_AGED_TIME,                    /* �����ϻ�ʱ�䣬�ɲ�ѯ����̬����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_DNS_REL_SWTICH,                       /* DNS����ʶ�𿪹أ��ɲ�ѯ����̬����̬����(��̬���ò�֧�ִӹص���״̬������)��EGN_UINT32 */
    EGN_UNITE_GET_SET_STAT_CONTROL,                         /* EGNͳ�ƹ��ܣ���ѯʱ��ӦEgnGetStatControl����̬���ö�ӦEGN_UINT32����̬���ö�ӦEgnSetStatControl */
    EGN_UNITE_GET_SET_MAX_INSTANCE_INFO,                    /* ���ʵ��������Ϣ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_SCAN_INTERVAL,                        /* �ϻ�ɨ���ʱ�������ɲ�ѯ����̬���ã�EGN_UINT32 ��λ: ���� */
    EGN_UNITE_GET_SET_FAST_RELAGING_TIME,                   /* ���ٹ����ϻ�ʱ�䣬�ɲ�ѯ����̬��EGN_UINT32����λ:����  */
    EGN_UNITE_GET_SET_WEAK_RELATION_SWITCH,                 /* ������ʶ�𿪹أ��ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_FLOWSCALE_INFO,                       /* ����ģ��Ϣ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_MEMPLICY_INFO,                        /* �ڴ����÷�ʽ��Ϣ���ɲ�ѯ����̬���ã�EGN_UINT32��0:�����ޣ�1:���� */
    EGN_UNITE_GET_SET_NGFW_UD_APP_SWITCH_INFO,              /* �û�NGFW�Զ�����ƿ�����Ϣ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_NGFW_HA_SWITCH,                       /* NGFW��Ʒ����Ӳ�����ٵ����ã��ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_FRAG_SWITCH_INFO,                     /* ��Ƭ���ƿ�����Ϣ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_UDRULE_SWITCH_INFO,                   /* �û��Զ�����ƿ�����Ϣ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_PROTO_IMPORT_STATE,                   /* Э���Ƿ������Ϣ���ɲ�ѯ����̬���ã���ѯʱ��ӦEgnGetProtoImport����̬����ʱ��ӦEgnSetProtoImportOrRelParse */
    EGN_UNITE_GET_SET_PROTO_REL_PARSE_STATE,                /* Э�鲻������������Ϣ���ɲ�ѯ����̬���ã���ѯʱ��ӦEgnGetProtoRelParse����̬����ʱ��ӦEgnSetProtoImportOrRelParse */
    EGN_UNITE_GET_SET_PROTO_HIER_INSPECT_STATE,             /* Э��㼶ʶ��ֵ����Ϣ���ɲ�ѯ����̬���ã���ѯʱ��ӦEgnGetProtoHierInspect����̬����ʱ��ӦEgnSetProtoHierInspect */
    EGN_UNITE_GET_SET_RULE_IMPORT_STATE,                    /* �����Ƿ������Ϣ(Ŀǰֻ֧��BT��Ϊʶ�����)���ɲ�ѯ����̬���ã���ѯʱ��ӦEgnGetRuleImport����̬����ʱ��ӦEgnSetRuleImport */
    EGN_UNITE_GET_SET_ALARM_THRESHOLD,                      /* �澯ֵ��Ϣ���ɲ�ѯ����̬���ã���ѯʱ��ӦEgnGetResAlarmThreshold����̬����ʱ��ӦEgnSetResAlarmThreshold */
    EGN_UNITE_GET_SET_ATTR_TYPE_CFG,                        /* ��������������Ϣ���ɲ�ѯ����̬���ã���ѯʱ��ӦEgnGetAttrTypeCfg����̬����ʱ��ӦEgnSetAttrTypeCfgInfo */
    EGN_UNITE_GET_SET_CFG_PARA_IS_SHARE,                    /* ������Ϣ�Ƿ����ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_RULELIB_IS_SHARE,                     /* ֪ʶ���Ƿ����ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_MEM_IS_SHARE,                         /* �Ƿ����ڴ棬�ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_REL_CB_NUM_IPV4,                      /* IPv4����ʶ��CB�����Ŀ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_REL_CB_NUM_IPV6,                      /* IPv6����ʶ��CB�����Ŀ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_MAX_RELAGE_NUM,                       /* �������ϻ����ޣ��ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_DNS_REL_CB_NUM_IPV4,                  /* DNS����ʶ��IPv4��CB�����Ŀ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_DNS_REL_CB_NUM_IPV6,                  /* DNS����ʶ��IPv6��CB�����Ŀ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_NEED_SUPER_CLASS,                     /* ʶ�������Ƿ���Ҫ���ش��ࡢ�����Ӧ��id��Ϣ���أ��ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_UD_BACK_RULE_LIB_NEED_MEM,            /* �û��Զ�����򱸷�����֪ʶ�������ڴ棬�ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_SN_CB_STATIC_INFO,                    /* session CB������Ϣ��ֻ�ܲ�ѯ��EgnCBStaticInfo */
    EGN_UNITE_GET_SET_SN_STATIC_BLOCK_INFO,                 /* session ȫ�־�̬�ڴ����ֻ�ܲ�ѯ��EgnStaticMemBlockInfo */
    EGN_UNITE_GET_SET_SN_SWITCH,                            /* session������Ϣ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_SN_FLOWSCALE,                         /* session����ģ��Ϣ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_SN_REL_CB_NUM_IPV4,                   /* session IPv4����ʶ��CB�����Ŀ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_SN_REL_CB_NUM_IPV6,                   /* session IPv6����ʶ��CB�����Ŀ���ɲ�ѯ����̬���ã�EGN_UINT32 */
    EGN_UNITE_GET_SET_SN_BODY_MEM_CACHE,                    /* session ������������ݵĴ�С���ɲ�ѯ����̬���ã�Ĭ��Ϊ2K�����ô�С������ڵ���1K��EGN_UINT32 */
    EGN_UNITE_GET_SET_SN_BODY_MEM_DECOMPRESS,               /* session �����ѹ���ݵĴ�С���ɲ�ѯ����̬���ã�Ĭ��Ϊ6K�����ô�С������ڵ���1K���Ҵ��ڵ���session ������������ݵĴ�С������ʱͨ��������session ������������ݵĴ�СEGN_UINT32 */

    EGN_UNITE_GET_SET_END,

    EGN_UNITE_GET_SET_BOTTOM     = EGN_EN_BUTT
}EGN_UNITE_GET_SET_EN;

/*STRUCT< peer��Ϣ�Ľṹ >*/
typedef struct _EgnPeerInfo
{
    EGN_UINT32   ulRelItemAddedCnt;      /* ��ӵĹ���������� */
    EGN_UINT32   ulRelItemDestroyedCnt;  /* �����������ٸ��� */
} EgnPeerInfo;

/*STRUCT< �м�״̬��Ϣ�Ľṹ >*/
typedef struct _EgnCtxNumInfo
{
    EGN_UINT32   ulCurCtxNum;         /* ��ǰ�м�״̬����Ŀ */
    EGN_UINT32   ulCurCtxNumWithRel;  /* ��ǰ����ʶ���м�״̬����Ŀ */
}EgnCtxNumInfo;

/*STRUCT< ��̬�ڴ���Ϣ�Ľṹ >*/
typedef struct _EgnDynMemInfo
{
    EGN_UINT32   ulMemCpAllocTimes;     /* MemCp������� */
    EGN_UINT32   ulMemCpAllocSize;      /* MemCp�����С */
    EGN_UINT32   ulDynAllocTimes;       /* DynAlloc������� */
    EGN_UINT32   ulDynAllocSize;        /* DynAlloc�����С */
    EGN_UINT32   ulRuleLibDynAllocSize; /* ֪ʶ���ڴ��С */
#ifdef EGN_64
    EGN_UINT8    aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
}EgnDynMemInfo;

/*STRUCT< ֪ʶ���ڴ����Ϣ�Ľṹ >*/
typedef struct _EgnRuleLibBlockInfo
{
    EGN_UINT32   ulMemTotalSize;      /* ֪ʶ���ܵ��ڴ��С */
    EGN_UINT32   ulMemUsedSize;       /* ʹ�õ��ڴ��С */
}EgnRuleLibBlockInfo;

/*STRUCT< ����ͳ����Ϣ >*/
typedef struct _EgnErrInfo
{
    EGN_UINT32     ulAllocFailedNum;        /* �ڴ����ʧ�ܴ��� */
    EGN_UINT32     ulMemRepeatFreeNum;      /* Bufmem�ظ��ͷŴ��� */
    EGN_UINT32     ulReLoadNum;             /* �ظ����ش��� */
    EGN_UINT32     ulReleaseIsGoing;        /* ��֪ʶ�������ͷ� */
    EGN_UINT32     ulCreatBufMemFailedNum;  /* ����BufMemʧ�ܴ��� */
    EGN_UINT32     ulThreadIdInconInstance; /* �ϲ������߳�ID��ʵ���б���Ĳ�һ�� */
    EGN_UINT32     ulThreadIdInconCtx;      /* �ϲ������߳�ID���м�״̬����Ĳ�һ�� */
    EGN_UINT32     ulPeerListIsFull;        /* peerlist���� */
    EGN_UINT32     ulPeerCacheNotEnough;    /* ���������Ԫ��ʱ��cache�Ŀռ䲻�� */
    EGN_UINT32     ulInspectTimeOut;        /* ʶ��ʱ */
    EGN_UINT32     ulAllocOverwriteFailed;  /* �ڴ��������з���дԽ����� */
    EGN_UINT32     ulPeerListFlowIsMax;     /* ����������������ӹ���������Ѿ��ﵽ���� */
    EGN_UINT32     ulPeerListMaxCollision;  /* ��ͻ����peer���ﵽ���� */
    EGN_UINT32     ulStatAllocFailedNum;    /* ͳ��ʧ�ܷ����ڴ�ʧ�� */
    EGN_UINT32     ulStatCreateBufFailedNum;  /* ͳ��ʶ�𴴽�Bufmemʧ�� */
#ifdef EGN_64
    EGN_UINT8      aucReserved[4];          /* 64λ���뱣���ֽ� */
#endif
}EgnErrInfo;

/*STRUCT< ����ͳ����Ϣ�Ľṹ >*/
typedef struct _EgnPacketStatInfo
{
    EGN_UINT32     ulPacketCount;       /* ����ʶ����ܰ��� */
    EGN_UINT32     ulSuccessCount;      /* ʶ��ɹ����� */
    EGN_UINT32     ulFailCount;         /* ʶ��ʧ�ܰ��� */
    EGN_UINT32     ulUnknownCount;      /* δʶ����� */
    EGN_UINT32     ulFinishCnt;         /* ʶ��������� */
    EGN_UINT32     ulRelCnt;            /* ��Ҫ����ʶ����� */
}EgnPacketStatInfo;

/*STRUCT< ֪ʶ��״̬�Ľṹ >*/
typedef struct _EgnRuleLibState
{
    EGN_UINT32     ulMasterRuleLibIdx;    /* ��֪ʶ�������� */
    EGN_UINT32     ulMasterRuleLibState;  /* ��֪ʶ��״̬ */
    EGN_UINT32     ulSlaveRuleLibState;   /* ��֪ʶ��״̬ */
#ifdef EGN_64
    EGN_UINT8      aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
}EgnRuleLibState;

/*STRUCT< CB������Ϣ�Ľṹ >*/
typedef struct _EgnCBStaticInfo
{
    EGN_UINT32     ulTotalNumIpv4;    /* IPv4�ܹ���CB�� */
    EGN_UINT32     ulTotalNumIpv6;    /* IPv6�ܹ���CB�� */
    EGN_UINT32     ulUsedNumIpv4;     /* IPv4ʹ�õ�CB�� */
    EGN_UINT32     ulUsedNumIpv6;     /* IPv6ʹ�õ�CB�� */
}EgnCBStaticInfo;

/*STRUCT< Block��Ϣ�Ľṹ >*/
typedef struct _EgnBpBlockInfo
{
    EGN_UINT32     ulEachBlockMemSize;    /* �ڴ���С */
    EGN_UINT32     ulBockNum;             /* ������ */
    EGN_UINT32     ulNoOfFreeElmnt;       /* ʣ����� */
    EGN_UINT32     ulFirstOccLoc;         /* ��һ������Ԫ�ص�λ�� */
    EGN_UINT32     ulLastOccLoc;          /* ���һ������Ԫ�ص�λ�� */
#ifdef EGN_64
    EGN_UINT8      aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
}EgnBpBlockInfo;

/*STRUCT< ��̬�ڴ���Ϣ�Ľṹ >*/
typedef struct _EgnStaticMemBlockInfo
{
    EGN_UINT32       ulBlockTypeNum;    /* Block���͵����� */
#ifdef EGN_64
    EGN_UINT8        aucReserved[4];    /* 64λ���뱣���ֽ� */
#endif
    EgnBpBlockInfo   stBlockInfo[EGN_MEMCP_INIT_MAX_COUNT]; /* Block��Ϣ */
}EgnStaticMemBlockInfo;

/*STRUCT< ��ѯЭ���Ƿ������Ϣ >*/
typedef struct _EgnGetProtoImport
{
    EGN_UINT32               ulInProtoID;            /* ��ѯ��Э��ID����ID��Ϊ0ʱ����ѯ����Э�飬��IDΪ0ʱ����ѯ���������õ�Э�鵼����Ϣ */
    EGN_UINT32               ulInOutItemNum;         /* ��Ϊ����ʱΪ������Ϣ�����������Ϊ���Ϊ���������� */
    EgnProtoImportCfgInfo   *pstOutProtoImportInfo;  /* Э�鵼��������Ϣ���飬�����ulInOutItemNumΪ������ڴ� */
}EgnGetProtoImport;

/*STRUCT< ��ѯЭ�鲻������������Ϣ >*/
typedef struct _EgnGetProtoRelParse
{
    EGN_UINT32               ulInProtoID;             /* ��ѯ��Э��ID����ID��Ϊ0ʱ����ѯ����Э�飬��IDΪ0ʱ����ѯ���������õ�Э�����������Ϣ */
    EGN_UINT32               ulInOutItemNum;          /* ��Ϊ����ʱΪ������Ϣ�����������Ϊ���Ϊ���������� */
    EgnProtoRelParseCfgInfo *pstOutProtoRelParseInfo; /* Э���������������Ϣ���飬�����ulInOutItemNumΪ������ڴ� */
}EgnGetProtoRelParse;

/*STRUCT< ��ѯЭ��㼶ʶ��ֵ����Ϣ >*/
typedef struct _EgnGetProtoHierInspect
{
    EGN_UINT32             ulInProtoID;             /* ��ѯ��Э��ID����ID��Ϊ0ʱ����ѯ����Э�飬��IDΪ0ʱ����ѯ���������õ�Э��㼶ʶ���ͬ��ʶ�𿪹ص���Ϣ */
    EGN_UINT32             ulInOutItemNum;          /* ��Ϊ����ʱΪ������Ϣ�����������Ϊ���Ϊ���������� */
    EgnHierMaxDetCntInfo  *pstOutHierMaxDetCntInfo; /* �㼶���װ�ʶ�𿪹�״̬������Ϣ���飬�����ulInOutItemNumΪ������ڴ� */
}EgnGetProtoHierInspect;

/*STRUCT< ��ѯ�����Ƿ������Ϣ >*/
typedef struct _EgnGetRuleImport
{
    EGN_UINT32             ulInRuleID;              /* ��ѯ�Ĺ���ID��Ŀǰֻ֧��BT��Ϊʶ�����ID,8155 */
    EGN_UINT32             ulInOutItemNum;          /* ��Ϊ����ʱΪ������Ϣ�����������Ϊ���Ϊ���������� */
    EgnRuleImportCfgInfo  *pstOutRuleImportCfgInfo; /* ������������Ϣ����,�����ulInOutItemNum������Ӧ�ڴ� */
}EgnGetRuleImport;

/*STRUCT< �澯ֵ��ѯ >*/
typedef struct _EgnGetResAlarmThreshold
{
    EGN_UINT32      ulInType;           /* ��Ҫ��ѯ�ĸ澯ֵ���� */
    EGN_UINT32      ulOutThreshold;     /* ��õľ������޸澯ֵ����ֵ��ȡֵ��Χ[50-95]��Ĭ��ֵ85 */
}EgnGetResAlarmThreshold;

/*STRUCT< ���������Ƿ�ʶ�� >*/
typedef struct _EgnGetAttrTypeCfg
{
    EGN_UINT32   ulInAttrTypeID;        /* ��������id */
    EGN_BOOL     bOutIsEnable;          /* �Ƿ�ʶ�� */
}EgnGetAttrTypeCfg;

/*STRUCT< ��ѯ����ͳ����Ϣ >*/
typedef struct _EgnGetRuleStatInfo
{
    EGN_UINT32         ulInStatRdNum;       /* �ڴ���ͳ�Ƽ�¼��Ŀ */
    EGN_UINT32         ulOutGetedRdNum;     /* ʵ�ʻ�õ�ͳ�Ƽ�¼��Ŀ */
    EgnRuleStatRd     *pstOutRuleStatRd;    /* �����ѯ��¼���ڴ棬�����ulInStatRdNumΪ������ڴ� */
}EgnGetRuleStatInfo;

/*STRUCT< ��ѯEGNͳ�ƹ��� >*/
typedef struct _EgnGetStatControl
{
    EGN_UINT32    ulInCommand;      /* ͳ�ƹ������ͣ�ȡֵ��ΧΪEGN_STAT_ONOFF_SWITCH ��EGN_STAT_PROTOID_SET */
    EGN_UINT32    ulOutContent;     /* ulInCommandΪ0ʱ����ʾ�û����õ�ͳ�ƿ���ֵ����ֵ��ȡ0��1��ulInCommandΪ1����ʾ�û����õ�Э��ID(��������ã�Ĭ��Ϊ11) */
}EgnGetStatControl;

/*STRUCT< ��ѯ����Ϣ >*/
typedef struct _EgnGetCfgInfo
{
    union
    {
        EGN_UINT32               ulOutGetValue;                             /* ��ȡ���������͵�ֵ */
        EGN_UCHAR                aucString[EGN_UNITE_QUERY_STRING_LEN_MAX]; /* �ַ���������Ϣ */
        EgnPeerInfo              stPeerInfo;                                /* Peer��Ϣ */
        EgnCtxNumInfo            stCtxNumInfo;                              /* �м�״̬��Ϣ */
        EgnDynMemInfo            stDynMemInfo;                              /* ��̬�ڴ���Ϣ */
        EgnRuleLibBlockInfo      stRuleLibBlockInfo;                        /* ֪ʶ���ڴ����Ϣ */
        EgnStaticMemBlockInfo    stStaticMemBlockInfo;                      /* ��̬�ڴ���Ϣ */
        EgnErrInfo               stErrInfo;                                 /* ����ͳ����Ϣ */
        EgnPacketStatInfo        stPacketStatInfo;                          /* ����ͳ����Ϣ */
        EgnRuleLibState          stRuleLibState;                            /* ֪ʶ��״̬ */
        EgnCBStaticInfo          stCBStaticInfo;                            /* CB������Ϣ */
        EgnGetProtoImport        stGetProtoImport;                          /* Э���Ƿ������Ϣ */
        EgnGetProtoRelParse      stGetProtoRelParse;                        /* Э�鲻������������Ϣ */
        EgnGetProtoHierInspect   stGetProtoHierInspect;                     /* Э��㼶ʶ�𿪹�״̬����Ϣ */
        EgnGetRuleImport         stGetRuleImport;                           /* �����Ƿ������Ϣ */
        EgnGetResAlarmThreshold  stGetResAlarmThreshold;                    /* �澯ֵ��ѯ */
        EgnGetAttrTypeCfg        stGetAttrTypeCfg;                          /* ���������Ƿ�ʶ�� */
        EgnGetRuleStatInfo       stGetRuleStatInfo;                         /* ����ͳ����Ϣ */
        EgnGetStatControl        stGetStatControl;                          /* EGNͳ�ƹ��� */
        EgnStatInfo              stStatInfo;                                /* ͳ���� */
    }GetCfgInfoUn;
} EgnGetCfgInfo;

/*STRUCT< ����һ��Э���Ƿ���/һ��Э������������صĽṹ >*/
typedef struct _EgnSetProtoImportOrRelParse
{
    EGN_UINT32   ulInProtoNum;          /* Э��������Ϣ�ĸ��� */
    EGN_BOOL     bInIsEnable;           /* Э���Ƿ��� */
    EGN_UINT32  *pulInOutProtoIdList;   /* Э���б�ʧ��ʱΪ����ʧ�ܵ�Э�顣��Ϊ���ʱ�����ulInProtoNum����������Ӧ�ڴ� */
    EGN_UINT32   ulOutFailNum;          /* ����ʧ�ܵ���Ŀ */
#ifdef EGN_64
    EGN_UINT8    aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
}EgnSetProtoImportOrRelParse;

/*STRUCT< ����һ��Э��Ĳ㼶ʶ��������ķ�ֵ >*/
typedef struct _EgnSetProtoHierInspect
{
    EGN_UINT32           ulInProtoNum;          /* Э��������Ϣ�ĸ��� */
    EGN_UINT32           ulOutFailNum;          /* ����ʧ�ܵ���Ŀ */
    EgnHierMaxDetCnt    *pstInOutProtoIdList;   /* ����:�û�Ҫ���õ�Э���б����:ʧ��ʱ����ʧ�ܵ�Э���б���Ϊ���ʱ�����ulInProtoNum�����ڴ� */
}EgnSetProtoHierInspect;

/*STRUCT< ���ù����Ƿ��� >*/
typedef struct _EgnSetRuleImport
{
    EGN_UINT32   ulInRuleNum;           /* ����������Ϣ�ĸ��� */
    EGN_BOOL     bInIsEnable;           /* �����Ƿ��� */
    EGN_UINT32  *pulInOutRuleIdList;    /* �����б�ʧ��ʱΪ����ʧ�ܵĹ���Ŀǰֻ֧��BT��Ϊʶ�������Ϊ���ʱ�����ulInProtoNum����������Ӧ�ڴ� */
    EGN_UINT32   ulOutFailNum;          /* ����ʧ�ܵ���Ŀ */
#ifdef EGN_64
    EGN_UINT8    aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
}EgnSetRuleImport;

/*STRUCT< ���ø澯ֵ >*/
typedef struct _EgnSetResAlarmThreshold
{
    EGN_UINT32  ulInType;       /* �澯ֵ���� */
    EGN_UINT32  ulInThreshold;  /* �������޸澯ֵ����ֵ��ȡֵ��Χ[50-95]��Ĭ��ֵ85�� */
}EgnSetResAlarmThreshold;

/*STRUCT< �������������Ƿ�ʶ��Ľṹ�� >*/
typedef struct _EgnSetAttrTypeCfgInfo
{
    EGN_UINT32   ulInAttrTypeId;    /* �������� */
    EGN_BOOL     bInIsEnable;       /* �Ƿ�ʶ�� */
}EgnSetAttrTypeCfgInfo;

/*STRUCT< ����EGNͳ�ƹ��� >*/
typedef struct _EgnSetStatControl
{
    EGN_UINT32    ulInCommand;  /* ͳ�ƹ������͡�ȡֵ��ΧΪEGN_STAT_ONOFF_SWITCH��EGN_STAT_PROTOID_SET */
    EGN_UINT32    ulInContent;  /* �����õ�ֵ��ulInCommandΪEGN_STAT_ONOFF_SWITCHʱ��ulInContent��ʾͳ�ƿ��ص�ֵ������ȡEGN_TRUE��EGN_FALSE; ulInCommandΪEGN_STAT_PROTOID_SETʱ��ulInContent��ʾ��ͳ�Ƶ�һ��Э��IDֵ��Ĭ����EGN_PROTO_ID_BT_DATA_TCP) */
}EgnSetStatControl;

/*STRUCT< ��������Ϣ�Ľṹ�� >*/
typedef struct _EgnSetCfgParamInfo
{
    union
    {
        EGN_UINT32                  ulInSetValue;               /* �����õ��������͵�ֵ */
        EgnSetProtoImportOrRelParse stProtoImportOrRelParse;    /* �����õ�Э�鵼��������Ϣ */
        EgnSetProtoHierInspect      stProtoHierInspect;         /* �����õĲ㼶ʶ��ֵ */
        EgnSetRuleImport            stRuleImport;               /* �����õĹ�������Ϣ */
        EgnSetResAlarmThreshold     stResAlarmThreshold;        /* �����õĸ澯��Ϣ */
        EgnSetAttrTypeCfgInfo       stAttrTypeCfgInfo;          /* �����õ�����ʶ����Ϣ */
        EgnSetStatControl           stStatControl;              /* �����õ�EGNͳ�ƹ��� */
    }CfgParamInfoUn;
} EgnSetCfgParamInfo;

/*STRUCT< IP��ַ�����Ľṹ�� >*/
typedef struct _EgnIpAddrCond
{
    EGN_UINT32   ulIpType;       /* IP����#EGN_ADDR_TYPE_EN */
    EGN_UINT32   ulIpMaskLen;    /* ipmask��ǰ׺,ipv4ȡֵ1-32,ipv6ȡֵ1-128 */
    union
    {
        EGN_UINT32   ulIpv4Addr;        /* IPv4��ַ,����Ϊ��� */
        EGN_UINT8    aucIpv4Addr[4];    /* IPv4��ַ,����Ϊ��� */
        EGN_UINT32   aulIpv6Addr[4];    /* IPv6��ַ,����Ϊ��� */
        EGN_UINT8    aucIpv6Addr[16];   /* IPv6��ַ,����Ϊ��� */
    }IpUn;
}EgnIpAddrCond;

/*STRUCT< NGFW�Զ���˿���������ʱ��֧�ֶ˿ڷ�Χ��usStartPort��usEndPort����� >*/
typedef struct _EgnPortCond
{
    EGN_UINT16  usStartPort;    /* ��ʼ�˿� */
    EGN_UINT16  usEndPort;      /* �����˿� */
#ifdef EGN_64
    EGN_UCHAR   aucReserved[4];
#endif
}EgnPortCond;

/*ENUM< DNS��ѯ���Ͷ��� >*/
typedef enum
{
    EGN_DNS_TYPE_BEGIN           = EGN_EN_INVALID,
    EGN_DNS_TYPE_A               = 1,                /* A���� */
    EGN_DNS_TYPE_AAAA            = 28,                /* AAAA���� */
    EGN_DNS_TYPE_CNAME           = 5,                /* CNAME���� */
    EGN_DNS_TYPE_OTHER           = 255,              /* ����EGN�����ĵ����� */
    EGN_DNS_TYPE_END,
    EGN_DNS_TYPE_BOTTOM          = EGN_EN_BUTT
}EGN_DNS_TYPE_EN;

/*ENUM< DNS��ѯ�ඨ�� >*/
typedef enum
{
    EGN_DNS_CLASS_BEGIN           = EGN_EN_INVALID,
    EGN_DNS_CLASS_IN              = 1,                /* IN�����internetϵͳ */
    EGN_DNS_CLASS_CH              = 2,                /* CH�����Chaosϵͳ */
    EGN_DNS_CLASS_END,
    EGN_DNS_CLASS_BOTTOM          = EGN_EN_BUTT
}EGN_DNS_CLASS_EN;

/*STRUCT< DNS��IP���͵����ݽṹ���� */
typedef struct _EgnDnsOtherData
{
    EGN_UINT32   ulDataLen;             /* ��IP���͵Ļش����ݳ��� */
#ifdef EGN_64
        EGN_UINT8    aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
    EGN_UCHAR   *pucData;               /* ��IP���͵Ļش����� */
}EgnDnsOtherData;

/*STRUCT< DNS�ش���Ϣ�ṹ�嶨�� >*/
typedef struct _EgnDnsAnswer
{
    EGN_UCHAR   *pucAnswerName;         /* �ش��Ӧ�������� */
    EGN_UINT32   ulAnswerNameLen;       /* �ش��Ӧ���� */
    EGN_UINT16   usType;                /* �ش����ͣ�����μ�EGN_DNS_TYPE_EN */
    EGN_UINT16   usClass;               /* �ش��Ӧ��ϵͳ���ͣ�����μ�EGN_DNS_CLASS_EN */
    EGN_UINT32   ulTTL;                 /* �ش���DNS�������Ĵ��ʱ�䣬��ʱ���ù�ע */
#ifdef EGN_64
    EGN_UINT8    aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
    union
    {
        EGN_UINT32      ulIpV4Data;
        EGN_UINT32      aulIpV6Data[4];
        EgnDnsOtherData stOtherData;
    }DataUn;
}EgnDnsAnswer;

/*STRUCT< DNS�ش���Ϣ����ṹ���� >*/
typedef struct _EgnDnsAnswerList
{
    EgnDnsAnswer                stDnsAnswer;    /* �ش���Ϣ�ڵ� */
    struct _EgnDnsAnswerList   *pstNext;        /* ָ����һ���ش� */
}EgnDnsAnswerList;

/*STRUCT< DNS��ѯ��Ϣ�ṹ�嶨�� >*/
typedef struct _EgnDnsQuery
{
    EGN_UCHAR   *pucQueryName;          /* ��ѯ��Ӧ�������� */
    EGN_UINT32   ulQueryNameLen;        /* ��ѯ��Ӧ���� */
    EGN_UINT16   usType;                /* ��ѯ���ͣ�����μ�EGN_DNS_TYPE_EN */
    EGN_UINT16   usClass;               /* ��ѯ��Ӧ��ϵͳ���ͣ�����μ�EGN_DNS_CLASS_EN */
}EgnDnsQuery;

/*STRUCT< DNS��ѯ��Ϣ����ṹ���� >*/
typedef struct _EgnDnsQueryList
{
    EgnDnsQuery                stDnsQuery;    /* ��ѯ��Ϣ�ڵ� */
    struct _EgnDnsQueryList   *pstNext;        /* ָ����һ����ѯ */
}EgnDnsQueryList;

/*STRUCT< DNSЭ�鱨����Ϣ >*/
typedef struct _EgnDnsPacketInfo
{
    EGN_UINT16          usTransactionID;      /* ��ʶ�ֶ� ��ӦRFC�ĵ��еı�־*/
    EGN_UINT16          usFlags;              /* ��־�ֶ� ��ӦRFC�ĵ��еı�־*/
#ifdef EGN_64
    EGN_UINT8    aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
    EgnDnsQueryList    *pstQueryHead;         /* �������� */
    EgnDnsAnswerList   *pstAnswerHead;        /* �ش����� */
}EgnDnsPacketInfo;

/*STRUCT< DNS��ϵ�ʶ���� >*/
typedef struct _EgnDnsRequestResult
{
    EGN_UINT32  ulProtoID;      /* ʶ�������Э��ID */
#ifdef EGN_64
        EGN_UINT8    aucReserved[4];        /* 64λ���뱣���ֽ� */
#endif
}EgnDnsRequestResult;

/*STRUCT< �����·�������Ϣ >*/
typedef struct _EgnPeerListTupleInfo
{
    EGN_UINT32     ulTunnelId;           /* Tunnel   Id*/
    EGN_UINT8      ucTransProtocol;      /* �����Э��*/
    EGN_UINT8      ucTupleFlag;          /* ��Ԫ��״̬*/
    EGN_UINT16     usPort;               /* �˿� */
    EgnIpAddr     *pstIpAddr;            /* IP */
}EgnPeerListTupleInfo;

/*STRUCT< �����·�ʶ������Ϣ >*/
typedef struct _EgnProtoResultInfo
{
    EGN_UINT32  ulAppId;                                     /* Ӧ��ID */
    EGN_UINT32  ulSuperClassId;                              /* ����ID */
    EGN_UINT32  ulClassId;                                   /* С��ID */
    EGN_UINT32  ulLastBearID;                                /* ����ID */
    EGN_UINT32  ulProtoId;                                   /* Э��ID */
    #ifdef EGN_64
    EGN_UINT32  ulReserved;                                  /**< 64λ���뱣���ֽ� */
    #endif
}EgnProtoResultInfo;

/*******************************************************************************
*    Func Name: EgnApiDnsBlockInspect
*      Purpose: �����DNS�������ʶ��
*  Description: �û�����EgnDnsRequestResult �е�Э��ID�Ƿ�Ϊ0���ж�EGN�Ƿ�ʶ��������DNSӦ��Э�顣
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EgnDnsPacketInfo* pstDnsInfo:DNS������Ϣ<�ǿ�>
*        InOut: EgnDnsRequestResult* pstInspectResult:ʶ����<�ǿ�>
*        Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:  ��API������������ɵ���:1.�ɹ���ʼ��EGNʶ���߳�֮ǰ
*                                        2.ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����á�
*                                        3.DNSӦ��ʶ�𿪹�Ϊ�ص�״̬
*                                        4.sessionģʽ��
*        Since: V3R6C00SPC200
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDnsBlockInspect
(
    IN                  EGN_UINT16               usThreadID,        /* ʶ�����ID */
    IN      EGN_CONST   EGN_VOID                *pvHandle,          /* ʵ����� */
    IN      EGN_CONST   EgnDnsPacketInfo      *pstDnsInfo,        /* ��ʶ���DNSЭ����Ϣ */
    INOUT               EgnDnsRequestResult     *pstInspectResult   /* ʶ���� */
);

/*******************************************************************************
*    Func Name: EgnApiDnsRelParse
*      Purpose: ����DNS��Ӧ����
*  Description: ����DNS��Ӧ��������ȡIP��Ϣ������DNS����ʶ��
                    ����pulAddIpNum��ֵ���ж�EGN�������ɹ����IP�ĸ�����
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EgnDnsPacketInfo* pstDnsInfo:DNS������Ϣ<�ǿ�>
*        InOut:
*       Output: EGN_UINT32* pulAddIpNum:�ɹ����IP�ĸ���<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:  ��API������������ɵ���:1.�ɹ���ʼ��EGNʶ���߳�֮ǰ
*                                        2.ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����á�
*                                        3.DNSӦ��ʶ�𿪹�Ϊ�ص�״̬
*                                        4.sessionģʽ��
*        Since: V3R6C00SPC200
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDnsRelParse
(
    IN              EGN_UINT16           usThreadID,
    IN              EGN_VOID            *pvHandle,
    IN  EGN_CONST   EgnDnsPacketInfo  *pstDnsInfo,
    OUT             EGN_UINT32          *pulAddIpNum
);

/*******************************************************************************
*    Func Name: EgnApiDnsDelIpFromIpTbl
*      Purpose: ɾ��ĳIP���
*  Description: �����û������IPɾ����Ӧ��IP���
*        Input: EGN_UINT16 usThreadID:�߳�ID
*               EGN_VOID  *pvHandle:ʵ�����<�ǿ�>
*               EgnIpAddr* pstIpAddr:IP�ṹ<�ǿ�>
*        InOut: NA
*        Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:  ��API������������ɵ���:1.�ɹ���ʼ��EGNʶ���߳�֮ǰ
*                                        2.ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����á�
*                                        3.DNSӦ��ʶ�𿪹�Ϊ�ص�״̬
*                                        4.sessionģʽ��
*        Since: V3R6C00SPC200
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDnsDelIpFromIpTbl
(
    IN              EGN_UINT16       usThreadID,
    IN  EGN_CONST   EGN_VOID        *pvHandle,
    IN  EGN_CONST   EgnIpAddr       *pstIpAddr
);

/*******************************************************************************
*    Func Name: EgnApiDnsGetIpFromIpTbl
*      Purpose: ��ѯĳIP�����Ƿ���ڡ�
*  Description: �����û������IP��ѯ�Ƿ�����
*        Input: EGN_UINT16 usThreadID:�߳�ID
*               EGN_VOID *pvHandle:ʵ�����<�ǿ�>
*               EgnIpAddr* pstIpAddr:IP�ṹ<�ǿ�>
*        InOut: NA
*        Output:EGN_BOOL* pbIsExist:�ñ����Ƿ���ڣ�0:�����ڣ�1:����
*               EGN_UINT32* pulProtoID:��ȡ����Э��ID,0:��ʾδ��ȡ
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:  ��API������������ɵ���:1.�ɹ���ʼ��EGNʶ���߳�֮ǰ
*                                        2.ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����á�
*                                        3.DNSӦ��ʶ�𿪹�Ϊ�ص�״̬
*                                        4.sessionģʽ��
*        Since: V3R6C00SPC200
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDnsGetIpFromIpTbl
(
    IN                  EGN_UINT16       usThreadID,
    IN      EGN_CONST   EGN_VOID        *pvHandle,
    IN      EGN_CONST   EgnIpAddr       *pstIpAddr,
    OUT                 EGN_BOOL        *pbIsExist,
    OUT                 EGN_UINT32      *pulProtoID
);

/*******************************************************************************
*    Func Name: EgnApiDnsGetIpTblInfo
*      Purpose: ��ӡ����IPʵ����ip������Ӵ�������´���
*  Description: �û���ͨ���ýӿڻ�ȡ����ʵ��IP������Ӽ����´���( ��������һ����ӵ� )
*        Input: EGN_UINT16  usThreadID:�߳�ID
*               EGN_VOID   *pvHandle:ʵ�����<�ǿ�>
*               EGN_UINT32  ulIpTblInfoLen:����IP��Ϣ���ڴ��ܳ���
*        InOut: EGN_UCHAR  *pucIpTblInfo:����IP��Ϣ���ڴ��׵�ַ�����鴫��2K�ڴ�
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:  ��API������������ɵ���:1.�ɹ���ʼ��EGN��SESSION���֮ǰ
*                                        2.ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����á�
*                                        3.DNSӦ��ʶ�𿪹�Ϊ�ص�״̬
*                                        4.sessionģʽ��
*        Since: V3R6C00SPC200
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDnsGetIpTblInfo
(
    IN      EGN_UINT16       usThreadID,
    IN      EGN_VOID        *pvHandle,
    IN      EGN_UINT32       ulIpTblInfoLen,
    INOUT   EGN_UCHAR       *pucIpTblInfo
);

/*******************************************************************************
*    Func Name: EgnApiPacketInspect
*      Purpose: �����2��4�������ı��Ĵ��벢����Э��ʶ��
*  Description: ��������ʵ���߳�ID��ʵ���������ʶ�����ͱ��Ļ�ȡʶ������ʶ����չ������
                �û����Ը���ʶ����EgnResult�е�bIsContinue�������Ƿ�����������������ʶ��
                ��bIsContinueΪEGN_TRUE��Ҫ�������������bIsContinueΪEGN_FALSE����Ҫ�����������
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EGN_VOID** ppvFlowInspect:��ʶ����<�ǿ�>
*               EgnPacket* pstPacketInfo:����<�ǿ�>
*        InOut: EgnResult* pstIspectResult:ʶ����<�ǿ�>
*               EgnInspectAuxData* pstAuxData:ʶ����չ����<Ԥ��>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API�ڳɹ���ʼ��EGNʶ���̹߳�����ǹ���ʱ����EgnApiExpandInspectorInit�ɹ�
                ���������ʱ����EgnApiInspectorInit�ɹ�֮ǰ���ɱ����á�
*        Since: V100R001C01
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiPacketInspect
(
    IN                EGN_UINT16           usThreadID,
    IN                EGN_VOID            *pvHandle,
    IN                EGN_VOID           **ppvFlowInspect,
    IN     EGN_CONST  EgnPacket           *pstPacketInfo,
    INOUT             EgnResult           *pstInspectResult,
    INOUT  EGN_CONST  EgnInspectAuxData   *pstAuxData
);

/*******************************************************************************
*    Func Name: EgnApiReleaseCtxData
*      Purpose: �ͷ�ָ������ʶ������
*  Description: ���ڷ��װ�ʶ�������ʶ�������ʹ�øýӿ��ͷ���ʶ������
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_VOID* pvHandle:��ʵ�����������Ϊ��<�ǿ�>
*               EGN_VOID** ppvCtxData:��ʶ����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID
*      Caution: ��API�ڳɹ���ʼ��EGNʶ���̹߳�����ǹ���ʱ����EgnApiExpandInspectorInit�ɹ�
                ���������ʱ����EgnApiInspectorInit�ɹ�֮ǰ���ɱ����á�
*        Since: V100R001C01
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_VOID EgnApiReleaseCtxData
(
    IN              EGN_UINT16    usThreadID,
    IN              EGN_VOID     *pvHandle,
    IN              EGN_VOID    **ppvCtxData
);

/*******************************************************************************
*    Func Name: EgnApiSetFlowMaxDetectCount
*      Purpose: ����������ֵⷧ
*  Description: ����������ֵⷧ��ȡֵ��Χ��uint32��ֵ��Χ���ơ�
                ������ֵⷧĬ�������ڽӿ�EgnApiInitPubParam�����á�
*        Input: EGN_UINT32 ulMaxDetectCnt:������ֵⷧ<������>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V100R001C01
*    Reference: EgnApiInitPubParam
*               EgnApiGetFlowMaxDetectCount
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetFlowMaxDetectCount
(
    IN    EGN_UINT32    ulMaxDetectCnt
);

/*******************************************************************************
*    Func Name: EgnApiGetFlowMaxDetectCount
*      Purpose: ��ѯ������ֵⷧ��
*  Description:
*        Input: NA
*        InOut: NA
*       Output: EGN_UINT32* pulMaxDetectCnt:������ֵⷧ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: null
*        Since: V100R001C01
*    Reference: EgnApiSetFlowMaxDetectCount
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetFlowMaxDetectCount
(
    OUT    EGN_UINT32    *pulMaxDetectCnt
);

/*******************************************************************************
*    Func Name: EgnApiInitPubParam
*      Purpose: ����EGN��Ĭ�ϳ�ʼ�����ò�����
*  Description: �ýӿ��ṩ��Ĭ�ϲ������ù��ܣ�����ȱʡֵ������EGN��Ĭ�ϳ�ʼ�����ò�����
                �����Щ��������ϣ���������ã��������������Ƚ����ѣ�����ʹ�øýӿڽ������á�
                ��ص����ò�������μ�EgnInitCfgParam�Ĳ�����
*        Input: EgnInitCfgParam* pstParam:��ʼ������<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V100R001C01
*    Reference: EgnInitCfgParam
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiInitPubParam
(
    IN  EgnInitCfgParam    *pstParam
);

/*******************************************************************************
*    Func Name: EgnApiGetSysInfo
*      Purpose: �ռ�EGN������Ϣ��
*  Description: EGNһ��ʽ��Ϣ�ռ��ӿڣ����������ʵ���߳�ID(usThreadID)��ʵ�����pvHandle��
                ����ʵ����������Ϣ�������׵�ַΪppucSysInfo���ڴ��У�����ΪpulSysInfoLen��
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*        InOut: NA
*       Output: EGN_UCHAR** ppucSysInfo:����������Ϣ�ڴ��׵�ַ<�ǿ�>
*               EGN_UINT32* pulSysInfoLen:����������Ϣ�ڴ泤��<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1���ڵ��øýӿ�֮ǰҪEGN�����ʼ����ϣ����ұ�֤��̬�ڴ�����ӿ��Ѿ�ע�ᡣ
                2����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                3����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
                4��EGN��ȥʹ��״̬�£�ͨ��EgnApiGetSysInfo��ȡ��Ϣ������ʾCB���֪ʶ�����Ϣ��
*        Since: V200R002C01
*    Reference: EgnApiFreeSysInfo
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetSysInfo
(
    IN            EGN_UINT16   usThreadID,
    IN            EGN_VOID    *pvHandle,
    OUT           EGN_UCHAR  **ppucSysInfo,
    OUT           EGN_UINT32  *pulSysInfoLen
);

/*******************************************************************************
*    Func Name: EgnApiFreeSysInfo
*      Purpose: �ͷ�EGNһ��ʽ��Ϣ�ռ����ڴ档
*  Description: EGNһ��ʽ��Ϣ�ռ����ڴ��ͷŽӿڣ�����ʵ���߳�IDusThreadID��ʵ�����pvHandle��
                �ͷ�EGNһ��ʽ��Ϣ�ռ����ڴ档
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*        InOut: NA
*       Output: EGN_UCHAR** ppucSysInfo:����������Ϣ�ڴ��׵�ַ<�ǿ�>
*       Return: ��
*      Caution: ��API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                ��API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
*        Since: V200R002C01
*    Reference: EgnApiGetSysInfo
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_VOID EgnApiFreeSysInfo
(
    IN              EGN_UINT16  usThreadID,
    IN              EGN_VOID   *pvHandle,
    INOUT           EGN_UCHAR **ppucSysInfo
);

/*******************************************************************************
*    Func Name: EgnApiGetHealthInfo
*      Purpose: ��ȡһ��ʽ������������Ϣ��
*  Description: EGNһ��ʽ�������ӿڣ����EGN��������Ϣ�Ľ�����飬
                ������Ӧʵ���Ľ�����Ϣ�洢���׵�ַΪppucHealthInfo���ڴ��С�
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*        InOut: NA
*       Output: EGN_UCHAR** ppucHealthInfo:���潡�������Ϣ�ڴ��׵�ַ<�ǿ�>
*               EGN_UINT32* pulHealthInfoLen:���潡�������Ϣ�ڴ泤��<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                2����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
                3���ڵ��øýӿ�֮ǰҪEGN�����ʼ����ϣ����ұ�֤��̬�ڴ�����ӿ��Ѿ�ע�ᡣ
                4���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V200R002C01
*    Reference: EgnApiFreeHealthInfo
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetHealthInfo
(
    IN            EGN_UINT16   usThreadID,
    IN            EGN_VOID    *pvHandle,
    OUT           EGN_UCHAR  **ppucHealthInfo,
    OUT           EGN_UINT32  *pulHealthInfoLen
);

/*******************************************************************************
*    Func Name: EgnApiFreeHealthInfo
*      Purpose: �ͷ�һ��ʽ���������Ϣ���ڴ档
*  Description: ͨ������ʵ���߳�ID��ʵ��������ͷŸ�ʵ����������ڴ�ppucHealthInfo�е���Ϣ��
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*        InOut: NA
*       Output: EGN_UCHAR** ppucHealthInfo:���潡�������Ϣ�ڴ��׵�ַ<�ǿ�>
*       Return: EGN_VOID����
*      Caution: 1����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                2����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
                3���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V200R002C01
*    Reference: EgnApiGetHealthInfo
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_VOID EgnApiFreeHealthInfo
(
    IN              EGN_UINT16    usThreadID,
    IN              EGN_VOID     *pvHandle,
    INOUT           EGN_UCHAR   **ppucHealthInfo
);

/*******************************************************************************
*    Func Name: EgnApiMngInit
*      Purpose: ��ʼ�������߳�
*  Description: EGN�����̳߳�ʼ���ӿڣ����EGN�����Ҫʹ�õ�ϵͳ��Դ�����롢��ʼ���ȹ�����
                ����EgnApiMngInitǰ����Ҫ�ȵ���EgnApiInitPubParam��ʼ��EGN�����ò���������ȱʡֵ��
                ����EGN��Ĭ������ֵ�����Ĭ��ֵ������ҵ�����󣬿���ֱ�ӵ���EgnApiMngInit��ʼ����
                ���Ĭ��ֵ��������ҵ�����󣬿��Ը���ҵ�������޸���Ӧ������ֵ��
                �ٵ���EgnApiMngInit��ʼ��EGNģ��Ĺ����̡߳�
*        Input: EGN_UCHAR* pucGlobalBuffer:ȫ���ڴ��׵�ַ<�ǿ�>
*               EGN_UINT32 ulBufferLen:ȫ���ڴ泤��<������>
*               EgnInitCfgParam* pstParam:������Ϣ<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1��������˵���⣬����APIӦ�ڳɹ���ʼ��EGN�����̳߳ɹ����ø�API֮����ܱ�ʹ�á�
                2���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V200R001C01
*    Reference: EgnApiInitPubParam
*               EgnApiMngDestroy
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiMngInit
(
   IN            EGN_UCHAR           *pucGlobalBuffer,
   IN            EGN_ULONG            ulBufferLen,
   IN  EGN_CONST EgnInitCfgParam     *pstParam
);

/*******************************************************************************
*    Func Name: EgnApiExpandInspectorInit
*      Purpose: ������ǹ���ʱ����ʼ��ʶ��ʵ����
*  Description: ������ǹ���ʱ������ʶ��ʵ����ʼ���ӿڡ����ҵ����̡��̵߳ĳ�ʼ����
                ����������߳�IDusThreadID�������ڴ���׵�ַpucSharedBuffer�������ڴ�س���ulSharedBufferLen��
                �ǹ����ڴ���׵�ַpucUnsharedBuffer���ǹ����ڴ�س���ulUnsharedBufferLen��
                ����ʶ��ʵ�����ppvHandle���ҳ�ʼ������Ϊ��ʵ�������ľ�����ⲿ���ܸı䡣
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_UCHAR* pucSharedBuffer:�����ڴ���׵�ַ<�ǿ�>
*               EGN_UINT32 ulSharedBufferLen:�����ڴ�س���<������>
*               EGN_UCHAR* pucUnsharedBuffer:�ǹ����ڴ���׵�ַ<�ǿ�>
*               EGN_UINT32 ulUnsharedBufferLen:�ǹ����ڴ�س���<������>
*        InOut: NA
*       Output: EGN_VOID** ppvHandle:ʵ���������ʼ������Ϊ��ʵ�������ľ�����ⲿ���ܸı�<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1��������˵���⣬����APIӦ�ڳɹ���ʼ��EGNʶ���̹߳�����ǹ���ʱ���ɹ����ø�API֮����ܱ�ʹ�á�
                2����ʵ��ʱʶ��ʵ����������ĳ�ʼ�����ڹ�����ǹ��������£����ֻ֧��32��ʵ����
*        Since: V200R002C00
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiExpandInspectorInit
(
   IN  EGN_UINT16           usThreadID,
   IN  EGN_UCHAR           *pucSharedBuffer,
   IN  EGN_ULONG            ulSharedBufferLen,
   IN  EGN_UCHAR           *pucUnsharedBuffer,
   IN  EGN_ULONG            ulUnsharedBufferLen,
   OUT EGN_VOID           **ppvHandle
);

/*******************************************************************************
*    Func Name: EgnApiInspectorInit
*      Purpose: ��ʼ��ʶ��ʵ����
*  Description: ����ʶ��ʵ����ʼ���ӿڣ��ڶ���̡����߳�ģ���µ��ã����ҵ����̡��̵߳ĳ�ʼ����
                ��ʵ��ʱʶ��ʵ����������ĳ�ʼ����
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_UCHAR* pucGlobalBuffer:�����߳��ڴ���׵�ַ<�ǿ�>
*               EGN_UINT32 ulBufferLen:�����߳��ڴ�س���<������>
*        InOut: NA
*       Output: EGN_VOID** ppvHandle:ʵ���������ʼ������Ϊ��ʵ�������ľ�����ⲿ���ܸı�<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ������˵���⣬����APIӦ�ڳɹ���ʼ��EGNʶ���̹߳�������ʱ���ɹ����ø�API֮����ܱ�ʹ�á�
*        Since: V200R002C00
*    Reference: EgnApiInspectorDestroy
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiInspectorInit
(
    IN     EGN_UINT16         usThreadID,
    IN     EGN_UCHAR         *pucGlobalBuffer,
    IN     EGN_ULONG          ulBufferLen,
    OUT    EGN_VOID         **ppvHandle
);

/*******************************************************************************
*    Func Name: EgnApiMngDestroy
*      Purpose: ȥ��ʼ�������߳�
*  Description: ��ɹ�����̡��߳�ϵͳ��Դ���ͷŵȹ�����
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API�ڳɹ���ʼ��EGN�����̳߳ɹ�����EgnApiMngInit֮ǰ�ɱ����á�
                2������̡����߳�ģ���µ��ã����߳�ģ���²��ܵ��ñ��ӿڡ�
                3���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V100R001C03
*    Reference: EgnApiMngInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiMngDestroy
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiInspectorDestroy
*      Purpose: ȥ��ʼ��ʶ��ʵ����
*  Description: ���ҵ����̡��߳�ϵͳ��Դ���ͷŵȹ�����
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_VOID** ppvHandle:ʵ�����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����ʵ��ʱʶ��ʵ�����������ȥ��ʼ����
                2���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V200R002C00
*    Reference: EgnApiInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiInspectorDestroy
(
    IN  EGN_UINT16  usThreadID,
    IN  EGN_VOID  **ppvHandle
);

/*******************************************************************************
*    Func Name: EgnApiGetNeededMemSize
*      Purpose: �������������ڴ档
*  Description: ��API�ӿڸ����������ģulFlowScale���������СulRelationScale��
                ʶ��ʵ������usMaxInstance���ڴ��Ƿ���bIsMemShared���������ʵ��
                ���蹲���ڴ��СpulSharedMemSize��ÿ��ʶ��ʵ������ǹ����ڴ�Ĵ�СpulUnSharedMemSize����λ�ֽڡ�
*        Input: EGN_UINT32 ulFlowScale:�������ģ<1000~10000000>
*               EGN_UINT32 ulRelScaleIPv4:IPv4�������С<0~10000000>
*               EGN_UINT32 ulRelScaleIPv6:IPv6�������С<0~10000000>
*               EGN_UINT16 usMaxInstance:ʶ��ʵ������<1~32>
*               EGN_BOOL bIsMemShared:�Ƿ����ڴ�<EGN_FALSE��������EGN_TRUE������>
*        InOut: EGN_UINT32* pulSharedMemSize:����ʵ�����蹲���ڴ��С<�ǿ�>
*               EGN_UINT32* pulUnSharedMemSize:ÿ��ʶ��ʵ������ǹ����ڴ�Ĵ�С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
                2���û�ʹ��ʱ�ϸ�����������Ӧ��������API�ӿ�ֻ�����ڴ����Ϊ�����޵�ʱ�����Ч��
                   ������EGN��������ʱ����ulMemPolicy��ʼ��ΪEGN_MEM_POLICY_UNLIMIT��EGNĬ�����øò���Ϊ�����ޡ�
                3���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V100R001C03
*    Reference: EgnApiInitPubParam
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetNeededMemSize
(
    IN     EGN_UINT32   ulFlowScale,
    IN     EGN_UINT32   ulRelScaleIPv4,
    IN     EGN_UINT32   ulRelScaleIPv6,
    IN     EGN_UINT16   usMaxInstance,
    IN     EGN_BOOL     bIsMemShared,
    INOUT  EGN_ULONG   *pulSharedMemSize,
    INOUT  EGN_ULONG   *pulUnSharedMemSize
);

/*******************************************************************************
*    Func Name: EgnApiImportSysRuleLib
*      Purpose: ����ϵͳ֪ʶ�⡣
*  Description: ���뷽ʽ�������ڴ淽ʽ��Ҳ�������ļ���ʽ������ʹ���ڴ淽ʽ�����ļ��ڴ�ָ��ǿ�ʱ��
                ʹ���ڴ淽ʽ�����ļ��ڴ�ָ��Ϊ�ջ��ļ��ڴ��СΪ��ʱ��ʹ���ļ���ʽ��
*        Input: EGN_UINT8* pucRuleLibBuff:�ļ��ڴ�ָ��<�ǿ�>
*               EGN_UINT32 ulBuffLen:�ļ��ڴ��С<������>
*               EGN_UINT8* pcRuleFilePath:�ļ�·��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V100R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiImportSysRuleLib
(
   IN             EGN_UINT8   *pucRuleLibBuff,
   IN             EGN_UINT32   ulBuffLen,
   IN   EGN_CONST EGN_UINT8   *pucRuleFilePath
);

/*******************************************************************************
*    Func Name: EgnApiImportUserRuleLib
*      Purpose: �����û�����֪ʶ�⡣
*  Description: ���뷽ʽ�������ڴ淽ʽ��Ҳ�������ļ���ʽ������ʹ���ڴ淽ʽ�����ļ��ڴ�ָ��ǿ�ʱ��
                ʹ���ڴ淽ʽ�����ļ��ڴ�ָ��Ϊ�ջ��ļ��ڴ��СΪ��ʱ��ʹ���ļ���ʽ��
*        Input: EGN_UINT8* pucRuleLibBuff:�ļ��ڴ�ָ��<�ǿ�>
*               EGN_UINT32 ulBuffLen:�ļ��ڴ��С<������>
*               EGN_UINT8* pcRuleFilePath:�ļ�·��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ڵ����û��Զ���֪ʶ��ǰ����Ҫ�ȵ���ϵͳ֪ʶ�⡣
*        Since: V100R001C01
*    Reference: EgnApiImportSysRuleLib
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiImportUserRuleLib
(
   IN            EGN_UINT8   *pucRuleLibBuff,
   IN            EGN_UINT32   ulBuffLen,
   IN  EGN_CONST EGN_UINT8   *pucRuleFilePath
);

/*******************************************************************************
*    Func Name: EgnApiLoadRuleLib
*      Purpose: ����֪ʶ�⡣
*  Description: ����֪ʶ�⡣
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ڼ���֪ʶ��ǰ����Ҫ�ȵ���ϵͳ֪ʶ�⣬�������ʧ�ܡ�
*        Since: V100R001C01
*    Reference: EgnApiImportSysRuleLib
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiLoadRuleLib
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiApplyRuleLib
*      Purpose: ����֪ʶ�⡣
*  Description: ����֪ʶ�⡣
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ������֪ʶ��ǰ����Ҫ�ȼ���֪ʶ�⣬��������ʧ�ܡ�
*        Since: V100R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiApplyRuleLib
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiReleaseRuleLib
*      Purpose: �ͷű�֪ʶ�⡣
*  Description: �ͷű�֪ʶ�⡣
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V100R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiReleaseRuleLib
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiRollBackRuleLib
*      Purpose: ����֪ʶ�⡣
*  Description: ������������֪ʶ�����һ��ʱ���ڿ���ʹ�øýӿڻ��˵���֪ʶ�⣬�����ôε�������
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬�μ�EGN_RET_RESULT_EN��
*      Caution: ���˱�����ָ����ʱ����Ĭ��Ϊ8Сʱ���У�������ʱ�䣬����ʧ�ܡ�
*        Since: V100R001C03
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiRollBackRuleLib
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiGetRuleLibState
*      Purpose: ��ȡ֪ʶ��״̬��
*  Description: ��ȡ��ǰ��֪ʶ�������ź�����֪ʶ���״̬��
*        Input: NA
*        InOut: NA
*       Output: EGN_UINT32* pulRuleLibIdx:��֪ʶ������<�ǿ�>
*               EGN_UINT32* pulMasterLibState:��֪ʶ��״̬<�ǿ�>
*               EGN_UINT32* pulSlaveLibState:��֪ʶ��״̬<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V100R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetRuleLibState
(
    OUT EGN_UINT32 *pulRuleLibIdx,
    OUT EGN_UINT32 *pulMasterLibState,
    OUT EGN_UINT32 *pulSlaveLibState
);

/*******************************************************************************
*    Func Name: EgnApiGetSuperClassInfo
*      Purpose: ���մ���ID�����Ʋ�ѯ������Ϣ��
*  Description: ���մ���ulSuperClassID���������pucSuperClassName��ѯ������Ϣ����pstSuperClassInfo
                    �ʹ�������Ĵ�СpulItemNumֻ�ܲ�ѯϵͳ֪ʶ����Ϣ��
*        Input: EGN_UINT32 ulSuperClassID:����ID<0~65535>
*               EGN_UINT8* pucSuperClassName:����������Сд������<�ǿ�>
*        InOut: EgnClassInfo* pstSuperClassInfo:������Ϣ����<�ǿ�>
*               EGN_UINT32* pulItemNum:��������Ĵ�С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ������´ε���EgnApiLoadProtoInfoLib��EgnApiReleaseProtoInfoLib��
                ֮�������ʹ�ñ��εĲ�ѯ�������Ҫ��EgnSuperClassInfo�е�stSuperClassName��stSuperClassDesc����������
                ��Ϊָ��pstSuperClassInfo�ٴε��ú��Ѿ��ı䡣
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetSuperClassInfo
(
    IN    EGN_UINT32            ulSuperClassID,
    IN    EGN_UINT8            *pucSuperClassName,
    INOUT EgnSuperClassInfo    *pstSuperClassInfo,
    INOUT EGN_UINT32           *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiGetClassInfo
*      Purpose: ��������ID�����Ʋ�ѯ������Ϣ��
*  Description: ��������ulClassID����������pucClassName��ѯ������Ϣ����pstClassInfo
                    ����������Ĵ�СpulItemNumֻ�ܲ�ѯϵͳ֪ʶ����Ϣ��
*        Input: EGN_UINT32 ulClassID:����ID<0~65535>
*               EGN_UINT8* pucClassName:����������Сд������<�ǿ�>
*        InOut: EgnClassInfo* pstClassInfo:������Ϣ����<�ǿ�>
*               EGN_UINT32* pulItemNum:��������Ĵ�С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ������´ε���EgnApiLoadProtoInfoLib��EgnApiReleaseProtoInfoLib��
                ֮�������ʹ�ñ��εĲ�ѯ�������Ҫ��EgnClassInfo�е�stClassName��stClassDesc����������
                ��Ϊָ��pstClassInfo�ٴε��ú��Ѿ��ı䡣
*        Since: V100R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetClassInfo
(
    IN    EGN_UINT32      ulClassID,
    IN    EGN_UINT8      *pucClassName,
    INOUT EgnClassInfo   *pstClassInfo,
    INOUT EGN_UINT32     *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiGetAppInfo
*      Purpose: ����Ӧ��ID�����Ʋ�ѯӦ����Ϣ��
*  Description: ����Ӧ��IDulAppID��Ӧ������pucAppName��ѯӦ����Ϣ����pstAppInfo
                    ��Ӧ������Ĵ�СpulItemNumֻ�ܲ�ѯϵͳ֪ʶ����Ϣ��
*        Input: EGN_UINT32 ulAppID:Ӧ��ID<��Ҫ��EgnTxt.txt>
*               EGN_UINT8* pucAppName:Ӧ��������Сд������<�ǿ�>
*        InOut: EgnAppInfo* pstAppInfo:Ӧ����Ϣ����<�ǿ�>
*               EGN_UINT32* pulItemNum:Ӧ������Ĵ�С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ������´ε���EgnApiLoadProtoInfoLib��EgnApiReleaseProtoInfoLib֮�������ʹ�ñ��εĲ�ѯ�����
                ��Ҫ��EgnAppInfo�е�stAppName��stAppDesc������������Ϊָ��pstAppInfo�ٴε��ú��Ѿ��ı䡣
*        Since: V200R002C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetAppInfo
(
    IN    EGN_UINT32    ulAppID,
    IN    EGN_UINT8    *pucAppName,
    INOUT EgnAppInfo   *pstAppInfo,
    INOUT EGN_UINT32   *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiGetProtoInfo
*      Purpose: ����Э��ID�����Ʋ�ѯЭ����Ϣ��
*  Description: ����Э��IDulProtoID��Э������pucProtoName��ѯЭ����Ϣ����pstProtoInfo
                ��Э������Ĵ�СpulItemNumֻ�ܲ�ѯϵͳ֪ʶ����Ϣ��
*        Input: EGN_UINT32 ulProtoID:Э��ID<��Ҫ��EgnTxt.txt>
*               EGN_UINT8* pucProtoName:Э��������Сд������<�ǿ�>
*        InOut: EgnProtoInfo* pstProtoInfo:Э����Ϣ����<�ǿ�>
*               EGN_UINT32* pulItemNum:Э������Ĵ�С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ������´ε���EgnApiLoadProtoInfoLib��EgnApiReleaseProtoInfoLib֮�������ʹ�ñ��εĲ�ѯ�����
                ��Ҫ��EgnProtoInfo�е�stProtoName��stProtoDesc������������Ϊָ��pstProtoInfo�ٴε��ú��Ѿ��ı䡣
*        Since: V100R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetProtoInfo
(
    IN    EGN_UINT32      ulProtoID,
    IN    EGN_UINT8      *pucProtoName,
    INOUT EgnProtoInfo   *pstProtoInfo,
    INOUT EGN_UINT32     *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiGetRuleLibVersion
*      Purpose: ��ȡ֪ʶ��汾��
*  Description: ��ȡ֪ʶ��İ汾��ϢpstRuleLibVersion��
*        Input: NA
*        InOut: EgnRuleLibVersion pstRuleLibVersion:֪ʶ��汾�ṹ<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V100R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetRuleLibVersion
(
    INOUT EgnRuleLibVersion *pstRuleLibVersion
);

/*******************************************************************************
*    Func Name: EgnApiGetRuleLibNormalVersion
*      Purpose: ��ȡ��֪ʶ����ʽ�汾��
*  Description: ��ȡ��֪ʶ�����ʽ�汾��pucRuleLibNorVer��
*        Input: NA
*        InOut: EGN_UINT32* pulRuleLibNorVerLen:����ʱ�ǻ��泤�ȣ����ʱ����ʽ�汾��ʵ�ʳ���<�ǿ�>
*               EGN_UCHAR* pucRuleLibNorVer:��Ű汾�ŵ��ڴ棬��������Ϊ��ʽ�汾��ʵ�ʳ��ȣ����������32�ֽ�<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��
*        Since: V300R005C02
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetRuleLibNormalVersion
(
    INOUT EGN_UINT32   *pulRuleLibNorVerLen,
    INOUT EGN_UCHAR    *pucRuleLibNorVer
);

/*******************************************************************************
*    Func Name: EgnApiGetProductVersion
*      Purpose: ��ȡ��ǰʹ��ʶ����������Ĳ�Ʒ�汾�š�
*  Description: ��ȡ��ǰʹ��ʶ����������Ĳ�Ʒ�汾�š�
*        Input: NA
*        InOut: EGN_UINT32 pulProductVerLen:����ʱ���泤�ȣ������ʵ�ʳ���<�ǿ�>
*               EGN_CHAR* pucProductVer:��Ű汾�ŵ��ڴ棬��������Ϊ65���ֽ�<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetProductVersion
(
    INOUT EGN_UINT32   *pulProductVerLen,
    INOUT EGN_CHAR     *pcProductVer
);

/*******************************************************************************
*    Func Name: EgnApiGetVersion
*      Purpose: ��ѯʶ�����浱ǰ�İ汾�š�
*  Description: ά���ӿڣ���ѯʶ�����浱ǰ�İ汾�š�
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UCHAR��EGN��ǰ�İ汾�ţ��ⲿ�����ͷŷ��صĵ�ַ
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V100R001C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UCHAR *EgnApiGetVersion
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiSetStatControl
*      Purpose: ����EGNͳ�ƹ���
*  Description: �ýӿڿ���EGNͳ�ƹ��ܿ��ؼ�ָ��ͳ���ĸ�Э�顣ulCommandΪEGN_STAT_ONOFF_SWITCHʱ��ulContent����ȡEGN_TRUE��EGN_FALSE;
                ulCommandΪEGN_STAT_PROTOID_SETʱ��ulContentΪһ��Э��IDֵ��Ĭ����EGN_PROTO_ID_BT_DATA_TCP����
*        Input: EGN_UINT32 ulCommand:ͳ����Ϣ����ѡ��<EGN_STAT_ONOFF_SWITCH��EGN_STAT_PROTOID_SET>
*               EGN_UINT32 ulContent:ͳ����Ϣ����ѡ��<EGN_TRUE/EGN_FALSE or Э��ID>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ulCommandΪEGN_STAT_ONOFF_SWITCHʱ��ulContent��ʾͳ�ƿ��ص�ֵ������ȡEGN_TRUE��EGN_FALSE��
                ulCommandΪEGN_STAT_PROTOID_SETʱ��ulContent��ʾ��ͳ�Ƶ�һ��Э��IDֵ��Ĭ����EGN_PROTO_ID_BT_DATA_TCP����
                ������Э��ID���ú󣬻Ὣ�ϴεĹ�����ͳ�ƽ�����㡣
*        Since: V200R002C02
*    Reference: EgnApiGetStatControl
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetStatControl
(
    IN      EGN_CONST    EGN_UINT32    ulCommand,
    IN      EGN_CONST    EGN_UINT32    ulContent
);

/*******************************************************************************
*    Func Name: EgnApiGetStatControl
*      Purpose: ��ѯEGNͳ����Ϣ
*  Description: �ýӿڲ�ѯEGNͳ�ƹ��ܿ���״̬����ѯͳ�Ƶ����ĸ�Э�顣
*        Input: EGN_UINT32 ulCommand:ͳ����Ϣ����ѡ��<EGN_STAT_ONOFF_SWITCH��EGN_STAT_PROTOID_SET>
*        InOut: EGN_UINT32* pulContent:ͳ����Ϣ<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ulCommandΪEGN_STAT_ONOFF_SWITCHʱ��pulContentΪ�û����õ�ͳ�ƿ���ֵ������ȡEGN_TRUE��EGN_FALSE��
                ulCommandΪEGN_STAT_PROTOID_SETʱ��pulContentΪ�û����õ�һ��Э��IDֵ���粻�����κ�����ʱ��Ĭ����EGN_PROTO_ID_BT_DATA_TCP����
*        Since: V200R002C02
*    Reference: EgnApiSetStatControl
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetStatControl
(
    IN      EGN_CONST    EGN_UINT32    ulCommand,
    INOUT                EGN_UINT32   *pulContent
);

/*******************************************************************************
*    Func Name: EgnApiStatGet
*      Purpose: ��ȡEGN�ڲ�ͳ����Ϣ��
*  Description: ��ȡ�ڲ�ͳ����Ϣ���û��ⲿ���������ڴ棬����ָ�롣�ڲ�ͳ�������ʶ�����ݰ���������
                ʶ��ɹ���������δʶ������������������ͳ���
*        Input: NA
*        InOut: EgnStatInfo* pstStatRslt:���ͳ������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R001C03
*    Reference: EgnApiStatClear
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiStatGet
(
    INOUT EgnStatInfo *pstStatRslt
);

/*******************************************************************************
*    Func Name: EgnApiStatClear
*      Purpose: ���EGN�ڲ�ͳ����Ϣ��
*  Description: ��EGN�ڲ���ͳ����ȫ�����㣬���¿�ʼͳ�ơ��ڲ�ͳ�������ʶ�����ݰ���������
                ʶ��ɹ���������δʶ������������������ͳ���
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ڿ�ʼ����ͳ��ǰ��������ʹ�øýӿ������ǰ��ͳ����Ϣ������ͳ����Ϣ�а�����ǰ����Ϣ��
*        Since: V200R001C03
*    Reference: EgnApiStatGet
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiStatClear
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiFastRelationSet
*      Purpose: ���ÿ��ٹ���ʶ��Ŀ���״̬���ϻ�ʱ��
*  Description: ���ÿ��ٹ���ʶ��Ŀ���״̬���ϻ�ʱ�䣬��ǰ�汾���ϻ�ʱ�����ò���Ч��
*        Input: EGN_BOOL bSwitch:���ٹ�������<EGN_FALSE:��
                                             EGN_TRUE:��
                                             Ĭ��:��>
*               EGN_UINT32 ulAgingTime:�ϻ�ʱ��(��λ:����)����ǰ�汾�����ò���Ч<3~30>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R001C03
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiFastRelationSet
(
    IN  EGN_CONST  EGN_BOOL     bSwitch,
    IN  EGN_CONST  EGN_UINT32   ulAgingTime
);

/*******************************************************************************
*    Func Name: EgnApiFastRelationGet
*      Purpose: ��ȡ���ٹ���ʶ��Ŀ���״̬���ϻ�ʱ�䡣
*  Description: ��ȡ���ٹ���ʶ��Ŀ���״̬���ϻ�ʱ�䡣
*        Input: NA
*        InOut: NA
*       Output: EGN_BOOL* pbSwitch:���ٹ������أ�EGN_FALSE:�أ�EGN_TRUE:��<�ǿ�>
*               EGN_UINT32* pulAgingTime:�ϻ�ʱ��<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R001C03
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiFastRelationGet
(
    OUT  EGN_BOOL      *pbSwitch,
    OUT  EGN_UINT32    *pulAgingTime
);

/*******************************************************************************
*    Func Name: EgnApiSetWellknownPortState
*      Purpose: ����֪���˿ڹ����Ƿ�����
*  Description: ����֪���˿ڹ����Ƿ�����
*        Input: EGN_BOOL bWellkonwnPortState:����֪���˿ڹ����Ƿ�������<EGN_FALSE:��
                                                                        EGN_TRUE:����
                                                                        Ĭ��:��>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R001C03
*    Reference: EgnApiGetWellknownPortState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetWellknownPortState
(
    IN EGN_BOOL  bWellkonwnPortState
);

/*******************************************************************************
*    Func Name: EgnApiGetWellknownPortState
*      Purpose: ��ȡ֪���˿ڹ��ܿ���״̬��
*  Description: ��ȡ֪���˿ڹ��ܿ���״̬��
*        Input: NA
*        InOut: NA
*       Output: EGN_BOOL pbWellkonwnPortState:ȡ��֪���˿ڹ��ܿ���״̬<EGN_FALSE:��
                                                                     EGN_TRUE:��>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R001C03
*    Reference: EgnApiSetWellknownPortState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetWellknownPortState
(
    OUT EGN_BOOL  *pbWellkonwnPortState
);

/*******************************************************************************
*    Func Name: EgnApiGetIdleRelationCBCount
*      Purpose: ��ȡ���еĹ���ʶ��CB��ĸ�����
*  Description: ���������ʵ���߳�ID��ʵ���������ȡ���еĹ���ʶ��CB��ĸ�����
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*        InOut: EGN_UINT32* pulIdleCBCountIPv4:���е�IPv4����ʶ��CB��ĸ���<�ǿ�>
*               EGN_UINT32* pulIdleCBCountIPv6:���е�IPv6����ʶ��CB��ĸ���<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API�ڳ�ʼ��EGNʶ���̵߳���EgnApiExpandInspectorInit�����EgnApiInspectorInit֮ǰ���ɱ����á�
                2����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                3����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
*        Since: V200R001C03
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetIdleRelationCBCount
(
    IN      EGN_UINT16  usThreadID,
    IN      EGN_VOID   *pvHandle,
    INOUT   EGN_UINT32 *pulIdleCBCntIPv4,
    INOUT   EGN_UINT32 *pulIdleCBCntIPv6
);

/*******************************************************************************
*    Func Name: EgnApiLoadProtoInfoLib
*      Purpose: ����֪ʶ������Э����Ϣ��
*  Description: ���ط�ʽ�������ڴ淽ʽ��Ҳ�������ļ���ʽ��
                ����ʹ���ڴ淽ʽ�����ļ��ڴ�ָ��ǿ�ʱ��ʹ���ڴ淽ʽ��
                ���ļ��ڴ�ָ��Ϊ�ջ��ļ��ڴ��СΪ��ʱ��ʹ���ļ���ʽ��
                ��������֪ʶ����Ϣ�󣬿��Ե���
                EgnApiGetRuleLibVersion��
                EgnApiGetClassInfo��
                EgnApiGetAppInfo��
                EgnApiGetProtoInfo��
                EgnApiGetRuleLibState
                ��ѯ֪ʶ�������Ϣ��
*        Input: EGN_UINT8* pucProtoInfoLibBuff:�ļ��ڴ�ָ��<�ǿ�>
*               EGN_UINT32 ulBuffLen:�ļ��ڴ��С<������>
*               EGN_UINT8* pucProtoInfoFilePath:�ļ�·��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ýӿ���ʶ���ʼ����ֻ����һ�Ρ��ýӿ����û��������ĵ�Э����Ϣʱ���á�
                ��֪ʶ���л�ʱ���û���Ҫ������֪ʶ���Ӧ������Э����Ϣ��
*        Since: V200R002C00
*    Reference: EgnApiGetRuleLibVersion
*               EgnApiGetClassInfo
*               EgnApiGetAppInfo
*               EgnApiGetProtoInfo
*               EgnApiGetRuleLibState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiLoadProtoInfoLib
(
    IN             EGN_UINT8   *pucProtoInfoLibBuffer,
    IN             EGN_UINT32   ulBufferLen,
    IN  EGN_CONST  EGN_UINT8   *pucProtoInfoFilePath
);

/*******************************************************************************
*    Func Name: EgnApiLoadProtoInfoLibIndependently
*      Purpose: ����֪ʶ������Э����Ϣ,��У��֪ʶ��İ汾���Լ���������
*  Description: ���ط�ʽ�������ڴ淽ʽ��Ҳ�������ļ���ʽ��
                ����ʹ���ڴ淽ʽ�����ļ��ڴ�ָ��ǿ�ʱ��ʹ���ڴ淽ʽ��
                ���ļ��ڴ�ָ��Ϊ�ջ��ļ��ڴ��СΪ��ʱ��ʹ���ļ���ʽ��
                ��������֪ʶ����Ϣ�󣬿��Ե���
                EgnApiGetRuleLibVersion��
                EgnApiGetClassInfo��
                EgnApiGetAppInfo��
                EgnApiGetProtoInfo��
                EgnApiGetRuleLibState
                ��ѯ֪ʶ�������Ϣ��
*        Input: EGN_UINT8* pucProtoInfoLibBuff:�ļ��ڴ�ָ��<�ǿ�>
*               EGN_UINT32 ulBuffLen:�ļ��ڴ��С<������>
*               EGN_UINT8* pucProtoInfoFilePath:�ļ�·��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ýӿ���ʶ���ʼ����ֻ����һ�Ρ��ýӿ����û��������ĵ�Э����Ϣʱ���á�
                ��֪ʶ���л�ʱ���û���Ҫ������֪ʶ���Ӧ������Э����Ϣ��
*        Since: V200R002C00
*    Reference: EgnApiGetRuleLibVersion
*               EgnApiGetClassInfo
*               EgnApiGetAppInfo
*               EgnApiGetProtoInfo
*               EgnApiGetRuleLibState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiLoadProtoInfoLibIndependently
(
    IN             EGN_UINT8   *pucProtoInfoLibBuffer,
    IN             EGN_UINT32   ulBufferLen,
    IN  EGN_CONST  EGN_UINT8   *pucProtoInfoFilePath
);

/*******************************************************************************
*    Func Name: EgnApiReleaseProtoInfoLib
*      Purpose: �ͷ�Э�顢Class��App��ѯ��Ϣ�ڴ档
*  Description: �ͷ�Э�顢Class��App��ѯ��Ϣ�ڴ档
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: ��
*      Caution: ��
*        Since: V200R002
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_VOID EgnApiReleaseProtoInfoLib
(
    EGN_VOID
);

#ifdef EGN_HA
/*******************************************************************************
*    Func Name: EgnApiDecomposeRuleLib
*      Purpose: �ֽ�֪ʶ��
*  Description: Ӳ�����ٷ�����ʹ�õ�����Ӳ����ϵ�֪ʶ�⣬��ʱ��Ҫ��֪ʶ��ֽ�Ϊ���֪ʶ��
                ��Ӳ��֪ʶ�Ȿ�ӿ��ṩ�ֽ�֪ʶ�⹦�ܣ�����֪ʶ��ָ���֪ʶ�ⳤ�ȣ�
                ��ȡ���֪ʶ�ⳤ�ȡ�Ӳ��֪ʶ�ⳤ���Լ���ȡ���֪ʶ�⡢Ӳ��֪ʶ�⡣
*        Input: EGN_CONST pucRuleLibBuff:EGN_UINT8��֪ʶ��Buff<�ǿ�>
*               EGN_CONST ulBuffLen:EGN_UINT32��֪ʶ��Buff����<������>
*        InOut: NA
*       Output: EGN_UINT32* pulSwRuleLibLen:���֪ʶ��Buff����<�ǿ�>
*               EGN_UINT8** ppucSwRuleLibBuf:���֪ʶ��Buff<�ǿ�>
*               EGN_UINT32* pulHwRuleLibLen:Ӳ��֪ʶ��Buff����<�ǿ�>
*               EGN_UINT8** ppucHwRuleLibBuf:Ӳ��֪ʶ��Buff<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API�ڳɹ���ʼ��EGN�����̳߳ɹ�����EgnApiMngInit֮ǰ�ɱ����á�
                2���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V200R002C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDecomposeRuleLib
(
    IN   EGN_CONST EGN_UINT8    *pucRuleLibBuff,
    IN   EGN_CONST EGN_UINT32    ulBuffLen,
    OUT  EGN_UINT32             *pulSwRuleLibLen,
    OUT  EGN_UINT8             **ppucSwRuleLibBuf,
    OUT  EGN_UINT32             *pulHwRuleLibLen,
    OUT  EGN_UINT8             **ppucHwRuleLibBuf
);

/*******************************************************************************
*    Func Name: EgnApiHAPacketInspect
*      Purpose: Ӳ���������ʶ��ӿڡ�Ӳ�����ٲ�֧��IPv6
*  Description: ͨ��Ӳ�����ٽ����2��4������ı��Ĵ������Э��ʶ��
                �û�����EgnHAResult�е�ulContinue������ʶ��ʽ��EGN_HA_INPUT_PACKET_STOPֹͣ��
                EGN_HA_INPUT_PACKET_SOFT�������EGN_HA_INPUT_PACKET_HARD��Ӳ�����١�
*        Input: EGN_UINT16 usThreadID:��ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EGN_VOID** ppvFlowInspect:��ʶ����<�ǿ�>
*               EgnPacket* pstPacketInfo:����<�ǿ�>
*        InOut: NA
*       Output: EGN_UINT32 ulRuleLibId:Ӳ��֪ʶ��ID<0,1>
*               EGN_UINT32 ulRuleNum:Ӳ��ʶ��������<1~3872>
*               EGN_UINT32* pulRuleId:Ӳ��ʶ������б�<�ǿ�>
*               EgnHAResult* pstInspectResult:ʶ����<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API�ڳɹ���ʼ��EGNʶ���̳߳ɹ�����EgnApiInspectorInit֮ǰ���ɱ����á�
                2���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
                3��Ӳ������Ϊ(128,3999),���������Ϊ3999-128+1=3872
*        Since: V200R002C01
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiHAPacketInspect
(
    IN           EGN_UINT16    usThreadID,
    IN           EGN_VOID     *pvHandle,
    IN           EGN_VOID    **ppvFlowInspect,
    IN EGN_CONST EgnPacket    *pstPacketInfo,
    IN           EGN_UINT32    ulRuleLibId,
    IN           EGN_UINT32    ulRuleNum,
    IN EGN_CONST EGN_UINT32   *pulRuleId,
    OUT          EgnHAResult  *pstInspectResult
);
#endif

/*******************************************************************************
*    Func Name: EgnApiSetBehaviorInspectState
*      Purpose: ������Ϊ����ʶ�����Ƿ�����
*  Description: ��Ϊ����ʶ���ܿ��ء�
*        Input: EGN_BOOL bBehaviorInspectState:<EGN_FALSE����
                                                EGN_TRUE����
                                                Ĭ�ϣ���>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R002C02
*    Reference: EgnApiGetBehaviorInspectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetBehaviorInspectState
(
    IN EGN_BOOL  bBehaviorInspectState   /* ��Ϊ����ʶ������״̬ */
);

/*******************************************************************************
*    Func Name: EgnApiGetBehaviorInspectState
*      Purpose: ��ȡ��Ϊ����ʶ����״̬
*  Description: ��ȡ��Ϊ����ʶ����״̬
*        Input: NA
*        InOut: NA
*       Output: EGN_BOOL pbBehaviorInspectState:<EGN_FALSE:��
                                                 EGN_TRUE:��>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R002C02
*    Reference: EgnApiSetBehaviorInspectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetBehaviorInspectState
(
    OUT EGN_BOOL  *pbBehaviorInspectState   /* ��Ϊ����ʶ������״̬ */
);

/*******************************************************************************
*    Func Name: EgnApiSetStatInspectState
*      Purpose: ����ͳ��ʶ�����Ƿ���
*  Description: ����ͳ��ʶ�����Ƿ���
*        Input: EGN_BOOL bStatInspectSwitch:����ͳ��ʶ�����Ƿ�������<EGN_FALSE: ��
                                                                       EGN_TRUE:��
                                                                       Ĭ��: ��>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C01
*    Reference: EgnApiGetStatInspectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetStatInspectState
(
    IN EGN_BOOL  bStatInspectSwitch   /* ͳ��ʶ������״̬ */
);

/*******************************************************************************
*    Func Name: EgnApiGetStatInspectState
*      Purpose: ��ȡͳ��ʶ����״̬
*  Description: ��ȡͳ��ʶ����״̬
*        Input: NA
*        InOut: NA
*       Output: EGN_BOOL pbStatInspectSwitch:ȡ��ͳ��ʶ���ܿ���״̬< EGN_FALSE: ��
                                                                     EGN_TRUE : �� >
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C01
*    Reference: EgnApiSetStatInspectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetStatInspectState
(
    OUT EGN_BOOL  *pbStatInspectSwitch   /* ͳ��ʶ������״̬ */
);

/*******************************************************************************
*    Func Name: EgnApiMemBufStatGet
*      Purpose: ��ȡ�ڴ�ʹ��ͳ����Ϣ��
*  Description: ����ʵ���߳�IDusThreadID��ʵ�����pvHandle������pstStatRslt����ȡ��ʵ��ʹ�õ��ڴ�ͳ����Ϣ���洢��pstStatRslt�ڡ�
*        Input: EGN_UINT16 usThreadID:��ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*        InOut: EgnBufStatInfo* pstStatRslt:����Ĳ���Ϊ��СΪ10������ָ�룬���ͳ������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: API�ڲ����ᶯ̬�����ڴ棬pstStatRslt��Ҫ�ⲿ��Ʒ�����ڴ洫�롣
*        Since: V200R002C02
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiMemBufStatGet
(
    IN    EGN_UINT16      usThreadID,
    IN    EGN_VOID       *pvHandle,
    INOUT EgnBufStatInfo *pstStatRslt
);

/*******************************************************************************
*    Func Name: EgnApiGetProtoImportState
*      Purpose: ��ѯЭ���Ƿ������Ϣ��
*  Description: ��ѯЭ���Ƿ������Ϣ����ulProtoID��Ϊ0ʱ����ѯ����Э�����Ϣ��
                ��ulProtoIDΪ0ʱ����ѯ���������õ�Э�鵼����Ϣ��
*        Input: EGN_UINT32 ulProtoID:��ѯ��Э��ID<��Ҫ��EgnTxt.txt>
*        InOut: EgnProtoImportCfgInfo* pstProtoInfo:Э�鵼��������Ϣ����<�ǿ�>
*               EGN_UINT32* pulItemNum:����Ϊ������Ϣ������������Ϊ����������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V200R001C03
*    Reference: EgnApiSetProtoImportState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetProtoImportState
(
    IN    EGN_UINT32              ulProtoID,
    INOUT EgnProtoImportCfgInfo  *pstProtoInfo,
    INOUT EGN_UINT32             *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiSetProtoImportState
*      Purpose: ����һ��Э���Ƿ��롣
*  Description: ����һ��Э���Ƿ����������Ϣ��ʧ��ʱ������������ʧ�ܵ�Э���ʧ�ܵĸ�����
                    ���ú���Ҫ���¼���֪ʶ�����ʹ����������Ч��
*        Input: EGN_UINT32 ulProtoNum:Э��������Ϣ�ĸ���<������>
*               EGN_BOOL bIsEnable:Э���Ƿ���<EGN_FALSE/EGN_TRUE>
*        InOut: EGN_UINT32* pulProtoIdList:Э���б�ʧ��ʱ����ʧ�ܵ�Э��<�ǿ�>
*       Output: EGN_UINT32* pulFailNum:����ʧ�ܵ���Ŀ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��֧�������Զ���Э��
*        Since: V200R001C03
*    Reference: EgnApiGetProtoImportState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetProtoImportState
(
    IN    EGN_UINT32   ulProtoNum,
    IN    EGN_BOOL     bIsEnable,
    INOUT EGN_UINT32  *pulProtoIdList,
    OUT   EGN_UINT32  *pulFailNum
);

/*******************************************************************************
*    Func Name: EgnApiGetProtoDetectState
*      Purpose: ��ѯһ��Э���ʹ��״̬��
*  Description: ��ѯһ��Э���ʹ��״̬��(ֻ�ܲ�ѯϵͳ����Э��)
*        Input: EGN_UINT32 ulProtoID:���ѯ��Э��ID<������>
*        InOut: ��
*       Output: EGN_BOOL* pbIsEnable:ʹ��״̬<EGN_FALSE/EGN_TRUE>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00SPC200
*    Reference: EgnApiSetProtoDetectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetProtoDetectState
(
    IN  EGN_UINT32   ulProtoID,
    OUT EGN_BOOL    *pbIsEnable
);

/*******************************************************************************
*    Func Name: EgnApiGetAllDisableDetectProto
*      Purpose: ��ѯ���б�����Ϊ��ʹ�ܵ�Э�顣
*  Description: ��ѯ���б�����Ϊ��ʹ�ܵ�Э�顣
*        Input: ��
*        InOut: EGN_UINT32* pulItemNum:����Ϊ���鳤�ȣ����Ϊ��ʹ�ܵ�Э������<�ǿ�>
*       Output: EGN_UINT32* pulProtoID:Э��ID����<�ǿ�>
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: EgnApiSetProtoDetectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetAllDisableDetectProto
(
    INOUT   EGN_UINT32      *pulItemNum,
    OUT     EGN_UINT32      *pulProtoID
);

/*******************************************************************************
*    Func Name: EgnApiSetProtoDetectState
*      Purpose: ����һ��Э����ʹ�ܡ�
*  Description: ����һ��Э���Ƿ�ʹ�ܵ�������Ϣ���Ӵ����Э��ID����ĵ�һ����
*                 ʼ��������һ������ʧ�����������أ���������óɹ���������
*                 ������ô˽ӿ�ʱ��δ����֪ʶ�⣬���������ö�ֻ����ʱ������
*                 �ȵ�������֪ʶ���Ժ�ֻ��֪ʶ���д��ڵ�Э��ID�����òŻ���Ч��
                ��֧���Զ���Э������ã����ڻỰ��������,�����ǰ������ʶ���У�
                   ��ʱ����Э��Ϊ��ʹ�ܣ�ʹ��״̬������������ʶ������Ч��
*        Input: EGN_UINT32* pulProtoID:Э��ID�����׵�ַ
*               EGN_UINT32  ulProtoNum:Э��ID�����������<������>
*               EGN_BOOL    bIsEnable:����Ŀ��״̬<EGN_FALSE/EGN_TRUE>
*       Output: EGN_UINT32* pulSuccessNum:���óɹ�����Ŀ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00SPC200
*    Reference: EgnApiGetProtoDetectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetProtoDetectState
(
    IN   EGN_CONST  EGN_UINT32 *pulProtoID,
    IN              EGN_UINT32  ulProtoNum,
    IN              EGN_BOOL    bIsEnable,
    OUT             EGN_UINT32 *pulSuccessNum
);

/*******************************************************************************
*    Func Name: EgnApiGetRuleImportState
*      Purpose: ��ѯ�����Ƿ������Ϣ��
*  Description: ����ulRuleID��ѯ���������Ƿ������Ϣ��������ѯ����洢��pstRuleInfo�С�
*        Input: EGN_UINT32 ulRuleID:��ѯ�Ĺ���ID��ֻ����8155(BTЭ���һ������)<8155>
*        InOut: EgnRuleImportCfgInfo* pstRuleInfo:������������Ϣ����<�ǿ�>
*               EGN_UINT32* pulItemNum:����Ϊ������Ϣ������������Ϊ����������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R005C03
*    Reference: EgnApiSetRuleImportState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetRuleImportState
(
    IN     EGN_UINT32                ulRuleID,
    INOUT  EgnRuleImportCfgInfo     *pstRuleInfo,
    INOUT  EGN_UINT32               *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiSetRuleImportState
*      Purpose: ����һ������Ƿ��롣
*  Description: ����һ������Ƿ����������Ϣ��ʧ��ʱ������������ʧ�ܵĹ����ʧ�ܵĸ�����
                    ���ú���Ҫ���¼���֪ʶ�����ʹ����������Ч��
*        Input: EGN_UINT32 ulRuleNum:����������Ϣ�ĸ�����ֻ����1<1>
*               EGN_BOOL bIsEnable:�����Ƿ���<EGN_FALSE����
                                               EGN_TRUE����>
*        InOut: EGN_UINT32* pulRuleIdList:�����б������RuleIdֻ����8155��ʧ��ʱ����ʧ�ܵĹ���<�ǿ�>
*       Output: EGN_UINT32* pulFailNum:����ʧ�ܵ���Ŀ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R005C03
*    Reference: EgnApiGetRuleImportState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetRuleImportState
(
    IN     EGN_UINT32   ulRuleNum,
    IN     EGN_BOOL     bIsEnable,
    INOUT  EGN_UINT32  *pulRuleIdList,
    OUT    EGN_UINT32  *pulFailNum
);

/*******************************************************************************
*    Func Name: EgnApiSetProtoRelParseState
*      Purpose: ����һ��Э�������������
*  Description: 1���ڲ����ñ�ֻ��������Ϊ���������û�����Ϊ�ص�Э����Ϣ��
                   ����ͨ��EgnApiGetProtoRelParseStateֻ�ܲ鵽�û����õ�����Ϊ�ص�Э�顣
                2�����ù���������Э��id�����Ǵ��ڵ�ǰ��������ñ������֪ʶ���е�Э��id�������������Э��id������ʧ�ܡ�
*        Input: EGN_UINT32 ulProtoNum:Э��������Ϣ�ĸ���<������>
*               EGN_BOOL bIsEnable:Э���Ƿ��������<EGN_FALSE����
                                                   EGN_TRUE����>
*        InOut: EGN_UINT32* pulProtoIdList:����:�û�Ҫ���õ�Э���б����:ʧ��ʱ����ʧ�ܵ�Э���б�<�ǿ�>
*       Output: EGN_UINT32* pulFailNum:����ʧ�ܵ���Ŀ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��֧�������Զ���Э��
*        Since: V300R005C02
*    Reference: EgnApiGetProtoRelParseState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetProtoRelParseState
(
    IN    EGN_UINT32   ulProtoNum,
    IN    EGN_BOOL     bIsEnable,
    INOUT EGN_UINT32  *pulProtoIdList,
    OUT   EGN_UINT32  *pulFailNum
);

/*******************************************************************************
*    Func Name: EgnApiGetProtoRelParseState
*      Purpose: ��ѯЭ�鲻������������Ϣ����ulProtoID��Ϊ0ʱ����ѯ����Э�鲻������������Ϣ��
*  Description: 1����ulProtoIDΪ0�ǣ���ѯ���������õ�Э�����������Ϣ��
                2��ͨ��EgnApiGetProtoRelParseStateֻ�ܲ鵽�û����õ�����Ϊ������Э�顣
                3����ѯ����Э��Ĺ�����������ʱ��ֻ�ܲ�ѯ�����û����ñ��е�Э�顣�����ѯ�����û����õı��е�Э�飬
                   ���᷵��ʧ�ܣ���������ʾ��Э�鲻���û����õı��У���ѯ������
*        Input: EGN_UINT32 ulProtoID:��ѯ��Э��ID<0���EgnTxt.txt>
*        InOut: EgnProtoRelParseCfgInfo* pstProtoInfo:Э���������������Ϣ����<�ǿ�>
*               EGN_UINT32* pulItemNum:����Ϊ������Ϣ������������Ϊ��������������ulProtoIDΪ0ʱ�����뽨��ֵ256��<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: ��֧�ֲ�ѯ�Զ���Э��
*        Since: V300R005C02
*    Reference: EgnApiSetProtoRelParseState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetProtoRelParseState
(
    IN      EGN_UINT32               ulProtoID,
    INOUT   EgnProtoRelParseCfgInfo *pstProtoInfo,
    INOUT   EGN_UINT32              *pulItemNum
);

/*******************************************************************************
*    Func Name: EgnApiSetProtoHierInspectState
*      Purpose: ����һ��Э��Ĳ㼶���װ�ʶ�𿪹ص�״̬
*  Description: ���������Э���б�pstProtoIdList����Э��Ĳ㼶ʶ�𿪹أ�������ЩЭ��Ĳ㼶ʶ��ֵ״̬��¼��EGN�ڲ��㼶ʶ�����ñ��С�
                ���ڽ�Լ�ڴ�Ŀ��ǣ�EGN����¼����Э��Ĳ㼶ʶ��ֵ״̬��������ݲ㼶ʶ�����з�ͬ��ʶ���ܵ��ܿ���(EgnInitCfgParam�ṹ���е�bHierInspectSwitch)��״̬
                �������usHierMaxDetCntֵ��ѡ���Եļ�¼����Э���б�Ĳ㼶ʶ��״̬��
                ������������£�EGN����Э��Ĳ㼶ʶ����Ϣ��¼���ڲ��㼶ʶ�����ñ��У�
                1����bHierInspectSwitchΪEGN_FALSEʱ��������Э��Ĳ㼶ʶ��ֵΪ0(���رղ㼶ʶ�����з�ͬ��ʶ����)ʱ��
                   �ڲ����ñ������Э�����ã�����ʹ��EgnApiGetProtoHierInspectState�鲻����Э��������Ϣ��
                2����bHierInspectSwitchΪEGN_TRUEʱ��������Э��Ĳ㼶ʶ��ֵΪ0XFFFF(���򿪲㼶ʶ�𣬲�ʹ��֪ʶ��Ĭ�Ϸ�ֵ)��
                   �ڲ����ñ������Э�����ã�����ʹ��EgnApiGetProtoHierInspectState�鲻����Э��������Ϣ��
*        Input: EGN_UINT32 ulProtoNum:Э��������Ϣ�ĸ���<������>
*        InOut: EgnHierMaxDetCnt* pstProtoIdList:����:�û�Ҫ���õ�Э���б����:ʧ��ʱ����ʧ�ܵ�Э���б�<�ǿ�>
*       Output: EGN_UINT32* pulFailNum:����ʧ�ܵ���Ŀ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��֧�������Զ���Э��
*        Since: V300R006
*    Reference: EgnApiGetProtoHierInspectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetProtoHierInspectState
(
    IN    EGN_UINT32             ulProtoNum,
    INOUT EgnHierMaxDetCnt      *pstProtoIdList,
    OUT   EGN_UINT32            *pulFailNum
);

/*******************************************************************************
*    Func Name: EgnApiCleanUpProtoHierInspectState
*      Purpose: ����ڲ��㼶ʶ�����ñ��зǲ㼶ʶ��Э���������
*  Description: ������֪ʶ���������˹����п��ܳ���Э��ɾ�����޸ģ�������ɾ�����ñ��еĶ�Ӧ�����
                  �Ա�֪ʶ����˺󱣳�ԭ�е����á�
                ������Э�������϶�ʱ�����ܵ������ñ���������ͨ��EgnApiCleanUpProtoHierInspectState�ӿ�
                  ������ڲ��㼶ʶ�����ñ��зǲ㼶ʶ��Э��������
                  ��ʹ�øýӿں��޷��ָ�����֪ʶ�����֮�󲻻ᱣ����Щ�����
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: NA
*        Since: V300R006C00SPC200
*    Reference: NA
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiCleanUpProtoHierInspectState
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiSetNotFirstPKTRelInspectSwitch
*      Purpose: �����Ƿ�֧�ַ��װ�ʶ����
*  Description: �����Ƿ�֧�ַ��װ�ʶ����,�����ʼ���ɹ��󣬲����������á�
*        Input: bIsNotFirstPktRelInspect:EGN_BOOL���Ƿ�֧�ַ��װ�ʶ��<EGN_TRUE:��ʾ֧��
                                                                      EGN_FALSE:��ʾ��֧��
                                                                      Ĭ�ϣ���֧��>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: EgnApiGetNotFirstPKTRelInspectSwitch
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetNotFirstPKTRelInspectSwitch
(
    IN  EGN_BOOL    bIsNotFirstPKTRelInspect
);

/*******************************************************************************
*    Func Name: EgnApiGetNotFirstPKTRelInspectSwitch
*      Purpose: ��ѯ�Ƿ�֧�ַ��װ�ʶ����
*  Description: ��ѯ�Ƿ�֧�ַ��װ�ʶ����,�����ʼ���ɹ��󣬲���������ѯ��
*        Input: NA
*        InOut: NA
*       Output: EGN_BOOL* pbIsNotFirstPktRelInspect:�Ƿ�֧�ַ��װ�ʶ��<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��
*        Since: V100R001C01
*    Reference: EgnApiSetNotFirstPKTRelInspectSwitch
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetNotFirstPKTRelInspectSwitch
(
    OUT    EGN_BOOL    *pbIsNotFirstPKTRelInspect
);

/*******************************************************************************
*    Func Name: EgnApiGetProtoHierInspectState
*      Purpose: ��ѯЭ��㼶ʶ��ֵ����Ϣ��
*  Description: 1����ulProtoIDΪ0ʱ����ѯ���������õ�Э��㼶ʶ���ͬ��ʶ�𿪹ص���Ϣ��
                2����ulProtoID��Ϊ0ʱ����ѯ����Э�飬������ǲ㼶ʶ��Э�飬����ʧ�ܣ����򷵻ظ�Э��㼶ʶ��״̬��
                   �����ѯ��Э�鲻���û����õĲ㼶ʶ��Э����У��򷵻ز�ѯʧ�ܡ�
                   �������������С���������᷵��ʧ�ܣ���ֻ���������������ɵ�������Ϣ��
*        Input: EGN_UINT32 ulProtoID:��ѯ��Э��ID<������>
*        InOut: EGN_UINT32* pulItemNum:����Ϊ������Ϣ������������Ϊ��������������ulProtoIDΪ0ʱ����������ֵ128��<�ǿ�>
*       Output: EgnHierMaxDetCntInfo* pstProtoInfo:�㼶��ͬ��ʶ�𿪹�״̬������Ϣ����<�ǿ�>
*       Return: EGN_UINT32���������С���������ش�����ΪEGN_RET_ERR_BUF_MORE��������μ�EGN_RET_RESULT_EN��
*      Caution: ��֧�ֲ�ѯ�Զ���Э��
*        Since: V300R006C00
*    Reference: EgnApiSetProtoHierInspectState
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetProtoHierInspectState
(
    IN      EGN_UINT32               ulProtoID,
    INOUT   EGN_UINT32              *pulItemNum,
    OUT     EgnHierMaxDetCntInfo    *pstProtoInfo
);

/*******************************************************************************
*    Func Name: EgnApiSetUnsymmetricalInspectFlag
*      Purpose: �����Ƿ�֧�ַǶԳ�ʶ����
*  Description: �����Ƿ�֧�ַǶԳ�ʶ���ܣ���Ҫ�ڳ�ʼ��ʱע��EgnSspFunc.pfPeerSynAdd
                   ��ԭ��PFEgnFuncPeerSynAdd�����ҳ�ʼ���ɹ���������á�
*        Input: EGN_BOOL bIsUnsymmetricalInspect:�Ƿ�֧�ַǶԳ�ʶ��<EGN_TRUE:֧��
                                                                    EGN_FALSE:��֧��
                                                                    Ĭ�ϣ���֧��>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C01
*    Reference: EgnApiGetUnsymmetricalInspectFlag
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetUnsymmetricalInspectFlag
(
    IN     EGN_BOOL     bIsUnsymmetricalInspect
);

/*******************************************************************************
*    Func Name: EgnApiGetUnsymmetricalInspectFlag
*      Purpose: ��ѯ�Ƿ�֧�ַǶԳ�ʶ����
*  Description: ��ѯ�Ƿ�֧�ַǶԳ�ʶ���ܣ������ʼ���ɹ��󣬲������������ò�ѯ���ܡ�
*        Input: NA
*        InOut: NA
*       Output: EGN_BOOL pbIsUnsymmetricalInspect:�Ƿ�֧�ַǶԳ�ʶ��<EGN_TRUE:֧��
                                                                     EGN_FALSE:��֧��>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C01
*    Reference: EgnApiSetUnsymmetricalInspectFlag
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetUnsymmetricalInspectFlag
(
    OUT EGN_BOOL    *pbIsUnsymmetricalInspect
);

/*******************************************************************************
*    Func Name: EgnApiDynMemMngDestroy
*      Purpose: �����߳�ȥ��ʼ���ӿڣ�AR��̬�ڴ����󣩡�
*  Description: ��ɹ�����̡��߳�ϵͳ��Դ���ͷŵȹ�����
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API��ʹ��EgnApiDynMemMngInit�ɹ���ʼ��EGN�����߳�֮ǰ�ɱ����á�
*        Since: V300R005C01
*    Reference: EgnApiDynMemMngInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDynMemMngDestroy
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiDynMemInspectorDestroy
*      Purpose: ����ʶ��ʵ��ȥ��ʼ���ӿڣ�AR��̬�ڴ����󣩡�
*  Description: ���ҵ����̡��߳�ϵͳ��Դ���ͷŵȹ�����
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_VOID** ppvHandle:ʵ�����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��ʵ��ʱʶ��ʵ�����������ȥ��ʼ����
*        Since: V300R005C01
*    Reference: EgnApiDynMemInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDynMemInspectorDestroy
(
    IN  EGN_UINT16  usThreadID,
    IN  EGN_VOID  **ppvHandle
);

/*******************************************************************************
*    Func Name: EgnApiDynMemMngInit
*      Purpose: EGN�����̳߳�ʼ���ӿڣ�AR��̬�ڴ����󣩡�
*  Description: ���EGN�����Ҫʹ�õ�ϵͳ��Դ�����롢��ʼ���ȹ�����
                �û���Ҫ�ȵ���EgnApiInitPubParam����EGN��ȱʡ���ã�Ȼ��EgnInitCfgParam��ulRelationCBCountIpv6����Ϊ0��
                ��IPv6����ʶ��CB�����ĿΪ0����ulMemPolicy����ΪEGN_MEM_POLICY_LIMIT�����ڴ����Ϊ���ޣ�
                ��������ɸ���������Ҫ���á�������Ϻ��ٵ���EgnApiDynMemMngInit��ʼ����
*        Input: EgnInitCfgParam* pstParam:������Ϣ<�ǿ�>
*        InOut: EGN_VOID** ppvShareInfoAddr:����globalspace���׵�ַ�����ڶ��߳�֮�乲��ͬһ��<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����ulRelationCBCountIpv6������Ϊ0��ulMemPolicy������ΪEGN_MEM_POLICY_LIMIT�����ʼ��ʧ�ܡ�
                2��������˵���⣬����APIӦ�ڳɹ���ʼ��EGN�����̣߳��ɹ����ø�API��֮����ܱ�ʹ�á�
*        Since: V300R005C01
*    Reference: EgnApiDynMemMngDestroy
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDynMemMngInit
(
   IN  EGN_CONST EgnInitCfgParam     *pstParam,
   INOUT         EGN_VOID           **ppvShareInfoAddr
);

/*******************************************************************************
*    Func Name: EgnApiDynMemInspectorInit
*      Purpose: ��ʼ��ʶ��ʵ����AR��̬�ڴ����󣩡�
*  Description: ����ʶ��ʵ����ʼ���ӿڣ��ڶ���̡����߳�ģ���µ��ã����ҵ����̡��̵߳ĳ�ʼ����
                ��ʵ��ʱʶ��ʵ����������ĳ�ʼ����
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_VOID* pvShareInfoAddr:����globalspace���׵�ַ�����ڶ��߳�֮�乲��ͬһ��<�ǿ�>
*        InOut: NA
*       Output: EGN_VOID** ppvHandle:ʵ���������ʼ������Ϊ��ʵ�������ľ�����ⲿ���ܸı�<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ������˵���⣬����APIӦ�ڳɹ���ʼ��EGNʶ���̹߳�������ʱ���ɹ����ø�API֮����ܱ�ʹ�á�
*        Since: V300R005C01
*    Reference: EgnApiDynMemInspectorDestroy
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDynMemInspectorInit
(
    IN     EGN_UINT16         usThreadID,
    IN     EGN_VOID          *pvShareInfoAddr,
    OUT    EGN_VOID         **ppvHandle
);

/*******************************************************************************
*    Func Name: EgnApiDynMemMngEnable
*      Purpose: ʹ��EGN��AR��̬�ڴ����󣩡�
*  Description: ����ʶ������Ϊʹ��״̬����ʶ�����洦��ȥʹ��״̬ʱ�����øýӿڽ��ظ�ʹ��״̬��
                ���µ���֪ʶ��󽫣���������ʶ���ܡ�
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ýӿڱ����ڹ����߳��ϵ��á�
*        Since: V300R005C01
*    Reference: EgnApiDynMemMngDisable
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDynMemMngEnable
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiDynMemMngDisable
*      Purpose: ȥʹ��EGN��AR��̬�ڴ����󣩡�
*  Description: ����ʶ������Ϊȥʹ��״̬����ʱʶ�����潫�ͷ�֪ʶ�⣬�ر�ʶ���ܡ�
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ýӿڱ����ڹ����߳��ϵ��á�
*        Since: V300R005C01
*    Reference: EgnApiDynMemMngEnable
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDynMemMngDisable
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiSetResAlarmThreshold
*      Purpose: �澯ֵ���ýӿڡ�
*  Description: ������̳�ʼ����ɺ󣬲��ܵ��øýӿڣ���������֪ʶ�⡢�������м�״̬�����޸澯ֵ��
*        Input: EGN_UINT32 ulType:��Ҫ���õĸ澯ֵ����<EGN_RESALARMTHRESHOLD_EN>
*               EGN_UINT32 ulThreshold:���޸澯ֵ<������>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution:
*        Since: V300R005C01
*    Reference: EgnApiGetResAlarmThreshold
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetResAlarmThreshold
(
    IN  EGN_UINT32  ulType,
    IN  EGN_UINT32  ulThreshold
);

/*******************************************************************************
*    Func Name: EgnApiGetResAlarmThreshold
*      Purpose: �澯ֵ��ѯ�ӿڡ�
*  Description: ������̳�ʼ����ɺ󣬲��ܵ��øýӿڣ����л��֪ʶ�⡢�������м�״̬�����޸澯ֵ��
*        Input: EGN_UINT32 ulType:��Ҫ��ѯ�ĸ澯ֵ����<EGN_RESALARMTHRESHOLD_EN>
*        InOut: NA
*       Output: EGN_UINT32 *pulThreshold:���޸澯ֵ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution:
*        Since: V300R005C01
*    Reference: EgnApiSetResAlarmThreshold
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetResAlarmThreshold
(
    IN  EGN_UINT32  ulType,
    OUT EGN_UINT32 *pulThreshold
);

/*******************************************************************************
*    Func Name: EgnApiGetStatErrInfo
*      Purpose: ��ȡ����ͳ����Ϣ��
*  Description: ��ȡ����ͳ����Ϣ���ⲿ����һ���ڴ棬egn������ͳ����Ϣд���ڴ棬�ⲿͨ����ӡ������ʾ����ͳ����Ϣ��
                ��������ο�EGN_STAT_ERROR_EN��
*        Input: EGN_UINT32 ulStatBuffLen:������ڴ��С������5k<������>
*        InOut: NA
*       Output: EGN_UINT8* pucStatBuff:����ͳ�ƽ����ʾ����Ҫ���ڴ�<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution:
*        Since: V300R005C02
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiGetStatErrInfo
(
    OUT EGN_UINT8    *pucStatBuff,
    IN  EGN_UINT32    ulStatBuffLen
);

/*******************************************************************************
*    Func Name: EgnApiStatErrClear
*      Purpose: �������ͳ����Ϣ
*  Description: �������ͳ����Ϣ
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: ��
*      Caution: ��
*        Since: V300R005C02
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_VOID  EgnApiStatErrClear
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiGetSysInfoExt
*      Purpose: �ռ�EGN������Ϣ��
*  Description: EGNһ��ʽ��Ϣ�ռ��ӿڣ����������ʵ���߳�IDusThreadID��ʵ�����pvHandle��
                ����ʵ����������Ϣ�������׵�ַΪpucSysInfo���ڴ���
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EGN_UINT32 ulSysInfoLen:����������Ϣ�ڴ��ܳ���<������>
*        InOut: NA
*       Output: EGN_UCHAR* pucSysInfo:����������Ϣ�ڴ��׵�ַ�����鴫��12k�ڴ�<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1���ڵ��øýӿ�֮ǰҪEGN�����ʼ����ϡ�
                2����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                3����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
                4��EGN��ȥʹ��״̬�£�ͨ��EgnApiGetSysInfoExt��ȡ��Ϣ������ʾCB���֪ʶ�����Ϣ��
                5���ⲿͨ����ӡ������ʾegn��������Ϣ
*        Since: V300R005C02
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetSysInfoExt
(
    IN            EGN_UINT16   usThreadID,
    IN            EGN_VOID    *pvHandle,
    OUT           EGN_UCHAR   *pucSysInfo,
    IN            EGN_UINT32   ulSysInfoLen
);

/*******************************************************************************
*    Func Name: EgnApiGetHealthInfoExt
*      Purpose: ��ȡһ��ʽ������������Ϣ��
*  Description: EGNһ��ʽ�������ӿڣ����EGN��������Ϣ�Ľ�����飬
                ������Ӧʵ���Ľ�����Ϣ�洢���׵�ַΪpucHealthInfo���ڴ��С�
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EGN_UINT32 ulHealthInfoLen:���潡�������Ϣ�ڴ��ܳ���<������>
*        InOut: NA
*       Output: EGN_UCHAR* pucHealthInfo:���潡�������Ϣ�ڴ��׵�ַ<��>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                2����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
                3���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V300R005C02
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetHealthInfoExt
(
    IN            EGN_UINT16   usThreadID,
    IN            EGN_VOID    *pvHandle,
    OUT           EGN_UCHAR   *pucHealthInfo,
    IN            EGN_UINT32   ulHealthInfoLen
);

/*******************************************************************************
*    Func Name: EgnApiSetAttrTypeCfgInfo
*      Purpose: �������������Ƿ�ʶ��
*  Description: �����������Ϳ��أ�ÿ������һ���������ͣ����ⲿ��Ҫ��ע�µ������������ʱ��
                    ����ͨ���ýӿڽ������á����ú���Ҫ���¼���֪ʶ�����ʹ����������Ч��
*        Input: EGN_UINT32 ulAttrTypeId:��������id<0~63>
*               EGN_BOOL bIsEnable:�Ƿ�ʶ��<EGN_TRUE��ʶ��
                                            EGN_FALSE����ʶ��>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetAttrTypeCfgInfo
(
    IN    EGN_UINT32   ulAttrTypeId,
    IN    EGN_BOOL     bIsEnable
);

/*******************************************************************************
*    Func Name: EgnApiGetAttrTypeCfgInfo
*      Purpose: ��ѯ��������������Ϣ��
*  Description: ��ѯ���������Ƿ�������ʶ��
*        Input: EGN_UINT32 ulAttrTypeId:��������id<0~63>
*        InOut: NA
*       Output: EGN_BOOL* pbIsEnable:�Ƿ�ʶ��<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetAttrTypeCfgInfo
(
    IN    EGN_UINT32   ulAttrTypeID,
    OUT   EGN_BOOL    *pbIsEnable
);

/*******************************************************************************
*    Func Name: EgnApiPeerListAddPeer
*      Purpose: ��ӹ�������
*  Description: ��ӹ�������ӿڣ�����ֻ��ͬ������ʱ���Ե��ã�
                �����������ò���֤����ʶ�����ȷ�Ի���ֱ�����ʧ�ܡ�
*        Input: usThreadID usThreadID:����ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EgnPeerTuple* pstPeerTuple:����ӵĹ���������Ϣ<�ǿ�>
*               EgnPeerTime* pstPeerTime:�ñ����Ӧ���ϻ�ʱ��<�ǿ�>
*               EGN_UINT32 ulProtocol:��ӦЭ��ID<��EgnTxt.txt>
*               EGN_VOID* pvFlowHandle:���ݰ������������<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: EgnApiPeerListDelPeer
                EgnApiPeerListSearchPeer
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiPeerListAddPeer
(
    IN  EGN_UINT16       usThreadID,
    IN  EGN_VOID        *pvHandle,
    IN  EgnPeerTuple    *pstPeerTuple,
    IN  EgnPeerTime     *pstPeerTime,
    IN  EGN_UINT32       ulProtocol,
    IN  EGN_VOID        *pvFlowHandle
);

/*******************************************************************************
*    Func Name: EgnApiPeerListSearchPeer
*      Purpose: ��ѯ��������
*  Description: ��ѯ��������ӿڣ�����ֻ��ͬ������ʱ���Ե��ã������������ò���֤����ʶ�����ȷ�ԡ�
*        Input: usThreadID usThreadID:����ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EgnPeerTuple* pstPeerTuple:����ӵĹ���������Ϣ<�ǿ�>
*        InOut: NA
*       Output: EgnRelResult* pstRelResult:��ѯ���<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: EgnApiPeerListAddPeer
                EgnApiPeerListDelPeer
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiPeerListSearchPeer
(
    IN  EGN_UINT16        usThreadID,
    IN   EGN_VOID        *pvHandle,
    IN   EgnPeerTuple    *pstPeerTuple,
    OUT  EgnRelResult    *pstRelResult
);

/*******************************************************************************
*    Func Name: EgnApiPeerListDelPeer
*      Purpose: ɾ����������
*  Description: ɾ����������ӿڣ�����ֻ��ͬ������ʱ���Ե��ã������������ò���֤����ʶ�����ȷ�ԡ�
*        Input: usThreadID usThreadID:����ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EgnPeerTuple* pstPeerTuple:����ӵĹ���������Ϣ<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: EgnApiPeerListAddPeer
                EgnApiPeerListSearchPeer
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiPeerListDelPeer
(
    IN  EGN_UINT16        usThreadID,
    IN   EGN_VOID        *pvHandle,
    IN   EgnPeerTuple    *pstPeerTuple
);

/*******************************************************************************
*    Func Name: EgnApiGetRuleStatInfo
*      Purpose: ��ѯ����ͳ����Ϣ��
*  Description: 1����ȡ���Ĳ�ͬ�ļ�¼��������ͬ�Ĺ����ۼӺ�Ϊʵ�ʹ���ͳ����Ϣ��
                2�������и��ӹ�ϵ�ģ�����ͳ����Ϣ����Ҫ�����ӹ�ϵ�ĸ�����
                3��ulStatRecordNum����Ϊ����ʵ�ʸ���+���ӹ�ϵ�ĸ�����
*        Input: EGN_UINT32 ulStatRecordNum:����ʵ�ʸ���+���ӹ�ϵ�ĸ���<������>
*        InOut: EgnRuleStatRd* pstRuleStatRd:�����ѯ��¼���ڴ�<�ǿ�>
*       Output: EGN_UINT32* pulRuleNum:ʵ�ʻ�õ�ͳ�Ƽ�¼��Ŀ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetRuleStatInfo
(
    INOUT EgnRuleStatRd   *pstRuleStatRd,
    IN    EGN_UINT32       ulStatRecordNum,
    OUT   EGN_UINT32      *pulRuleNum
);

/*******************************************************************************
*    Func Name: EgnApiClearRuleStatInfo
*      Purpose: �������ͳ����Ϣ��
*  Description: �������ͳ����Ϣ��
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiClearRuleStatInfo
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiGetMatchedRule
*      Purpose: ��ȡ��ǰ����ƥ�䵽�Ĺ���id
*  Description: ��ȡ��ǰ����ƥ�䵽�Ĺ���id
*        Input: EGN_UINT32   ulThreadId:�߳�ID<0~65535>
                EGN_VOID pvHandle:ʵ�����<�ǿ�>
*        InOut: NA
*       Output: EGN_UINT32* pulRuleId:����id<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetMatchedRule
(
    IN   EGN_UINT32   ulThreadId,
    IN   EGN_VOID    *pvHandle,
    OUT  EGN_UINT32  *pulRuleId
);

/*******************************************************************************
*    Func Name: EgnApiGetMaintainInfo
*      Purpose: ��һ����ѯ�ӿ�
*  Description: ��ȡEGNά��������Ϣ
*        Input: EGN_UINT32 ulInfoMask:��ѯ����<EGN_DBG_QUERY_ENGINE_VERSION       0x01    ��ѯ����汾��
                                              EGN_DBG_QUERY_DETECT_THRESHOLD      0x02    ��ѯʶ��ֵ
                                              EGN_DBG_QUERY_RULELIB_VERSION       0x04    ��ѯ֪ʶ��汾��
                                              EGN_DBG_QUERY_PEER_INFO             0x08    ��ѯpeer��Ϣ
                                              EGN_DBG_QUERY_RELTBL_INFO           0x10    ��ѯ������״̬
                                              EGN_DBG_QUERY_PKT_STAT_INFO         0x20    ��ѯ����ͳ����Ϣ
                                              EGN_DBG_QUERY_STATICBP_INFO         0x40    ��ѯ��̬�ڴ������Ϣ
                                              EGN_DBG_QUERY_ALL_INFO              0x7f    ��ѯ����������Ϣ >
*               EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ��handle<�ǿ�>
*               EGN_UINT32 ulBufLen:�ⲿ�����ڴ�Ĵ�С<������>
*        InOut: EGN_UINT32* pucBuffer:�ⲿ������ڴ��׵�ַ<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1���ڵ��øýӿ�֮ǰҪEGN�����ʼ����ϡ\
                2����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ������Ͷ�Ӧ���߳�id��
                3����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�ա�
                4���ⲿͨ����ӡ������ʾegn��������Ϣ��
*        Since: V300R006C00
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetMaintainInfo
(
    IN    EGN_UINT32   ulInfoMask,
    IN    EGN_UINT16   usThreadID,
    IN    EGN_VOID    *pvHandle,
    INOUT EGN_UCHAR   *pucBuffer,
    IN    EGN_UINT32   ulBufLen
);

/*******************************************************************************
*    Func Name: EgnApiGetMngInfo
*      Purpose: ����ӿ�ʹ�÷��ͳһ����������Ϣ��ѯ�ӿ�
*  Description: 1.�ڵ��øýӿ�֮ǰҪEGN�����ʼ�����
*               2.�ⲿ�ɸ��ݻ�ȡ��Ϣ��������ȷ��ȡ��Ϣ�����ݽṹ����������ݽṹ�ڽṹ��EgnGetCfgInfo��,
*                �ýṹ���еĹ������Ӧ�������ݽṹ�����ݽṹ��ͳһ������ʽ:��Σ�����In;����Σ�����InOut;���Σ�����Out������ָ�����͵ı������û������䴫��ĸ��������ڴ档
*                (���������뷵�ؽ���Ķ�Ӧ��ϵ��EGN_UNITE_GET_SET_EN)
*        Input: EGN_UINT32      ulInfoEnum:��ѯ����<EGN_UNITE_GET_SET_EN
*                 (ulInfoEnum�ķ�Χ:"EGN_UNITE_GET_SET_ENGINE_VERSION~EGN_UNITE_GET_SET_UD_BACK_RULE_LIB_NEED_MEM"����ȥEGN_UNITE_GET_SET_MATCHED_RULE_INFO��
*                 ����EGN_UNITE_GET_SET_STATIC_BLOCK_INFO��EGN_UNITE_GET_SET_CB_STATIC_INFO���͵���Ϣֻ���ڴ�Ϊ����ģʽʱ������ͨ���ýӿڻ�ȡ��>
*        InOut: EgnGetCfgInfo    pstGetCfgInfo:��ȡ������Ϣ�׵�ַ<�ǿ�>������ѯ������Ϣʱ�����ڴ��쳣��Ϣ�������������ڳ������ƣ�������ǰ�����ڴ��¼��Ϣ����Ҫ��ѯ������Ϣ����ʹ��
*                 EgnApiGetHealthInfo��ȡ��
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetMngInfo
(
    IN     EGN_UINT32       ulInfoEnum,
    INOUT  EgnGetCfgInfo   *pstGetCfgInfo
);

/*******************************************************************************
*    Func Name: EgnApiGetInspectorInfo
*      Purpose: ����ӿ�ʹ�÷��ͳһ��ҵ������Ϣ��ѯ�ӿ�
*  Description: 1.�ڵ��øýӿ�֮ǰҪEGN�����ʼ�����
*               2.�ⲿ�ɸ��ݻ�ȡ��Ϣ��������ȷ��ȡ��Ϣ�����ݽṹ����������ݽṹ�ڽṹ��EgnGetCfgInfo��,
*                �ýṹ���еĹ������Ӧ�������ݽṹ�����ݽṹ��ͳһ������ʽ:��Σ�����In;����Σ�����InOut;���Σ�����Out������ָ�����͵ı������û������䴫��ĸ��������ڴ档
*                (���������뷵�ؽ���Ķ�Ӧ��ϵ��EGN_UNITE_GET_SET_EN)
*               3.��API�����ڹ����̵߳��ã�ֻ����ʶ���̵߳��ã\
*        Input: EGN_UINT32  ulInfoEnum:��ѯ����<EGN_UNITE_GET_SET_EN
*                  (ulInfoEnum�ķ�Χ:"EGN_UNITE_GET_SET_STATIC_BLOCK_INFO~EGN_UNITE_GET_SET_MATCHED_RULE_INFO��>
*               EGN_UINT16  usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID    pvHandle:ʵ��handle<�ǿ�>
*        InOut: EgnGetCfgInfo  pstGetCfgInfo:��ȡ������Ϣ�׵�ַ<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetInspectorInfo
(
    IN        EGN_UINT32      ulInfoEnum,
    IN        EGN_UINT16      usThreadID,
    IN        EGN_VOID       *pvHandle,
    INOUT     EgnGetCfgInfo  *pstGetCfgInfo
);

/*******************************************************************************
*    Func Name: EgnApiSetCfgParamInfo
*      Purpose: ����ӿ�ʹ�÷��ͳһ��ͳһ����������Ϣ����Ϊ��̬�����붯̬����
*  Description: 1.��̬����:����ʱ�����ڳ�ʼ��֮ǰ����ע���˻ص�����֮�󣬷��򷵻�ʧ�ܡ�
*                 ����ڳ�ʼ��Ĭ�ϲ���֮����ã����ڵ���EgnApiInitPubParam֮����øýӿڣ����õ�������Ϣ��Ч�������سɹ���
*                 ��̬���õĲ����ɹ���������Ч���ýӿڵĵ���ʱ�����ڳ�ʼ��Ĭ�ϲ���֮ǰ��ע���˻ص�����֮����ϵͳδ��ʼ��
*               2.��̬����:EGN�����ʼ�����,���򷵻�ʧ��
*               3.�ⲿ�ɸ���������Ϣ��������ȷ������Ϣ�����ݽṹ����������ݽṹ�ڽṹ��EgnSetCfgParamInfo��,
*                �ýṹ���еĹ������Ӧ�������ݽṹ�����ݽṹ��ͳһ������ʽ:��Σ�����In;����Σ�����InOut;���Σ�����Out������ָ�����͵ı������û������䴫��ĸ��������ڴ档
*                (���������뷵�ؽ���Ķ�Ӧ��ϵ��EGN_UNITE_GET_SET_EN)��
*        Input: EGN_UINT32      ulSetType:���õ�����<0:��̬��1:��̬>
*               EGN_UINT32      ulEnumNum:��������<EGN_UNITE_GET_SET_EN
                     ��̬����:"EGN_UNITE_GET_SET_DETECT_THRESHOLD~EGN_UNITE_GET_SET_UDRULE_SWITCH_INFO",
                              "EGN_UNITE_GET_SET_CFG_PARA_IS_SHARE~EGN_UNITE_GET_SET_UD_BACK_RULE_LIB_NEED_MEM"
                     ��̬����:"EGN_UNITE_GET_SET_DETECT_THRESHOLD~EGN_UNITE_GET_SET_IP_FLOW_AGED_TIME",
                              "EGN_UNITE_GET_SET_PROTO_IMPORT_STATE~EGN_UNITE_GET_SET_STAT_CONTROL" >
*        InOut: EgnSetCfgParamInfo    pstSetCfgParamInfo:�����õ���Ϣ<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSetCfgParamInfo
(
    IN      EGN_UINT32              ulSetType,
    IN      EGN_UINT32              ulEnumNum,
    INOUT   EgnSetCfgParamInfo     *pstSetCfgParamInfo
);

/*******************************************************************************
*    Func Name: EgnApiSnDnsBlockInspect
*      Purpose: �����DNS�������ʶ��
*  Description: �û�����EgnDnsRequestResult �е�Э��ID�Ƿ�Ϊ0���ж�EGN�Ƿ�ʶ��������DNSӦ��Э�顣
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EgnDnsPacketInfo* pstDnsInfo:DNS������Ϣ<�ǿ�>
*        InOut: EgnDnsRequestResult* pstInspectResult:ʶ����<�ǿ�>
*        Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:  ��API�ڳɹ���ʼ��EGN��session���֮ǰ����ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����ã�����ֻ��sessionģʽ����ʹ�øýӿڡ�
*        Since: V3R6C00SPC200
*    Reference: EgnApiSnInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnDnsBlockInspect
(
    IN                  EGN_UINT16               usThreadID,        /* ʶ�����ID */
    IN      EGN_CONST   EGN_VOID                *pvHandle,          /* ʵ����� */
    IN      EGN_CONST   EgnDnsPacketInfo      *pstDnsInfo,        /* ��ʶ���DNSЭ����Ϣ */
    INOUT               EgnDnsRequestResult     *pstInspectResult   /* ʶ���� */
);

/*******************************************************************************
*    Func Name: EgnApiSnDnsRelParse
*      Purpose: ����DNS��Ӧ����
*  Description: ����DNS��Ӧ��������ȡIP��Ϣ������DNS����ʶ��
                    ����pulAddIpNum��ֵ���ж�EGN�������ɹ����IP�ĸ�����
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EgnDnsPacketInfo* pstDnsInfo:DNS������Ϣ<�ǿ�>
*        InOut: EGN_UINT32* pulAddIpNum:�ɹ����IP�ĸ���<�ǿ�>
*        Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:  ��API�ڳɹ���ʼ��EGN��SESSION���֮ǰ����ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���sessionģʽ�²��ɱ����á�
*        Since: V3R6C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnDnsRelParse
(
    IN              EGN_UINT16           usThreadID,
    IN              EGN_VOID            *pvHandle,
    IN  EGN_CONST   EgnDnsPacketInfo  *pstDnsInfo,
    OUT             EGN_UINT32          *pulAddIpNum
);

/*******************************************************************************
*    Func Name: EgnApiSnDnsDelIpFromIpTbl
*      Purpose: ɾ��ĳIP���
*  Description: �����û������IPɾ����Ӧ��IP���
*        Input: EGN_UINT16 usThreadID:�߳�ID
*               EGN_VOID  *pvHandle:ʵ�����<�ǿ�>
*               EgnIpAddr* pstIpAddr:IP�ṹ<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API������������ɵ���:
                1.�ɹ���ʼ��EGN��SESSION���֮ǰ
*               2.ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����á�
*               3.DNSӦ��ʶ�𿪹�Ϊ�ص�״̬
*               4.��sessionģʽ��
*        Since: V3R6C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnDnsDelIpFromIpTbl
(
    IN              EGN_UINT16       usThreadID,
    IN  EGN_CONST   EGN_VOID        *pvHandle,
    IN  EGN_CONST   EgnIpAddr       *pstIpAddr
);

/*******************************************************************************
*    Func Name: EgnApiSnDnsGetIpFromIpTbl
*      Purpose: ��ѯĳIP�����Ƿ���ڡ�
*  Description: �����û������IP��ѯ�Ƿ�����
*        Input: EGN_UINT16 usThreadID:�߳�ID
*               EGN_VOID *pvHandle:ʵ�����<�ǿ�>
*               EgnIpAddr* pstIpAddr:IP�ṹ<�ǿ�>
*        InOut: NA
*       Output: EGN_BOOL* pbIsExist:�ñ����Ƿ����<0:������
                                                   1:����>
*               EGN_UINT32* pulProtoID:��ȡ����Э��ID��0��ʾδ��ȡ
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API������������ɵ���:
                1.�ɹ���ʼ��EGN��SESSION���֮ǰ
*               2.ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����á�
*               3.DNSӦ��ʶ�𿪹�Ϊ�ص�״̬
*               4.��sessionģʽ��
*        Since: V3R6C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnDnsGetIpFromIpTbl
(
    IN                  EGN_UINT16       usThreadID,
    IN      EGN_CONST   EGN_VOID        *pvHandle,
    IN      EGN_CONST   EgnIpAddr       *pstIpAddr,
    OUT                 EGN_BOOL        *pbIsExist,
    OUT                 EGN_UINT32      *pulProtoID
);

/*******************************************************************************
*    Func Name: EgnApiSnDnsGetIpTblInfo
*      Purpose: ��ӡ����IPʵ����ip������Ӵ�������´���
*  Description: �û���ͨ���ýӿڻ�ȡ����ʵ��IP������Ӽ����´���( ��������һ����ӵ� )
*        Input: EGN_UINT16  usThreadID:�߳�ID
*               EGN_VOID   *pvHandle:ʵ�����<�ǿ�>
*               EGN_UINT32  ulIpTblInfoLen:����IP��Ϣ���ڴ��ܳ���
*        InOut: EGN_UCHAR  *pucIpTblInfo:����IP��Ϣ���ڴ��׵�ַ�����鴫��2K�ڴ�<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution:  ��API������������ɵ���:1.�ɹ���ʼ��EGN��SESSION���֮ǰ
*                                        2.ʹ�ö�̬�����ڴ淽ʽ�Ĳ�Ʒ���ɱ����á�
*                                        3.DNSӦ��ʶ�𿪹�Ϊ�ص�״̬
*                                        4.��sessionģʽ��
*        Since: V3R6C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnDnsGetIpTblInfo
(
    IN      EGN_UINT16       usThreadID,
    IN      EGN_VOID        *pvHandle,
    IN      EGN_UINT32       ulIpTblInfoLen,
    INOUT   EGN_UCHAR       *pucIpTblInfo
);

/*******************************************************************************
*    Func Name: EgnApiQueryBearedProtocols
*      Purpose: ��ѯ����Э��
*  Description: ��ѯ����Э��.����֪ʶ��ʱ����Ҫ��������֪ʶ��.
*        Input: EGN_UINT32 ulParentProtoID:����ѯ�ĸ�Э��ID<����>
*        InOut: EGN_UINT32* pulProtoIdListLen:���룺����ĳ��ȡ������ʵ�ʳ���Э�������<�ǿ�
                    �������ĳ��Ȳ��㣬�򷵻ش�����EGN_RET_ERR_BUF_MORE��ͬʱ�ó�������������С���ȡ�>
                EGN_UINT32* pulProtoIdList:�����ص���Э��ID�б�����(��������Э�鱾��)<�ǿ�>
*       Output:
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��ѯ�����ϵͳЭ�飬��֧�ֲ�ѯ�Զ���Э��
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiQueryBearedProtocols
(
    IN          EGN_UINT32      ulParentProtoID,
    INOUT       EGN_UINT32     *pulProtoIdList,
    INOUT       EGN_UINT32     *pulProtoIdListLen
);

/************************************************************************************************/
/* ����Ϊ��Ӳ��������ص�API */

/*STRUCT<����������Ϣ�Ľṹ�壬���������ڵ��� Search ʱ����ýṹ�壬��ģʽƥ������֮�󷵻�> */
typedef struct _EgnHAMatchInfo
{
    EGN_UINT32     ulPatternID;             /* ģʽ��ƥ������ʱ��Ψһ��־����ģʽ����ID */
    EGN_INT32      lCurPacketOffset;        /* ƥ���ģʽ����ʼλ������ڵ�ǰ������ͷ��ƫ�� */
    EGN_UINT32     ulFlowOffset;            /* ƥ���ģʽ����ʼλ�����������ǰ������ͷ����ƫ�� */
    EGN_UINT16     usPatternLen;            /* ģʽ������ */
    EGN_UINT8      aucReserved[2];          /* �����ֽڣ�64λ���� */
} EgnHAMatchInfo;

/*STRUCT<Ӳ�����е�ģʽ���ṹ����>*/
typedef struct _EgnHAMatchInfoList
{
    EGN_UINT16  usMatchInfoNum;             /* ����ģʽ������ */
    EGN_UINT8   ucIsFull;                   /* �Ƿ�ƥ�䳬�� */
    EGN_UINT8   aucReserved[5];             /* �����ֽڣ�64λ���� */
    EgnHAMatchInfo  astMatchInfo[EGN_HA_RETURN_PATT_MAX];  /* Ӳ�����е�ģʽ���ṹ���� */
} EgnHAMatchInfoList;

/*STRUCT<�Ự��Ϣ >*/
typedef struct _EgnHASessionInfo
{
    EGN_VOID        *pvNgeSessionAddr;   /* NGE�Ự�ĵ�ַ */
    EGN_UINT32       ulDpSessVersion;    /* �Ự�汾�� */
    EGN_UINT16       usVrfID;            /* �������ǽID */
    EGN_UINT8        ucHAPatternSetID;   /* Ӳ������ģʽ�����ID���൱��ԭGPM_PATTSETKEY_ST�ṹ�е�uiMLable */
    EGN_UINT8        ucRuleLibID;        /* ��ǰ�Ựʹ�õ�֪ʶ��ID���൱��ԭGPM_PATTSETKEY_ST�ṹ�е�uiSLable */
} EgnHASessionInfo;

/*STRUCT<ģʽ���������ݽṹ >*/
typedef struct _EgnPatternAtt
{
    EGN_UINT8   ucNoCase;           /* �Ƿ��Сд���У�����AC�㷨��Ч */
    EGN_UINT8   ucType;             /* �Ƿ�Ϊ������ʽ�������������ʽҪ��һ��������ʽ�ļ�� 0:��ͨ�ַ���,1:������ʽ */
    EGN_UINT8   aucReserved[6];     /* �����ֽڣ�64λ���� */
} EgnPatternAtt;

/*STRUCT<��������Ϣ >*/
typedef struct _EgnNgfwRel
{
    EGN_UINT32  ulType;         /* ������Ķ��� */
    EGN_UINT32  ulDpSessVer;    /* ת����Ự�汾�� */
    EgnPeerInfoSetItem  stPeerItem;
    EGN_VOID    *pvNgeSess;     /* NGE�Ựָ�� */
} EgnNgfwRel;

/*STRUCT<���������ͬ����Ϣ�Ľṹ��Ŀǰֻ��ͬ����������һ��> */
typedef struct _EgnSynMsg
{
    EGN_UINT32  ulMsgType;          /* ��Ϣ���� */
    EGN_UINT8   aucReserved[4];
    union
    {
        EgnNgfwRel  stNgfwRel;      /* �ṩ��NGFW�� */
    }u;
} EgnSynMsg;

/*******************************************************************************
*    Func Name: EgnApiNgfwHASelectHardwareHandle
*      Purpose: ѡ��Ӳ�����ٵ�״̬��
*  Description: Ӳ�����ٷ�����Ӳ���л���ڶ��״̬����ÿ�α��Ľ���Ӳ��ƥ��ǰ����Ҫ��
                  ���˽ӿ���ѡ���Ӧ��Ӳ��ƥ��״̬����
                ��EgnHASessionInfo�ṹ�е�ucHAPatternSetID����EGN_HA_PATTERN_SET_TYPE_INVALID��
                  ��ǰ���Ĳ�������Ӳ��ƥ�䣬ֱ�������ƥ�䡣
*        Input: EGN_CONST EgnPacket*    pstPacketInfo   :����<�ǿ�>*
*        InOut: EgnHASessionInfo*       pstSessInfo     :�Ự��Ϣ<�ǿ�>
*               EGN_VOID**              ppvFlowInspect  :��ʶ����<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: NA
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwHASelectHardwareHandle
(
    IN EGN_CONST EgnPacket          *pstPacketInfo,
    INOUT        EgnHASessionInfo   *pstSessInfo,
    INOUT        EGN_VOID          **ppvFlowInspect
);

/*******************************************************************************
*    Func Name: EgnApiNgfwHAPacketInspect
*      Purpose: Ӳ���������ʶ��ӿڡ�
*  Description: ͨ��Ӳ�����ٽ����2��4������ı��Ĵ������Э��ʶ��
*        Input: EGN_UINT16          usThreadID          :��ʵ���߳�ID<0~65535>
*               EGN_VOID*           pvMulInstanceHandle :ʵ�����<�ǿ�>
*               EGN_VOID**          ppvFlowInspect      :��ʶ����<�ǿ�>
*               EgnPacket*          pstPacketInfo       :����<�ǿ�>
*               EgnHAMatchInfoList* pstMatchList        :Ӳ��ƥ����Ϣ<�ǿ�>
*               EgnHASessionInfo*   pstSessInfo         :�Ự��Ϣ<�ǿ�>
*        InOut: NA
*       Output: EgnResult*          pstInspectResult    :ʶ����<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API�ڳɹ���ʼ��EGNʶ���̳߳ɹ�����EgnApiInspectorInit֮ǰ���ɱ����á�
*        Since: V300R006C00SPC200
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiNgfwHAPacketInspect
(
    IN           EGN_UINT16          usThreadID,
    IN           EGN_VOID           *pvMulInstanceHandle,
    IN           EGN_VOID          **ppvFlowInspect,
    IN EGN_CONST EgnPacket          *pstPacketInfo,
    IN           EgnHAMatchInfoList *pstMatchList,
    IN           EgnHASessionInfo   *pstSessInfo,
    OUT          EgnResult          *pstInspectResult
);

/*******************************************************************************
*    Func Name: EgnApiGetMemSizeOnlyLoadRuleLib
*      Purpose: ��ֻ��������֪ʶ�������£��������������ڴ档
*  Description: ��APIֻ������ֻ��������֪ʶ�������£�����Ҫ���ڴ��С��
*                  ��ʱ��������ڴ��ǰ�����ģΪ1��������Ϊ0��ʵ������Ϊ1������������
*        Input: NA
*        InOut: NA
*       Output: EGN_ULONG pulmemSize:�����ڴ��С
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*               2����API�����û��趨��ulMemPolicyΪEGN_MEM_POLICY_ONLY_LOAD_TXT_RULELIB��ģʽ�µ���
*               3���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V3R6C02
*    Reference: EgnApiInitPubParam
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetMemSizeOnlyLoadRuleLib
(
    OUT  EGN_ULONG  *pulmemSize
);

/*******************************************************************************
*    Func Name: EgnApiGetProtoInfoRuleLibVersion
*      Purpose: ��ȡ֪ʶ��汾
*  Description: ��EgnApiGetRuleLibVersion�ĺ����������ڣ�֧���ڲ��������Ŀ�������
*                  ��ѯ��֪ʶ��汾��
*        Input: NA
*        InOut: EgnRuleLibVersion pstRuleLibVersion:֪ʶ��汾�ṹ<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R006C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetProtoInfoRuleLibVersion
(
    INOUT EgnRuleLibVersion *pstRuleLibVersion
);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __EGN_API_COMMON_H__ */

