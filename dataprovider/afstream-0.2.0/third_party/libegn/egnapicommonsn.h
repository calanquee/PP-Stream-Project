/*
 ******************************************************************************
 ��Ȩ���� (C), 2008-2009, ��Ϊ�������޹�˾
 ******************************************************************************
  �� �� ��   : egnapicommonsn.h
  �� �� ��   : ����
  ��    ��   : EGN��Ŀ��
  ��������   : 2012��06��07��
  ����޸�   :
  ��������   : �����궨��
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2012��06��07��
    ��    ��   : EGN��Ŀ��
    �޸�����   : �����ļ�

******************************************************************************/
/**@file  egnapicommonsn.h
  *    �����궨��
*******************************************************/
/**
 * @defgroup session  EGN�Ựģ���API
 */

#ifndef __EGN_API_COMMON_SN_H__
#define __EGN_API_COMMON_SN_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/*STRUCT< ʶ����� >*/
typedef struct _EgnCfgParam
{
    EGN_UINT32  ulFlowScale;            /* �������ģ����ֵ���ܳ���10000000 */
    EGN_UINT32  ulRelScaleIPv4;         /* IPv4�������С����ֵ���ܳ���10000000 */
    EGN_UINT32  ulRelScaleIPv6;         /* IPv6�������С����ֵ���ܳ���10000000 */
#ifdef EGN_64
    EGN_UINT8   aucReserved[4];         /* 64λ���뱣���ֽ� */
#endif
} EgnCfgParam;

/*STRUCT< �Ự���� >*/
typedef struct _EgnSnCfgParam
{
    EGN_UINT32  ulSnSwitch;             /* Session���ܿ��� */
    EGN_UINT32  ulSnFlowScale;          /* ��ҪSn���������������ڼ���Sn�м�״̬�ڴ棬������ */
    EGN_UINT32  ulSnCBCntIPv4;          /* IPv4�Ự����ʶ��CB�����Ŀ */
    EGN_UINT32  ulSnCBCntIPv6;          /* IPv6�Ự����ʶ��CB�����Ŀ */
    EGN_UINT32  ulSnBodyMemCache;       /* 2k���� */
    EGN_UINT32  ulSnBodyMemDecompress;  /* 6k���� */
} EgnSnCfgParam;

/*******************************************************************************
*    Func Name: PFEgnSspDeCompress
*      Purpose: ��ѹ���ص�ԭ��
*  Description: ��ѹ���ص�ԭ��
*        Input: EGN_UINT32 ulCompressType:ѹ������<EGN_SN_DECOMPRESS_TYPE_EN>
                EGN_UCHAR *pucInData:ѹ������<�ǿ�>
                EGN_UINT32 ulInDataLen:ѹ�����ݳ���<������>
*        InOut: EGN_UCHAR *pucOutData:��ѹ����<�ǿ�>
                EGN_UINT32 *pulOutDataLen:��ѹ���ݳ���<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��
*        Since: V300R06C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnSspDeCompress)
(
    IN    EGN_UINT32      ulCompressType,  /* ѹ������ */
    IN    EGN_UCHAR      *pucInData,       /* ѹ������ */
    IN    EGN_UINT32      ulInDataLen,     /* ѹ�����ݳ��� */
    INOUT EGN_UCHAR      *pucOutData,      /* ��ѹ���� */
    INOUT EGN_UINT32     *pulOutDataLen    /* ��ѹ���ݳ��� */
);
/*STRUCT< ϵͳ�����ܵĻص��������� >*/
typedef struct _EgnSnSspFunc
{
    PFEgnSspDeCompress  pfDeCompress;      /* ��ѹ�� ���� */
} EgnSnSspFunc;

/*STRUCT< SSP�ص��ӿ� >*/
typedef struct _EgnSnSspSmpGlobalInfo
{
    EgnSnSspFunc   stSnSspCallback;        /* SSP�ص��ӿ� */
} EgnSnSspSmpGlobalInfo;

/*ENUM< Session��ѹ������ >*/
typedef enum
{
    EGN_SN_DECOMPRESS_TYPE_BEGIN            = EGN_EN_INVALID,
    EGN_SN_DECOMPRESS_TYPE_GZIP             = 0,              /* Gzip��ѹ�� */
    EGN_SN_DECOMPRESS_TYPE_END,

    EGN_SN_DECOMPRESS_TYPE_BOTTOM           = EGN_EN_BUTT
}EGN_SN_DECOMPRESS_TYPE_EN;

/*******************************************************************************
*    Func Name: EgnApiSnPacketInspect
*      Purpose: �����2��4�������ı��Ĵ��벢����Э��ʶ��
*  Description: ��������ʵ���߳�ID��ʵ���������ʶ�����ͱ��Ļ�ȡʶ������ʶ����չ������
                �û����Ը���ʶ����EgnResult�е�bIsContinue�������Ƿ�����������������ʶ��
                ��bIsContinueΪEGN_TRUE��Ҫ�������������bIsContinueΪEGN_FALSE����Ҫ�����������
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EGN_VOID** ppvFlowInspect:��ʶ����<�ǿ�>
*               EgnPacket* pstPacketInfo:����<�ǿ�>
*        InOut: EgnResult* pstIspectResult:ʶ����<�ǿ�>
*               EgnInspectAuxData* pstAuxData:ʶ����չ����<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API�ڳɹ���ʼ��EGNʶ���߳�EgnApiSnInspectorInit�ɹ�֮ǰ���ɱ����á�
*        Since: V300R06C00
*    Reference: EgnApiSnInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnPacketInspect
(
    IN                EGN_UINT16           usThreadID,
    IN                EGN_VOID            *pvHandle,
    IN                EGN_VOID           **ppvFlowInspect,
    IN     EGN_CONST  EgnPacket           *pstPacketInfo,
    INOUT             EgnResult           *pstInspectResult,
    INOUT  EGN_CONST  EgnInspectAuxData   *pstAuxData
);

/*******************************************************************************
*    Func Name: EgnApiSnReleaseCtxData
*      Purpose: �ͷ�ָ������ʶ������
*  Description: ���ڷ��װ�ʶ�������ʶ�������ʹ�øýӿ��ͷ���ʶ������
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_VOID* pvHandle:��ʵ�����������Ϊ��<�ǿ�>
*               EGN_VOID** ppvCtxData:��ʶ����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID
*      Caution: ��API�ڳɹ���ʼ��EGNʶ���߳�EgnApiSnInspectorInit�ɹ�֮ǰ���ɱ����á�
*        Since: V300R06C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_VOID EgnApiSnReleaseCtxData
(
    IN              EGN_UINT16    usThreadID,
    IN              EGN_VOID     *pvHandle,
    IN              EGN_VOID    **ppvCtxData
);

/*******************************************************************************
*    Func Name: EgnApiSnInitPubParam
*      Purpose: ����EGN��Ĭ�ϳ�ʼ�����ò�����
*  Description: �ýӿ��ṩ��Ĭ�ϲ������ù��ܣ�����ȱʡֵ������EGN��Ĭ�ϳ�ʼ�����ò�����
                �����Щ��������ϣ���������ã��������������Ƚ����ѣ�����ʹ�øýӿڽ������á�
                ��ص����ò�������μ�_EgnInitCfgParam�Ĳ�����
*        Input: EgnInitCfgParam* pstParam:��ʼ������<�ǿ�>
*               EgnSnCfgParam* pstParamSn:��ʼ������<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V300R06C00
*    Reference: EgnInitCfgParam
*               EgnSnCfgParam
                EgnApiSnMngInit
                EgnApiSnGetNeededMemSize
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnInitPubParam
(
    IN  EgnInitCfgParam    *pstParam,
    IN  EgnSnCfgParam      *pstParamSn
);

/*******************************************************************************
*    Func Name: EgnApiSnMngInit
*      Purpose: ��ʼ�������߳�
*  Description: EGN�����̳߳�ʼ���ӿڣ����EGN�����Ҫʹ�õ�ϵͳ��Դ�����롢��ʼ���ȹ�����
                ����EgnApiSnMngInitǰ����Ҫ�ȵ���EgnApiSnInitPubParam��ʼ��EGN�����ò�����
                ����ȱʡֵ������EGN��Ĭ������ֵ�����Ĭ��ֵ������ҵ�����󣬿���ֱ�ӵ���EgnApiSnMngInit��ʼ����
                ���Ĭ��ֵ��������ҵ�����󣬿��Ը���ҵ�������޸���Ӧ������ֵ���ٵ���EgnApiSnMngInit��ʼ��EGNģ��Ĺ����̡߳�
*        Input: EGN_UCHAR* pucGlobalBuffer:ȫ���ڴ��׵�ַ<�ǿ�>
*               EGN_UINT32 ulBufferLen:ȫ���ڴ泤��<������>
*               EgnInitCfgParam* pstParam:������Ϣ<�ǿ�>
*               EgnSnCfgParam* pstParamSn:������Ϣ<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1��������˵���⣬����APIӦ�ڳɹ���ʼ��EGN�����̳߳ɹ����ø�API֮����ܱ�ʹ�á�
                2���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V300R06C00
*    Reference: EgnApiSnInitPubParam
*               EgnApiSnMngDestroy
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnMngInit
(
   IN            EGN_UCHAR           *pucGlobalBuffer,
   IN            EGN_ULONG            ulBufferLen,
   IN  EGN_CONST EgnInitCfgParam     *pstParam,
   IN  EGN_CONST EgnSnCfgParam       *pstParamSn
);

/*******************************************************************************
*    Func Name: EgnApiSnInspectorInit
*      Purpose: ��ʼ��ʶ��ʵ����
*  Description: ����ʶ��ʵ����ʼ���ӿڣ��ڶ���̡����߳�ģ���µ��ã����ҵ����̡��̵߳ĳ�ʼ����
                ��ʵ��ʱʶ��ʵ����������ĳ�ʼ����
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_UCHAR* pucGlobalBuffer:�����߳��ڴ���׵�ַ<�ǿ�>
*               EGN_UINT32 ulBufferLen:�����߳��ڴ�س���<������>
*        InOut: NA
*       Output: EGN_VOID** ppvHandle:ʵ���������ʼ������Ϊ��ʵ�������ľ�����ⲿ���ܸı�< >
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1��������˵���⣬����APIӦ�ڳɹ���ʼ��EGNʶ���̹߳�������ʱ���ɹ����ø�API֮����ܱ�ʹ�á�
                2���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V300R06C00
*    Reference: EgnApiSnInspectorDestroy
                EgnApiSnPacketInspect
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnInspectorInit
(
    IN     EGN_UINT16         usThreadID,
    IN     EGN_UCHAR         *pucGlobalBuffer,
    IN     EGN_ULONG          ulBufferLen,
    OUT    EGN_VOID         **ppvHandle
);

/*******************************************************************************
*    Func Name: EgnApiSnMngDestroy
*      Purpose: ȥ��ʼ�������߳�
*  Description: ��ɹ�����̡��߳�ϵͳ��Դ���ͷŵȹ�����
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API�ڳɹ���ʼ��EGN�����̳߳ɹ�����EgnApiSnMngInit֮ǰ�ɱ����á�
                2������̡����߳�ģ���µ��ã����߳�ģ���²��ܵ��ñ��ӿڡ�
                3���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V300R06C00
*    Reference: EgnApiSnMngInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnMngDestroy
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiSnInspectorDestroy
*      Purpose: ȥ��ʼ��ʶ��ʵ����
*  Description: ���ҵ����̡��߳�ϵͳ��Դ���ͷŵȹ�����
*        Input: EGN_UINT16 usThreadID:���ô˽ӿڵ��߳�ID<0~65535>
*               EGN_VOID** ppvHandle:ʵ�����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����ʵ��ʱʶ��ʵ�����������ȥ��ʼ����
                2���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V300R06C00
*    Reference: EgnApiSnInspectorInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnInspectorDestroy
(
    IN  EGN_UINT16  usThreadID,
    IN  EGN_VOID  **ppvHandle
);

/*******************************************************************************
*    Func Name: EgnApiSnGetNeededMemSize
*      Purpose: �������������ڴ档
*  Description: ��API�ӿڸ����������ģulFlowScale���������СulRelationScale��ʶ��ʵ������usMaxInstance
                ���ڴ��Ƿ���bIsMemShared���������ʵ�����蹲���ڴ��СpulSharedMemSize��ÿ��ʶ��ʵ������
                �ǹ����ڴ�Ĵ�СpulUnSharedMemSize����λ�ֽڡ�
*        Input: EgnInitCfgParam pstParam:���������������<�ǿ�>
*               EgnSnCfgParam pstSnParam:Session����ר��<�ǿ�>
*               EGN_UINT16 usMaxInstance:ʶ��ʵ����������ֵ���ܳ���32<1~32>
*               EGN_BOOL bIsMemShared:�Ƿ����ڴ�<EGN_FALSE��������
                                                  EGN_TRUE������>
*        InOut: EGN_UINT32* pulSharedMemSize:����ʵ�����蹲���ڴ��С<�ǿ�>
*               EGN_UINT32* pulUnSharedMemSize:ÿ��ʶ��ʵ������ǹ����ڴ�Ĵ�С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
                2���û�ʹ��ʱ�ϸ�����������Ӧ��������API�ӿ�ֻ�����ڴ����Ϊ�����޵�ʱ�����Ч��
                   ������EGN��������ʱ����ulMemPolicy��ʼ��ΪEGN_MEM_POLICY_UNLIMIT��EGNĬ�����øò���Ϊ�����ޡ�
                3���ڶ�̬�ڴ�ģʽ�²��ܵ��øýӿڣ�����ᵼ��ʶ��ҵ���쳣��
*        Since: V300R06C00
*    Reference: EgnApiSnInitPubParam
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnGetNeededMemSize
(
    IN     EGN_CONST EgnInitCfgParam *pstParam,
    IN     EGN_CONST EgnSnCfgParam   *pstSnParam,
    IN               EGN_UINT16       usMaxInstance,
    IN               EGN_BOOL         bIsMemShared,
    INOUT            EGN_ULONG       *pulSharedMemSize,
    INOUT            EGN_ULONG       *pulUnSharedMemSize
);

/*******************************************************************************
*    Func Name: EgnApiSnRegDeCompressFn
*      Purpose: ע���ѹ���Ļص�������
*  Description: ע���ѹ���Ļص�������
*        Input: PFEgnSspDeCompress pfDeCompress:��ѹ����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V300R06C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnRegDeCompressFn
(
    IN  PFEgnSspDeCompress  pfDeCompress
);

/*******************************************************************************
*    Func Name: EgnApiSnGetIdleRelationCBCount
*      Purpose: ��ȡ���еĹ���ʶ��CB��ĸ�����
*  Description: ���������ʵ���߳�ID��ʵ���������ȡ���еĹ���ʶ��CB��ĸ�����
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*        InOut: EGN_UINT32* pulIdleCBCountIPv4:Egn���е�IPv4����ʶ��CB��ĸ���<�ǿ�>
*               EGN_UINT32* pulIdleCBCountIPv6:Egn���е�IPv6����ʶ��CB��ĸ���<�ǿ�>
*               EGN_UINT32* pulIdleCBCountIPv4Sn:Session���е�IPv4����ʶ��CB��ĸ���<�ǿ�>
*               EGN_UINT32* pulIdleCBCountIPv6Sn:Session���е�IPv6����ʶ��CB��ĸ���<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1����API�ڳ�ʼ��EGNʶ���̣߳�����EgnApiExpandInspectorInit�����EgnApiInspectorInit�����EgnApiSnInspectorInit��֮ǰ���ɱ����á�
                2����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                3����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
*        Since: V300R06C00
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnGetIdleRelationCBCount
(
    IN      EGN_UINT16      usThreadID,
    IN      EGN_VOID       *pvHandle,
    INOUT   EGN_UINT32     *pulIdleCBCntIPv4,
    INOUT   EGN_UINT32     *pulIdleCBCntIPv6,
    INOUT   EGN_UINT32     *pulIdleCBCntIPv4Sn,
    INOUT   EGN_UINT32     *pulIdleCBCntIPv6Sn
);

/*******************************************************************************
*    Func Name: EgnApiSnGetSysInfoExt
*      Purpose: �ռ�SESSION������Ϣ��
*  Description: EGNһ��ʽ��Ϣ�ռ��ӿڣ����������ʵ���߳�IDusThreadID��ʵ�����pvHandle��
                ����ʵ����������Ϣ�������׵�ַΪpucSysInfo���ڴ��С�
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID* pvHandle:ʵ�����<�ǿ�>
*               EGN_UINT32 ulSysInfoLen:����������Ϣ�ڴ��ܳ���<������>
*        InOut: NA
*       Output: EGN_UCHAR* pucSysInfo:����������Ϣ�ڴ��׵�ַ�����鴫��12k�ڴ�<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: 1���ڵ��øýӿ�֮ǰҪEGN��SESSION�����ʼ����ϡ�
                2����API��ʶ���̱߳�����ʱ��������������̵߳�ʶ��ʵ��������������Ϊ������߳̿ɿ���У���ʧЧ��
                3����API�ڹ����̱߳�����ʱ��ʶ��ʵ������������Ϊ�գ���ʱ������ж��߳̿ɿ���У�顣
                4��session��ȥʹ��״̬�£�ͨ��EgnApiGetSysInfoExt��ȡ��Ϣ������ʾCB���֪ʶ�����Ϣ��
                5���ⲿͨ����ӡ������ʾSESSION��������Ϣ
*        Since: V300R005C02
*    Reference: ��
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnGetSysInfoExt
(
    IN            EGN_UINT16   usThreadID,
    IN            EGN_VOID    *pvHandle,
    OUT           EGN_UCHAR   *pucSysInfo,
    IN            EGN_UINT32   ulSysInfoLen
);

/*******************************************************************************
*    Func Name: EgnApiSnGetHealthInfo
*      Purpose: SN��ȡһ��ʽ������������Ϣ��
*  Description: EGNһ��ʽ�������ӿڣ����EGN��������Ϣ�Ľ�����飬������Ӧʵ���Ľ�����Ϣ
                �洢���׵�ַΪppucHealthInfo���ڴ��С�
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
*    Reference: EgnApiSnFreeHealthInfo
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiSnGetHealthInfo
(
    IN            EGN_UINT16   usThreadID,
    IN            EGN_VOID    *pvHandle,
    OUT           EGN_UCHAR  **ppucHealthInfo,
    OUT           EGN_UINT32  *pulHealthInfoLen
);

/*******************************************************************************
*    Func Name: EgnApiSnFreeHealthInfo
*      Purpose: Sn�ͷ�һ��ʽ���������Ϣ���ڴ档
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
*    Reference: EgnApiSnGetHealthInfo
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_VOID EgnApiSnFreeHealthInfo
(
    IN              EGN_UINT16    usThreadID,
    IN              EGN_VOID     *pvHandle,
    INOUT           EGN_UCHAR   **ppucHealthInfo
);

/*******************************************************************************
*    Func Name: EgnApiSnGetMngInfo
*      Purpose: session����ӿ�ʹ�÷��ͳһ����������Ϣ��ѯ�ӿ�
*  Description: 1.�ڵ��øýӿ�֮ǰҪsession��EGN�����ʼ�����
*               2.�ⲿ�ɸ��ݻ�ȡ��Ϣ��������ȷ��ȡ��Ϣ�����ݽṹ����������ݽṹ�ڽṹ��EgnGetCfgInfo��,
*                �ýṹ���еĹ������Ӧ�������ݽṹ�����ݽṹ��ͳһ������ʽ:��Σ�����In;����Σ�����InOut;���Σ�����Out������ָ�����͵ı������û������䴫��ĸ��������ڴ档
*                (���������뷵�ؽ���Ķ�Ӧ��ϵ��EGN_UNITE_GET_SET_EN)
*        Input: EGN_UINT32      ulInfoEnum:��ѯ����<EGN_UNITE_GET_SET_EN
*                (ulInfoEnum�ķ�Χ"EGN_UNITE_GET_SET_ENGINE_VERSION~EGN_UNITE_GET_SET_SN_BODY_MEM_DECOMPRESS"����ȥEGN_UNITE_GET_SET_MATCHED_RULE_INFO��
*                 ����EGN_UNITE_GET_SET_STATIC_BLOCK_INFO��EGN_UNITE_GET_SET_CB_STATIC_INFO��EGN_UNITE_GET_SET_SN_CB_STATIC_INFO��EGN_UNITE_GET_SET_SN_STATIC_BLOCK_INFO���͵���Ϣֻ���ڴ�Ϊ����ģʽʱ������ͨ���ýӿڻ�ȡ)>
*        InOut: EgnGetCfgInfo*    pstGetCfgInfo:��ȡ������Ϣ�׵�ַ<�ǿ�>
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
EGN_UINT32 EgnApiSnGetMngInfo
(
    IN     EGN_UINT32       ulInfoEnum,
    INOUT  EgnGetCfgInfo   *pstGetCfgInfo
);

/*******************************************************************************
*    Func Name: EgnApiSnGetInspectorInfo
*      Purpose: session����ӿ�ʹ�÷��ͳһ��ҵ������Ϣ��ѯ�ӿ�
*  Description: 1.�ڵ��øýӿ�֮ǰҪsession��EGN�����ʼ�����
*               2.�ⲿ�ɸ��ݻ�ȡ��Ϣ��������ȷ��ȡ��Ϣ�����ݽṹ����������ݽṹ�ڽṹ��EgnGetCfgInfo��,
*                �ýṹ���еĹ������Ӧ�������ݽṹ�����ݽṹ��ͳһ������ʽ:��Σ�����In;����Σ�����InOut;���Σ�����Out������ָ�����͵ı������û������䴫��ĸ��������ڴ档
*                (���������뷵�ؽ���Ķ�Ӧ��ϵ��EGN_UNITE_GET_SET_EN)
*               3.��API�����ڹ����̵߳��ã�ֻ����ʶ���̵߳��ã\
*               4.������������̵߳�ʶ��ʵ������Ͷ�Ӧ���߳�id
*        Input: EGN_UINT32  ulInfoEnum:��ѯ����<EGN_UNITE_GET_SET_EN
*               (ulInfoEnum�ķ�Χ"EGN_UNITE_GET_SET_STATIC_BLOCK_INFO, EGN_UNITE_GET_SET_MATCHED_RULE_INFO",
                "EGN_UNITE_GET_SET_SN_CB_STATIC_INFO, EGN_UNITE_GET_SET_SN_STATIC_BLOCK_INFO"(session���������Ϣ)>
*               EGN_UINT16  usThreadID:ʵ���߳�ID<0~65535>
*               EGN_VOID*    pvHandle:ʵ��handle<�ǿ�>
*        InOut: EgnGetCfgInfo*  pstGetCfgInfo:��ȡ������Ϣ�׵�ַ<�ǿ�>
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
EGN_UINT32 EgnApiSnGetInspectorInfo
(
    IN        EGN_UINT32      ulInfoEnum,
    IN        EGN_UINT16      usThreadID,
    IN        EGN_VOID       *pvHandle,
    INOUT     EgnGetCfgInfo  *pstGetCfgInfo
);

/*******************************************************************************
*    Func Name: EgnApiSnSetCfgParamInfo
*      Purpose: session����ӿ�ʹ�÷��ͳһ��ͳһ����������Ϣ����Ϊ��̬�����붯̬����
*  Description: 1.��̬����:����ʱ�����ڳ�ʼ��֮ǰ����ע���˻ص�����֮�󣬷��򷵻�ʧ�ܡ�
*                 ����ڳ�ʼ��Ĭ�ϲ���֮����ã����ڵ���EgnApiSnInitPubParam֮����øýӿڣ����õ�������Ϣ��Ч�������سɹ���
*                 ��̬���õĲ����ɹ���������Ч���ýӿڵĵ���ʱ�����ڳ�ʼ��Ĭ�ϲ���֮ǰ��ע���˻ص�����֮����ϵͳδ��ʼ��
*               2.��̬����:EGN�����ʼ�����,���򷵻�ʧ��
*               3.�ⲿ�ɸ���������Ϣ��������ȷ������Ϣ�����ݽṹ����������ݽṹ�ڽṹ��EgnSetCfgParamInfo��,
*                �ýṹ���еĹ������Ӧ�������ݽṹ�����ݽṹ��ͳһ������ʽ:��Σ�����In;����Σ�����InOut;���Σ�����Out������ָ�����͵ı������û������䴫��ĸ��������ڴ档
*                (���������뷵�ؽ���Ķ�Ӧ��ϵ��EGN_UNITE_GET_SET_EN)��
*               4.�ýӿڿ�����session���������Ϣ��EGN���������Ϣ��
*        Input: EGN_UINT32      ulSetType:���õ�����<0:��̬��1:��̬>
*               EGN_UINT32      ulEnumNum:��ѯ����<EGN_UNITE_GET_SET_EN
*                 (ulInfoEnum�ķ�Χ����̬����:"EGN_UNITE_GET_SET_DETECT_THRESHOLD, EGN_UNITE_GET_SET_UDRULE_SWITCH_INFO",
                  "EGN_UNITE_GET_SET_CFG_PARA_IS_SHARE, EGN_UNITE_GET_SET_UD_BACK_RULE_LIB_NEED_MEM"
*                  "EGN_UNITE_GET_SET_SN_SWITCH, EGN_UNITE_GET_SET_SN_BODY_MEM_DECOMPRESS"(session���������Ϣ)
*                 ��̬����:"EGN_UNITE_GET_SET_DETECT_THRESHOLD, EGN_UNITE_GET_SET_IP_FLOW_AGED_TIME", "EGN_UNITE_GET_SET_PROTO_IMPORT_STATE, EGN_UNITE_GET_SET_STAT_CONTROL")>
*               EGN_VOID*    pvHandle:ʵ��handle<�ǿ�>InOut: EgnSetCfgParamInfo*    pstSetCfgParamInfo:�����õ���Ϣ
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
EGN_UINT32 EgnApiSnSetCfgParamInfo
(
    IN      EGN_UINT32              ulSetType,
    IN      EGN_UINT32              ulEnumNum,
    INOUT   EgnSetCfgParamInfo     *pstSetCfgParamInfo
);

/*******************************************************************************
*    Func Name: EgnApiSnExpendInspectorInit
*      Purpose: �Ự����ģʽ�³�ʼ��ʶ��ʵ����
*  Description: ����ʶ��ʵ����ʼ���ӿڣ��ڶ���̡����߳�ģ���µ��ã����ҵ����̡��̵߳ĳ�ʼ������ʵ��ʱʶ��ʵ����������ĳ�ʼ����
*        Input: EGN_UINT16  usThreadID�����ô˽ӿڵ��߳�ID<0~65535>
                EGN_UCHAR*  pucSharedBuffer�������߳��ڴ���׵�ַ<�ǿ�>
                EGN_ULONG   ulBufferLen�������߳��ڴ�س���<������>
                EGN_UCHAR*  pucUnsharedBuffer���ǹ����߳��ڴ���׵�ַ<�ǿ�>
                EGN_ULONG   ulUnsharedBufferLen���ǹ����߳��ڴ�س���<������>
*        InOut: NA
*       Output: EGN_VOID**  ppvHandle��ʵ���������ʼ������Ϊ��ʵ�������ľ�����ⲿ���ܸı�<�ǿ�>
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
EGN_UINT32  EgnApiSnExpendInspectorInit
(
   IN  EGN_UINT16           usThreadID,
   IN  EGN_UCHAR           *pucSharedBuffer,
   IN  EGN_ULONG            ulSharedBufferLen,
   IN  EGN_UCHAR           *pucUnsharedBuffer,
   IN  EGN_ULONG            ulUnsharedBufferLen,
   OUT EGN_VOID           **ppvHandle
);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __EGN_API_COMMON_H__ */

