/*
 ******************************************************************************
 ��Ȩ���� (C)�� 2008-2010�� ��Ϊ�������޹�˾
 ******************************************************************************
  �� �� ��   : egnapiipflow.h
  �� �� ��   : ����
  ��    ��   : EGN��Ŀ��
  ��������   : 2010��12��3��
  ����޸�   :
  ��������   : ����ӿڶ���
  �����б�   :
******************************************************************************/
/**
 *@file  egnapiipflow.h
 *�������ͷ�ļ�
*/
#ifndef  __EGN_API_IPF_
#define __EGN_API_IPF_

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/*STRUCT< ������Ϣ >*/
typedef struct _EgnIpFlowTblInfo
{
    EGN_UINT32  ulTotalFlow;     /* ��������� */
    EGN_UINT32  ulIdleFlow;      /* ������������ */
} EgnIpFlowTblInfo;

/*STRUCT< ͳ���� >*/
typedef struct _EgnIpFlowStatInfo
{
    EGN_UINT32  ulReceivedCnt;    /* ���յ��ı������� */
    EGN_UINT32  ulSeqRejectCnt;   /* ���кŴ���Ķ������ĸ��� */
    EGN_UINT32  ulOtherRejectCnt; /* �����������İ��ĸ��� */
    EGN_UINT32  ulSuccessCnt;     /* ʶ��ɹ��İ��ĸ��� */
    EGN_UINT32  ulUnknownCnt;     /* δʶ�������İ��ĸ��� */
    EGN_UINT32  ulErrorCnt;       /* ʶ�𷵻ش���İ��ĸ��� */
}EgnIpFlowStatInfo;

/*STRUCT< ��Ԫ�� >*/
typedef struct _EgnIpFlowFiveTuple
{
    EGN_UINT32  ulSrcIp;        /* IPv4 source address */
    EGN_UINT32  ulDstIp;        /* IPv4 destination address */
    EGN_UINT16  usSrcPort;      /* Source Port */
    EGN_UINT16  usDstPort;      /* Destination Port */
    EGN_UINT8   ucProto;        /* �����Э�����ͣ���Ӧ��#EGN_TRANS_TYPE_EN */
    EGN_UINT8   aucReserved[3];
} EgnIpFlowFiveTuple;

/*STRUCT< �����ʼ�����ò��� >*/
typedef struct _EgnIpFlowTblCfgParam
{
    EGN_UINT32  ulSize;            /* ���Ĺ�ģ */
    EGN_UINT8   aucReserved[4];    /* �����ֽڣ�64λ���� */
} EgnIpFlowTblCfgParam;

/*STRUCT< ��չ���������ں�����չ >*/
typedef struct _EgnIpFlowAuxData
{
    EGN_UINT32 ulAuxData;          /* ��չ���� */
    EGN_UINT32 ulReserved;         /* �����ֽڣ�64λ���� */
}EgnIpFlowAuxData;

/*STRUCT< ��ʼ����̬�ڴ�Buffer >*/
typedef struct _EgnIpFlowInitStaticBuf
{
    EGN_UCHAR  *pucIpFlowBuf;     /* EgnIpFlow�ڴ���ʼ��ַ */
    EGN_UCHAR  *pucSharedBuf;     /* �����ڴ���ʼ��ַ */
    EGN_UCHAR  *pucUnsharedBuf;   /* �ǹ����ڴ���ʼ��ַ */
    EGN_ULONG   ulIpFlowBufLen;   /* EgnIpFlow�ڴ泤�� */
    EGN_ULONG   ulSharedBufLen;   /* �����ڴ泤�� */
    EGN_ULONG   ulUnsharedBufLen; /* �ǹ����ڴ泤�� */
}EgnIpFlowInitStaticBuf;

/*ENUM< ��ɾ��ԭ�� >*/
typedef enum
{
    EGN_IP_FLOW_DEL_BEGIN         = EGN_EN_INVALID,
    EGN_IP_FLOW_DEL_FIN_INSPECT   = 0x0,            /* ʶ����� */
    EGN_IP_FLOW_DEL_CHAIN_BREAK   = 0x1,            /* ���� */
    EGN_IP_FLOW_DEL_AGED          = 0x2,            /* �ϻ� */
    EGN_IP_FLOW_DEL_END,
    EGN_IP_FLOW_DEL_BOTTOM = EGN_EN_BUTT
}EGN_IP_FLOW_DEL_EN;

/*ENUM< ���ķ��� >*/
typedef enum
{
    EGN_IP_FLOW_DIRECT_BEGIN  = EGN_EN_INVALID,
    EGN_IP_FLOW_DIRECT_UP     = 0x0,              /* ���з����� */
    EGN_IP_FLOW_DIRECT_DOWN   = 0x1,              /* ���з����� */
    EGN_IP_FLOW_DIRECT_END,
    EGN_IP_FLOW_DIRECT_BOTTOM = EGN_EN_BUTT
}EGN_IP_FLOW_DIRECT_EN;

/*******************************************************************************
*    Func Name: EgnApiIpFlowGetNeededMemSize
*      Purpose: �������������ڴ档
*  Description: �������������ڴ棬��λ�ֽڡ�
*        Input: EGN_UINT32 ulSize:���Ĺ�ģ<1000~120000>
*        InOut: EGN_UINT32* pulMemSize:�����ڴ�Ĵ�С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ��API��EgnApiIpFlowTblInit֮ǰ���á���������Ĺ�ģulSizeֵ����Ҫ��
                EgnApiIpFlowTblInit��EgnApiGetNeededMemSize��_EgnInitCfgParam�е�ulFlowScale��ͬ��
*        Since: V200R002C02
*    Reference: EgnApiIpFlowTblInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiIpFlowGetNeededMemSize
(
    IN     EGN_UINT32   ulSize,
    INOUT  EGN_UINT32  *pulMemSize
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowTblInit
*      Purpose: ��ʼ������ҵ��ʵ����
*  Description: ��ʼ��������ڴ棬�������������
*        Input: EgnIpFlowInitStaticBuf* pstInitBuf:��ʼ���ڴ�Buffer<�ǿ�>
*               EgnIpFlowTblCfgParam pstCfgParam:�������ò���<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �����ȵ���EgnApiIpFlowGetNeededMemSize��������������ڴ��С��
                ��ǰ������ֻ֧�ֹ�����ǹ������������ֻ֧��32��ʵ����
*        Since: V200R002C02
*    Reference: EgnApiIpFlowGetNeededMemSize
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiIpFlowTblInit
(
    IN  EgnIpFlowInitStaticBuf *pstInitBuf,
    IN  EgnIpFlowTblCfgParam *pstCfgParam
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowTblDestroy
*      Purpose: ����ҵ��ʵ��ȥ��ʼ����
*  Description: ������������ʱ����ʵ��ȥ��ʼ����
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID���ޡ�
*      Caution: �ޡ�
*        Since: V200R002C02
*    Reference: N/A
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_VOID  EgnApiIpFlowTblDestroy
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowInspect
*      Purpose: ��IPԭʼ���ݰ��������ʶ��
*  Description: ͨ������IPԭʼ���ݰ������ݰ����ȡ������򼰰����кţ������ݰ�����ʶ�����ʶ������
*        Input: EGN_UINT8* pucPacket:IPԭʼ���ݰ�<�ǿ�>
*               EGN_UINT16 usPacketLen:���ݰ�����<21~65535>
*               EGN_UINT8 ucDirect:�����򣬶�Ӧ��EGN_IP_FLOW_DIRECT_EN<EGN_IP_FLOW_DIRECT_EN>
*               EGN_UINT32 ulSequence:������ţ�������Ȼ��������һ�����Ϊ1<����0>
*        InOut: EgnResult pstInspectResult:ʶ����<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: Ŀǰ��֧�ֶ���̻�����ʹ�ã���֧�ֶ��̡߳��ýӿڲ�֧��IPv6��
*        Since: V200R002C02
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiIpFlowInspect
(
    IN     EGN_CONST  EGN_UINT8    *pucPket,
    IN                EGN_UINT16    usPketlen,
    IN                EGN_UINT8     ucDirect,
    IN                EGN_UINT32    ulSequence,
    INOUT             EgnResult    *pstInspectResult
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowDelete
*      Purpose: ɾ��һ������
*  Description: ������������ʱ�������������Ԫ����Ϣ��ɾ��ԭ��ɾ��һ����
*        Input: EgnIpFlowFiveTuple* pstFiveTuple:��Ԫ��<�ǿ�>
*               EGN_UINT8 ucDelReason:ɾ��ԭ�򣬶�Ӧ��EGN_IP_FLOW_DEL_EN<EGN_IP_FLOW_DEL_EN>
*        InOut: EgnIpFlowTblCfgParam pstAuxData:��չ����<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ޡ�
*        Since: V200R002C02
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiIpFlowDelete
(
    IN  EGN_CONST  EgnIpFlowFiveTuple  *pstFiveTuple,
    IN             EGN_UINT8            ucDelReason,
    INOUT          EgnIpFlowAuxData    *pstAuxData
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowQueryTableInfo
*      Purpose: ��ѯ������Ϣ��
*  Description: ����������ʱ�����������Ϣ��
*        Input: NA
*        InOut: EgnIpFlowTblInfo* pstTblInfo:������Ϣ<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ޡ�
*        Since: V200R002C02
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32  EgnApiIpFlowQueryTableInfo
(
    INOUT  EgnIpFlowTblInfo  *pstTblInfo
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowGetHandle
*      Purpose: ��ȡʵ��handle��
*  Description: ������������ʱ����ȡʵ��handle��
*        Input: NA
*        InOut: NA
*       Output: EGN_VOID** ppvHandle:ʵ��handle<�ǿ�>
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ޡ�
*        Since: V200R002C02
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiIpFlowGetHandle
(
    OUT    EGN_VOID         **ppvHandle
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowStatGet
*      Purpose: ��ȡ����ͳ����Ϣ��
*  Description: ��ȡ����ͳ����Ϣ���û���Ҫ���ⲿ���������ڴ棬����ָ�롣
*        Input: NA
*        InOut: EgnIpFlowStatInfo* pstStatRslt:���ͳ������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ڿ�ʼ����ͳ��ǰ����ʹ��EgnApiIpFlowStatClear�����ǰ��ͳ����Ϣ��
*        Since: V200R002C02
*    Reference: EgnApiIpFlowStatClear
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiIpFlowStatGet
(
    INOUT EgnIpFlowStatInfo *pstStatRslt
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowStatClear
*      Purpose: �������ͳ����Ϣ��
*  Description: �������ͳ����Ϣ��
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �ڿ�ʼ����ͳ��ǰ����ʹ�øýӿ������ǰ��ͳ����Ϣ��
*        Since: V200R002C02
*    Reference: EgnApiIpFlowStatGet
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiIpFlowStatClear
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowMngInit
*      Purpose: ��ʼ�������߳�
*  Description: EGN�����̳߳�ʼ���ӿڣ�ѡ��ʹ��������ʱʹ�ø�API������ʹ��EgnApiMngInit��
                ���EGN�����Ҫʹ�õ�ϵͳ��Դ�����롢��ʼ���ȹ���������EgnApiIpFlowMngInitǰ��
                ��Ҫ�ȵ���EgnApiInitPubParam��ʼ��EGN�����ò���������ȱʡֵ������EGN��Ĭ������ֵ��
                ���Ĭ��ֵ������ҵ�����󣬿���ֱ�ӵ���EgnApiIpFlowMngInit��ʼ����
                ���Ĭ��ֵ��������ҵ�����󣬿��Ը���ҵ�������޸���Ӧ������ֵ��
                �ٵ���EgnApiIpFlowMngInit��ʼ��EGNģ��Ĺ����̡߳�
*        Input: EGN_UCHAR* pucGlobalBuffer:ȫ���ڴ��׵�ַ��32λƽ̨Ҫ��4�ֽڶ��룬64λƽ̨Ҫ��8�ֽڶ���<�ǿ�>
*               EGN_UINT32 ulBufferLen:ȫ���ڴ泤�ȣ�����Ϊ��<������>
*               EgnInitCfgParam* pstParam:������Ϣ<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: ������˵���⣬����APIӦ�ڳɹ���ʼ��EGN�����̳߳ɹ����ø�API֮����ܱ�ʹ�á�
*        Since: V200R002C02
*    Reference: EgnApiInitPubParam
*               EgnApiMngInit
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiIpFlowMngInit
(
   IN            EGN_UCHAR           *pucGlobalBuffer,
   IN            EGN_UINT32           ulBufferLen,
   IN  EGN_CONST EgnInitCfgParam     *pstParam
);

/*******************************************************************************
*    Func Name: EgnApiIpFlowMngDestroy
*      Purpose: �����߳�ȥ��ʼ����
*  Description: ��ɹ�����̡��߳�ϵͳ��Դ���ͷŵȹ�����
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ���ʧ�ܵĴ����룬������μ�EGN_RET_RESULT_EN��
*      Caution: �������ʵ��ȥ��ʼ��������ʶ��ҵ��ʵ��ȥ��ʼ��֮����С���
*        Since: V200R002C02
*    Reference: EgnApiIpFlowMngDestroy
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiIpFlowMngDestroy
(
    EGN_VOID
);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __EGN_API_IPF_ */

