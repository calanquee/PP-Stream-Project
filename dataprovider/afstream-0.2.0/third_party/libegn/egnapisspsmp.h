
/**@file  egnapisspsmp.h
  *   ϵͳ�����ܺ�ϵͳ�����ܶ���
  *******************************************************/

#ifndef __EGN_API_SSP_SMP_H__
#define __EGN_API_SSP_SMP_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/** ȫ�����ģ��� */
#define EGN_COMP_GLOBAL 0

/** �����ڴ����Ͷ��� */
#define EGN_MEM_DYNAMIC 0   /* ��̬�ڴ� */
#define EGN_MEM_STATIC  1   /* ��̬�ڴ� */

/** CPU�ͺŶ��� */
#ifdef EGN_CPU
#define EGN_X86      "X86"      /* X86 */
#define EGN_PPC750   "PPC750"   /* PPC750 */
#define EGN_MIPS64   "MIPS64"   /* MIPS64 */
#else
#define EGN_CPU ""              /* NONE */
#endif

/** EGN֧�ֵĲ���ϵͳ���� */
#ifdef EGN_OSVER
#define EGN_WIN32          "WIN32"              /* WIN32 */
#define EGN_SUSE_LNX       "SUSE_LINUX"         /* SUSE_LINUX */
#define EGN_WINDRIVER_LNX  "WINDRIVER_LINUX"    /* WINDRIVER_LINUX */
#define EGN_VXWS           "VXWORKS"            /* VXWORKS */
#define EGN_VXWS55         "VXWORKS55"          /* VXWORKS55 */
#else
#define EGN_OSVER          ""                   /* NONE */
#endif

/** EGN�û����� */
#ifdef EGN_PRODUCT
#define EGN_GEN     "GEN"   /* GEN */
#define EGN_UAP     "GGSN"  /* GGSN */
#define EGN_SCG     "SCG"   /* SCG */
#else
#define EGN_PRODUCT ""      /* NONE */
#endif

/** �ļ�����λ�ö��� */
#ifndef EGN_FILE_OP
#define  EGN_FILE_OP                /* �ļ�����λ�� */
#define  EGN_SEEK_SET    0          /* ���ļ�ͷ��ʼ */
#define  EGN_SEEK_CUR    1          /* ���ļ�ָ�뵱ǰλ�ÿ�ʼ */
#define  EGN_SEEK_END    2          /* ���ļ���β��ʼ */

#define  EgnFileHandle   EGN_VOID*  /* �����ļ���� */
#endif  /* EGN_FILE_OP */

/*ENUM< ���Կ��ƿ��� >*/
typedef enum
{
    EGN_DEBUG_BEGIN   = EGN_EN_INVALID,
    EGN_DEBUG_ON      = 0,     /* ������Ϣ���ش� */
    EGN_DEBUG_OFF     = 1,     /* ������Ϣ���عر� */
    EGN_DEBUG_END,

    EGN_DEBUG_BOTTOM  =  EGN_EN_BUTT
}EGN_DBG_SWTICH_EN;

/*ENUM< ������Ϣ������� >*/
typedef enum
{
    EGN_DEBUG_LEVEL_INVALID = EGN_EN_INVALID,
    EGN_DEBUG_PRINT_ALL     = 0,  /* ����δʹ�� */
    EGN_DEBUG_LEVEL_FATAL   = 1,  /* ���Fatal��Ϣ */
    EGN_DEBUG_LEVEL_ERR     = 2,  /* ���Fatal��Error��Ϣ */
    EGN_DEBUG_LEVEL_WARN    = 3,  /* ���Fatal��Error��Warning��Ϣ */
    EGN_DEBUG_LEVEL_INFO    = 4,  /* ���Fatal��Error��Warning��Info��Ϣ */
    EGN_DEBUG_LEVEL_END,

    EGN_DEBUG_LEVEL_BOTTOM    =  EGN_EN_BUTT
}EGN_DEBUG_LEVEL_EN;

/*ENUM< ������Ϣ������ƿ��� >*/
typedef enum
{
    EGN_DBGCMD_INVALID       = EGN_EN_INVALID,
    EGN_DBGCMD_ONOFF_SWITCH  = 1, /* enum EGN_DBG_SWTICH_EN */
    EGN_DBGCMD_LEVEL_SWITCH  = 2, /* enum EGN_DEBUG_LEVEL_EN */
    EGN_DBGCMD_END,

    EGN_DBGCMD_BOTTOM        = EGN_EN_BUTT
}EGN_DBG_CMD_EN;

/*ENUM< ģ��Ŷ��� >*/
typedef enum
{
    EGN_MODULE_INVALID  = EGN_EN_INVALID,
    EGN_MODULE_PARSER   = 0,    /* ����ģ�� */
    EGN_MODULE_REPORT   = 1,    /* ����ģ�� */
    EGN_MODULE_ENGINE   = 2,    /* ����ģ�� */
    EGN_MODULE_END,

    EGN_MODULE_BOTTOM     =  EGN_EN_BUTT
}EGN_MODULE_EN;

/*ENUM< ��ʱ��������ģʽ���� >*/
typedef enum    EGN_TIMER_MODE_TYPE_ENUM
{
    EGN_TIMER_MODE_TYPE_BEGIN  = EGN_EN_INVALID,
    EGN_TIMER_MODE_TYPE_NOLOOP = 0,             /* ��ѭ��ģʽ */
    EGN_TIMER_MODE_TYPE_LOOP   = 1,             /* ѭ��ģʽ */
    EGN_TIMER_MODE_TYPE_END,

    EGN_TIMER_MODE_TYPE_BOTTOM = EGN_EN_BUTT
}EGN_TIMER_MODE_TYPE_EN;

/*
 *#define EGN_TASK_ID  g_stCoreGlobalInfo.ulTaskId
*/

/*MACRO< TaskID >*/
#define EGN_TASK_ID 0

/*MACRO< ��־ID >*/
#define EGN_LOG_ID  (EGN_UINT32)((0xff000000 & __FILE_ID__) | __LINE__)

/*MACRO< ��־�ȼ� >*/
#define EGN_LOG_ERR 0

/*******************************************************************************
*    Func Name: PFEgnSspMemAlloc
*      Purpose: �����ڴ�
*  Description: �ڴ�����Ļص�������ΪulPIDģ����������ΪulMemType����СΪulSize���ڴ档
*        Input: EGN_UINT32 ulPID:ģ���<EGN_MODULE_EN>
*               EGN_UINT32 ulMemType:�ڴ������<EGN_DYNAMIC/EGN_STATIC>
*               EGN_UINT32 ulSize:�����ڴ�Ĵ�С����λ:�ֽ�<������>
*        InOut: NA
*       Output: NA
*       Return: HTTP_VOID�����ط����ڴ�ĵ�ַ
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnSspMemFree
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID * (*PFEgnSspMemAlloc)
(
    IN EGN_UINT32   ulPID,
    IN EGN_UINT32   ulMemType,
    IN EGN_UINT32   ulSize
);

/*******************************************************************************
*    Func Name: PFEgnSspMemFree
*      Purpose: �ͷ��ڴ�
*  Description: �ͷ��ڴ�Ļص��������ͷ�ģ���ΪulModId��ַΪpvMemAddr���ڴ档
*        Input: EGN_UINT32 ulModId:ģ���<EGN_MODULE_EN>
*               EGN_VOID *pvMemAddr:�ڴ�ĵ�ַ<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: �ޡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnSspMemAlloc
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnSspMemFree)
(
    IN EGN_UINT32   ulModId,
    IN EGN_VOID    *pvMemAddr
);

/*******************************************************************************
*    Func Name: PFEgnSspMemSet
*      Purpose: ����ڴ�Ļص�����
*  Description: ����ʼ��ַΪpvMemAddr������ΪulSize���ڴ棬����ַ�ucByte��
*        Input: EGN_VOID *pvMemAddr:�ڴ�ĵ�ַ<EGN_MODULE_EN>
*               EGN_UCHAR ucByte:�����ַ�<�ַ�ֵ>
*               EGN_UINT32 ulSize:���ĳ��ȣ���λ:�ֽ�<������>
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID�����ر�����Ŀ���ַ��
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID * (*PFEgnSspMemSet)
(
    IN EGN_VOID    *pvMemAddr,
    IN EGN_UCHAR    ucByte,
    IN EGN_UINT32   ulSize
);

/*******************************************************************************
*    Func Name: PFEgnSspMemCpy
*      Purpose: �ڴ渴�ƵĻص�����
*  Description: ����Դ��ַpvSrcAddr��ʼ���ڴ��г���ΪulSize�����ݣ����Ƶ���Ŀ���ַpvDestAddr��ʼ���ڴ��С�
*        Input: EGN_VOID *pvSrcAddr:Դ��ַ<�ǿ�>
*               EGN_UINT32 ulSize:���Ƶĳ��ȣ���λ:�ֽ�<������>
*        InOut: EGN_VOID *pvDestAddr:Ŀ���ַ<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��һ���ڴ�����ݸ��Ƶ���һ�������У���������ڴ棬ָ���ĳ��Ȳ��ܴ���Ŀ���ַ�ĳ��ȣ�������ڴ�Խ�硣
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID *(*PFEgnSspMemCpy)
(
    INOUT EGN_VOID     *pvDestAddr,
    IN    EGN_VOID     *pvSrcAddr,
    IN    EGN_UINT32   ulSize
);

/*******************************************************************************
*    Func Name: PFEgnSspMemCmp
*      Purpose: �ڴ�ȽϵĻص�����
*  Description: ����Դ��ַpvSrcAddr��ʼ���ڴ����Ŀ���ַpvDestAddr��ʼ���ڴ��г���ΪulSize�����ݱȽϡ�
*        Input: EGN_VOID *pvDestAddr:Ŀ���ַ<�ǿ�>
*               EGN_VOID *pvSrcAddr:Դ��ַ<�ǿ�>
*               EGN_UINT32 ulSize:�Ƚϵĳ��ȣ���λ:�ֽ�<������>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32��0��ʾ��ȣ������ʾ���ȡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32   (*PFEgnSspMemCmp)
(
    IN  EGN_VOID    *pvDestAddr,
    IN  EGN_VOID    *pvSrcAddr,
    IN  EGN_UINT32   ulSize
);

/*******************************************************************************
*    Func Name: PFEgnSspStrLen
*      Purpose: �����ַ����ĳ��ȵĻص�������
*  Description: ���������ַ���pcStr�ĳ��ȣ�һֱ���㵽�ַ���������\\0Ϊֹ��������\\0��
*        Input: EGN_CHAR *pcStr:ָ���ַ�����ָ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32�������ַ����ĳ��ȡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32   (*PFEgnSspStrLen)
(
    IN  EGN_CHAR    *pcStr
);

/*******************************************************************************
*    Func Name: PFEgnSspStrNCmp
*      Purpose: �ַ����ȽϵĻص�������
*  Description: �Ƚ�Ŀ���ַ���pcStr1��Դ�ַ���pcStr2ǰulCount���ֽ��Ƿ���ͬ��
*        Input: EGN_CHAR *pcStr1:Ŀ���ַ���<�ǿ�>
*               EGN_CHAR *pcStr2:Դ�ַ���<�ǿ�>
*               EGN_UINT32 ulCount:�Ƚϵĳ��ȣ���λ���ֽ�<������>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32��0Ϊ�ַ�����ȣ���������ֵΪ�ַ�������ȡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32   (*PFEgnSspStrNCmp)
(
    IN  EGN_CONST   EGN_CHAR    *pcStr1,
    IN  EGN_CONST   EGN_CHAR    *pcStr2,
    IN              EGN_UINT32   ulCnt
);

/*******************************************************************************
*    Func Name: PFEgnAtomicAdd
*      Purpose: ԭ�ӼӲ�����
*  Description: �������ulAddEnd��ָ�򱻼�����ָ��pulSummand���������pulSummandָ����ڴ��С�
*        Input: EGN_UINT32 ulAddEnd:����<������>
*        InOut: EGN_UINT32 *pulSummand:������ִ�к�Ϊ��<�ǿ�>
*       Output: NA
*       Return: �ޡ�
*      Caution: �ڶ�pulSummandָ����ڴ����Ӳ�����ʱ��Ҫ��֤��ԭ�Ӳ�����
*        Since: V100R001C03
*    Reference: PFEgnAtomicSub
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnAtomicAdd)
(
    IN      EGN_UINT32  ulAddEnd,
    INOUT   EGN_UINT32 *pulSummand
);

/*******************************************************************************
*    Func Name: PFEgnAtomicSub
*      Purpose: ԭ�Ӽ�������
*  Description: �������ulSubtrahend��ָ�򱻼�����ָ��pulMinuend���������pulMinuendָ����ڴ��С�
*        Input: EGN_UINT32 ulSubtrahend:����<������>
*        InOut: EGN_UINT32 *pulMinuend:��������ִ�к�Ϊ��<�ǿ�>
*       Output: NA
*       Return: �ޡ�
*      Caution: �ڶ�pulMinuendָ����ڴ�����������ʱ��Ҫ��֤��ԭ�Ӳ�����
*        Since: V100R001C03
*    Reference: PFEgnAtomicAdd
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnAtomicSub)
(
    IN      EGN_UINT32  ulSubtrahend,
    INOUT   EGN_UINT32 *pulMinuend
);

/*******************************************************************************
*    Func Name: PFEgnFeedWatchdog
*      Purpose: ��λ���Ź���
*  Description: null
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: �ޡ�
*      Caution: �ޡ�
*        Since: V100R001C03
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnFeedWatchdog)
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: PFEgnFuncPeerSynAdd
*      Purpose: ��������Ϣͬ���ӿڡ�
*  Description: ����Ҫ֧�ַǶԳ�ʶ�𳡾�ʱ����Ҫ���øýӿ�ʵ�ֲ�ͬ�豸��Ĺ�������ͬ����
*        Input: EgnPeerSet pstPeerSet:��ͬ���Ĺ���������Ϣ<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: �ޡ�
*      Caution: ��ͬ������ֻ���ڶ����ݰ����ݽ��н�����ӹ������ʱ��ŵ��ã����ڿ��ٹ��������á�
*        Since: V300R006C00
*    Reference: N/A
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnFuncPeerSynAdd)
(
    IN  EgnPeerSet    *pstPeerSet
);

/*******************************************************************************
*    Func Name: PFEgnIsInspectTimeOut
*      Purpose: APIʶ��ʱ��������
*  Description: �Ƿ�ʱ�ɲ�Ʒ�����жϣ�ע���ʱ������������������������ֻ֧��TD_RNC��Ʒ��
*        Input: EGN_UINT16 usThreadID:ʵ���߳�ID<0~65535>
*        InOut: NA
*       Output: NA
*       Return: EGN_BOOL��ʶ���Ƿ�ʱ��
                1��ʾʶ��ʱ���Ѿ���ʱ����Ҫ���������ض�������EGN_RET_INSPECT_TIME_OUT��EGN�������̽��˳�������һ���쳣��������
                0��ʾ�����жϣ����Լ���ʶ��
*      Caution: �ޡ�
*        Since: V200R002C02
*    Reference: N/A
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_BOOL (*PFEgnIsInspectTimeOut)
(
    IN  EGN_UINT16  usThreadID  /* ʵ���߳�ID */
);

/*******************************************************************************
*    Func Name: PFEgnSspFileOpen
*      Purpose: ���ļ���
*  Description: ��ucModeģʽ���ļ�����ΪpucFileName���ļ���
*        Input: EGN_UCHAR *pucFileName:�ļ�����<�ǿ�>
*               EGN_CHAR ucMode:ģʽ���μ�fopen������mode����<fopen������mode����>
*        InOut: NA
*       Output: NA
*       Return: EgnFileHandle������0��ʾʧ�ܣ����طǿգ���ʾ�������ļ������
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EgnFileHandle   (*PFEgnSspFileOpen)
(
    IN  EGN_CONST EGN_UCHAR   *pucFileName,
    IN            EGN_CHAR    *pcMode
);

/*******************************************************************************
*    Func Name: PFEgnSspFileSeek
*      Purpose: �����ļ����hFd����λ�ļ���д��λ��Ϊ����ʼλ��ulWhence��ʼƫ��ilOffset���ֽڡ�
*  Description: null
*        Input: EgnFileHandle hFd:�ļ����<�ǿ�>
*               EGN_INT32 ilOffset:ƫ�Ƶľ��룬���lWhence����<����ֵ>
*               EGN_UINT32 ulWhence:��λ����ʼλ��<�μ�EGN_FILE_OP>
*        InOut: NA
*       Output: NA
*       Return: EGN_INT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_INT32   (*PFEgnSspFileSeek)
(
    IN  EgnFileHandle  hFd,
    IN  EGN_INT32      ilOffset,
    IN  EGN_UINT32     ulWhence
);

/*******************************************************************************
*    Func Name: PFEgnSspFileRead
*      Purpose: ��ȡ�ļ����ݵ�ָ�����ڴ�ռ䡣
*  Description: ��ȡ�ļ�hFd��ulCount�ֽ��������ݵ�pBufָ����ڴ�顣
*        Input: EgnFileHandle hFd:�ļ����<�ǿ�>
*               EGN_VOID *pBuf:������ڴ�����<�ǿ�>
*               EGN_UINT32 ulCount:������ֽ���<������>
*        InOut: NA
*       Output: NA
*       Return: EGN_INT32������ֵ>=0����ʾʵ�ʶ�ȡ���ֽڴ�С��Ŀ��������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_INT32   (*PFEgnSspFileRead)
(
    IN  EgnFileHandle    hFd,
    IN  EGN_VOID        *pBuf,
    IN  EGN_UINT32       ulCnt
);

/*******************************************************************************
*    Func Name: PFEgnSspFileClose
*      Purpose: �ر��ļ������
*  Description: �ر��Ѿ��򿪵��ļ�hFd��
*        Input: EgnFileHandle hFd:�ļ����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_INT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_INT32   (*PFEgnSspFileClose)
(
    IN  EgnFileHandle      hFd
);

/*******************************************************************************
*    Func Name: PFEgnFuncTimeout
*      Purpose: ��ʱ����ʱ��������
*  Description: ��ʱ����ʱ�����������볬ʱ�Ķ�ʱ�����ulTmSn�Ͷ�ʱ������ulTmName��
                ����ʱ����ʱʱ��ִ�й������ϻ���֪ʶ��������
*        Input: EGN_UINT32 ulTmSn:��ʱ�Ķ�ʱ�����<��ʱ����ţ�0~n>
*               EGN_UINT32 ulTmName:��ʱ�Ķ�ʱ����<�ص�������ע>
*        InOut: NA
*       Output: NA
*       Return: �ޡ�
*      Caution:
*        Since: V100R001C01
*    Reference: PFEgnTimerGrpCreate
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnFuncTimeout)
(
    IN  EGN_UINT32      ulTmSn,  /* ��Զ�ʱ�������The serial number ofthe relative timer */
    IN  EGN_UINT32      ulTmName /* ��ʱ������ The timer name */
);

/*******************************************************************************
*    Func Name: PFEgnTimerGrpCreate
*      Purpose: ������ʱ���顣
*  Description: ��������Ķ�ʱ���鳬ʱ������pfTimeout�Ͷ�ʱ������ulMaxTimerNums�����Ķ�ʱ���飬
                ��������Ķ�ʱ������ppTimerGrp��
*        Input: EGN_UINT32 ulMaxTimerNums:�����Ķ�ʱ����Ķ�ʱ������<1~32>
*               PFEgnFuncTimeout pfTimeout:�����Ķ�ʱ���鳬ʱ������<�ǿ�>
*        InOut: NA
*       Output: EGN_VOID** ppTimerGrp:�����Ķ�ʱ������<�ǿ�>
*       Return: EGN_UINT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnTimerGrpDestroy
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32  (*PFEgnTimerGrpCreate)
(
    OUT EGN_VOID          **ppvTimerGrp,
    IN  EGN_UINT32          ulMaxTimerNums,
    IN  PFEgnFuncTimeout    pfTimeout
);

/*******************************************************************************
*    Func Name: PFEgnTimerGrpStart
*      Purpose: ������ʱ���顣
*  Description: ��������Ҫ�����Ķ�ʱ������ppTimerGrp�����ulTmSn������ulTmName������ʱ���飬
                �����ö�ʱ����ĳ�ʱʱ��ulTmLength������ģʽucTmMode��
*        Input: EGN_VOID* ppTimerGrp:Ҫ�����Ķ�ʱ������<�ǿ�>
*               EGN_UINT32 ulTmSn:������ʱ����Ķ�ʱ�����<0~31>
*               EGN_UINT32 ulTmLength:��ʱ����ʱʱ������λΪms<100~60000>
*               EGN_UINT32 ulTmName:������ʱ����Ķ�ʱ������<�ص�������ע>
*               EGN_UINT32 ucTmMode:��ʱ��������ģʽ<EGN_TIMER_MODE_TYPE_EN>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnTimerGrpStop
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32  (*PFEgnTimerGrpStart)
(
    IN  EGN_VOID           *pvTimerGrp,
    IN  EGN_UINT32          ulTmSn,
    IN  EGN_UINT32          ulTmLength,
    IN  EGN_UINT32          ulTmName,
    IN  EGN_UCHAR           ucTmMode
);

/*******************************************************************************
*    Func Name: PFEgnTimerGrpStop
*      Purpose: ֹͣ��ʱ���顣
*  Description: ����Ҫֹͣ�Ķ�ʱ������ppTimerGrp�Ͷ�ʱ�����ulTmSn��ֹͣ��ʱ���顣
*        Input: EGN_VOID* ppTimerGrp:Ҫֹͣ�Ķ�ʱ������<�ǿ�>
*               EGN_UINT32 ulTmSn:ֹͣ�Ķ�ʱ����Ķ�ʱ�����<0~31>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnTimerGrpStart
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32  (*PFEgnTimerGrpStop)
(
    IN  EGN_VOID           *pvTimerGrp,
    IN  EGN_UINT32          ulTmSn
);

/*******************************************************************************
*    Func Name: PFEgnTimerGrpDestroy
*      Purpose: �ͷŶ�ʱ���顣
*  Description: ����Ҫ�ͷŵĶ�ʱ������ppTimerGrp���ͷŶ�ʱ���顣
*        Input: EGN_VOID** ppTimerGrp:Ҫ�ͷŵĶ�ʱ������<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnTimerGrpCreate
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32  (*PFEgnTimerGrpDestroy)
(
    IN  EGN_VOID          **ppvTimerGrp
);

/*******************************************************************************
*    Func Name: PFEgnSspFileTell
*      Purpose: ��ȡ�ļ�ָ�뵱ǰλ�á�
*  Description: �����ļ��������ȡ�ļ�ָ�뵱ǰλ�á�
*        Input: EGN_INT32 hFd:�ļ����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_INT32�������ļ�ָ�뵱ǰλ�á�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_INT32   (*PFEgnSspFileTell)
(
    IN  EgnFileHandle       hFd
);

/*******************************************************************************
*    Func Name: PFEgnSspFileRewind
*      Purpose: �ƶ��ļ�ָ�뵽�ļ��ס�
*  Description: �����ļ�������ƶ��ļ�ָ�뵽�ļ��ס�
*        Input: EGN_INT32 hFd:�ļ����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: �ޡ�
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID    (*PFEgnSspFileRewind)
(
    IN  EgnFileHandle       hFd
);

/*******************************************************************************
*    Func Name: PFEgnFuncAssert
*      Purpose: ���������Ϣ��
*  Description: ��������Ļص��������û����ýӿ�EgnApiRegAssertFn�������Իص�����PFEgnFuncAssertע��������
                ���ͨ�����ûص�����PFEgnFuncAssert���������Ķ�ջ������Ϣ������û���
*        Input: EGN_BOOL bCond:���Բ���<EGN_FALSE/EGN_TRUE>
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID
*      Caution: �ޡ�
*        Since: V100R001C03
*    Reference: EgnApiRegAssertFn
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnFuncAssert)
(
    IN    EGN_BOOL bCond
);

/*******************************************************************************
*    Func Name: PFEgnFuncLogSend
*      Purpose: �����־��Ϣ��
*  Description: ��־����Ļص��������û����ýӿ�EgnApiRegLogSendFn������־��Ϣ����ص�����
                PFEgnFuncLogSendע�����������ͨ�����ûص�����PFEgnFuncLogSend������־��Ϣ������û���
*        Input: EGN_UINT32 ulTaskId:TaskID����ϵͳ��ʼ��ʱ���õ�egnģ��<EGN_TASK_ID>
*               EGN_UINT32 ulLogId:�������ڲ�Ψһ��ʶ��־��ID��ʹ��ģ��ź��кŵ����<EGN_LOG_ID>
*               EGN_UINT32 ulLogLevel:��־�ĵȼ�����δʹ�ã�Ԥ��<EGN_LOG_ERR>
*               EGN_INT8 pcFormat:��ʽ�����������<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: �ޡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: EgnApiRegLogSendFn
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnFuncLogSend)
(
    IN  EGN_UINT32  ulTaskId,
    IN  EGN_UINT32  ulLogId,
    IN  EGN_UINT32  ulLogLevel,
    IN  EGN_INT8   *pcFormat,
    ...
);

/*******************************************************************************
*    Func Name: PFEgnFuncDbgPrint
*      Purpose: ���������Ϣ��
*  Description: ������Ϣ����Ļص��������û����ýӿ�EgnApiRegDebugPrintFn����������Ϣ����ص�����
                PFEgnFuncDbgPrintע�����������ͨ�����ûص�����PFEgnFuncDbgPrint����������Ϣ������û���
*        Input: EGN_UINT32 ulTaskId:���û��ڳ�ʼ��ʱע��<EGN_TASK_ID>
*               EGN_UINT32 ulDebugPrintLevel:���Եȼ�<EGN_DEBUG_LEVEL_EN>
*               EGN_VOID pvDbgPara:���Բ���<�ǿ�>
*               EGN_INT8 format:��ʽ�����������<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: �ޡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: EgnApiRegDebugPrintFn
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnFuncDbgPrint)
(
    IN  EGN_UINT32   ulTaskId,
    IN  EGN_UINT32   ulDebugPrintLevel,
    IN  EGN_VOID    *pvDbgPara,
    IN  EGN_INT8    *pcFormat,...
);

/*******************************************************************************
*    Func Name: PFEgnFuncStatSend
*      Purpose: ���ͳ����Ϣ��
*  Description: ͳ����Ϣ����Ļص��������û����ýӿ�EgnApiRegStatSendFn����ͳ����Ϣ����ص�����
                PFEgnFuncStatSendע�����������ͨ�����ûص�����PFEgnFuncStatSend����ͳ����Ϣ������û���
*        Input: EGN_UINT32 ulStatUnit:ͳ�Ƶ�����<EGN_STAT_UNIT_EN>
*               EGN_UINT32 ulStatEntity:ͳ�Ƶ�Э������<EGN_STAT_ENTITY_EN>
*               EGN_UINT32 ulOperateType:ͳ�Ʋ���<EGN_OPER_ADD/EGN_OPER_DEL/EGN_OPER_SET>
*               EGN_UINT32 ulValue:����<������>
*               EGN_UCHAR pucParams:����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: �ޡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: EgnApiRegStatSendFn
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnFuncStatSend)
(
    IN EGN_UINT32 ulStatUnit,
    IN EGN_UINT32 ulStatEntity,
    IN EGN_UINT32 ulOperateType,
    IN EGN_UINT32 ulValue,
    IN EGN_UCHAR  *pucParams
);

/*******************************************************************************
*    Func Name: PFEgnFuncTraceSend
*      Purpose: ���������Ϣ��
*  Description: ������Ϣ����Ļص��������û����ýӿ�EgnApiRegTraceSendFn����������Ϣ����ص�����
                PFEgnFuncTraceSendע�����������ͨ�����ûص�����PFEgnFuncTraceSend����������Ϣ������û���
*        Input: EGN_UINT32 ulTraceObjectType:ģ���<EGN_TASK_ID>
*               EGN_UINT32 ulTraceObj:���ٶ���<Ԥ��>
*               EGN_UINT32 ulMsgLength:��Ϣ����<������>
*               EGN_UCHAR pucTraceMsg:��Ϣ����<�ǿ�>
*               EGN_VOID pvTraceHandle:���پ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: �ޡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: EgnApiRegTraceSendFn
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnFuncTraceSend)
(
    IN EGN_UINT32  ulTraceObjectType,
    IN EGN_UINT32  ulTraceObj,
    IN EGN_UINT32  ulMsgLength,
    IN EGN_UCHAR  *pucTraceMsg,
    IN EGN_VOID   *pvTraceHandle
);

/*******************************************************************************
*    Func Name: PFEgnRWLockCreate
*      Purpose: ������д����
*  Description: ������д���Ļص�������������������pucName�����ľ��ָ��ppRWLockHandle����һ����д����
*        Input: EGN_UCHAR pucName:��������<�ǿ�>
*               EGN_VOID** ppRWLockHandle:���ľ��ָ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: ��ͬ�̣߳������������������һ����Ҫ�󷵻�ͬһ��handle��
*        Since: V100R001C01
*    Reference: PFEgnRWLockDelete
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnRWLockCreate)
(
    IN EGN_CONST    EGN_UCHAR *pucName,
    INOUT           EGN_VOID** ppRWLockHandle
);

/*******************************************************************************
*    Func Name: PFEgnRWLock
*      Purpose: �Ӷ�д���ص�������
*  Description: �Ӷ�д���ص��������������ľ��pRWLockHandle������
*        Input: const pRWLockHandle:EGN_VOID�����ľ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnRWUnlock
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnRWLock)
(
    IN EGN_CONST EGN_VOID   *pRWLockHandle
);

/*******************************************************************************
*    Func Name: PFEgnRWUnlock
*      Purpose: ���д���ص�������
*  Description: ���д���ص��������������ľ��pRWLockHandle������
*        Input: const pRWLockHandle:EGN_VOID�����ľ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnRWLock
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnRWUnlock)
(
    IN EGN_CONST EGN_VOID* pRWLockHandle
);

/*******************************************************************************
*    Func Name: PFEgnRWLockDelete
*      Purpose: ɾ����д���ص�������
*  Description: ����������������pucName�����ľ��ָ��ppRWLockHandleɾ������
*        Input: EGN_UCHAR pucName:��������<�ǿ�>
*               const ppRWLockHandle:EGN_VOID�����ľ��ָ��<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32������EGN_RET_SUCCESS��ʾ�ɹ���������ʾʧ�ܡ�
*      Caution: �ޡ�
*        Since: V100R001C01
*    Reference: PFEgnRWLockCreate
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnRWLockDelete)
(
    IN      EGN_CONST   EGN_UCHAR *pucName,
    INOUT               EGN_VOID **ppRWLockHandle
);

/*******************************************************************************
*    Func Name: PFEgnSspMemCreateBuf
*      Purpose: ������ʽ�ڴ������
*  Description: ������ʽ�ڴ�������ص�����
*        Input: NA
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID���������ڴ��������
*      Caution:
*        Since: V300R005C01
*    Reference: PFEgnMmCreateBufMem
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID * (*PFEgnSspMemCreateBuf)
(
    EGN_VOID
);

/*******************************************************************************
*    Func Name: PFEgnSspMemReleaseBuf
*      Purpose: �ͷ��ڴ���ƿ�
*  Description: �ͷ��ڴ���ƿ�ص�����
*        Input: NA
*        InOut: EGN_VOID *pvBufMemCp:���ͷŵĵ��ڴ���ƿ�<�ǿ�>
*               EGN_UINT32 *pulReleaseSize:�ͷŵ��ڴ���С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution:
*        Since: V300R005C01
*    Reference: PFEgnSspMemReleaseBuf
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnSspMemReleaseBuf)
(
    INOUT EGN_VOID      *pvBufMemCp,
    OUT   EGN_UINT32    *pulReleaseSize
);

/*******************************************************************************
*    Func Name: PFEgnSspMemResetBuf
*      Purpose: ��λ�ڴ���ƿ�
*  Description: ��λ�ڴ���ƿ�ص�����
*        Input: NA
*        InOut: EGN_VOID *pvBufMemCp:����λ�ĵ��ڴ���ƿ�<�ǿ�>
*               EGN_UINT32 *pulResetSize:��λ���ڴ���С<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution:
*        Since: V300R005C01
*    Reference: PFEgnSspMemResetBuf
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
 typedef EGN_UINT32 (*PFEgnSspMemResetBuf)
(
    INOUT EGN_VOID      *pvBufMemCp,
    OUT   EGN_UINT32    *pulResetSize
);

/*******************************************************************************
*    Func Name: PFEgnSspMemBufAlloc
*      Purpose: ����Memcp�Ĺ���ṹ
*  Description: ����Memcp�Ĺ���ṹ�ص�����
*        Input: EGN_VOID *pBufCp:�ڴ���ƿ�<�ǿ�>
*               EGN_UINT32 ulSize:��ʼ��С<������>
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID���ɹ�����ʧ�ܵĴ����롣
*      Caution:
*        Since: V300R005C01
*    Reference: PFEgnSspMemBufAlloc
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID * (*PFEgnSspMemBufAlloc)
(
   IN  EGN_VOID    *pvhandle,
   IN  EGN_UINT32   ulSize
);

/*******************************************************************************
*    Func Name: PFEgnSspMemBufFree
*      Purpose: �ͷ��ڴ�
*  Description: �ͷ�Buffer�ڴ棬ʵ���ϲ�û���ͷţ����ṩ�ӿ�
*        Input: EGN_VOID *pvDummy:��Ҫ�ͷŵĵ�ַ<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_VOID���ɹ�����ʧ�ܵĴ����롣
*      Caution:
*        Since: V300R005C01
*    Reference: PFEgnSspMemBufFree
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_VOID (*PFEgnSspMemBufFree)
(
   IN  EGN_VOID *pvDummy
);

/*******************************************************************************
*    Func Name: PFEgnSspMemBufGetSize
*      Purpose: ��ѯָ���ڴ���ƿ�������ڴ����ֽ���
*  Description: ��ѯָ���ڴ���ƿ�������ڴ����ֽ����Ļص�����
*        Input: EGN_VOID *pBufCp:�ڴ���ƿ�<�ǿ�>
*        InOut: NA
*       Output: EGN_UINT32 *pulSize:�Ѿ�������ڴ�����(��λ��Byte)<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution:
*        Since: V300R005C01
*    Reference: PFEgnSspMemBufGetSize
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnSspMemBufGetSize)
(
   IN  EGN_VOID    *pvhandle,
   OUT EGN_UINT32  *pulSize
);

 /*******************************************************************************
 *    Func Name: PFEgnAddPeerList
 *      Purpose: ��ӹ����·��ӿ�
 *  Description: �·�������Ϣ��ӵĽӿ�
 *        Input: EgnPeerListTupleInfo *pstTuple : ��Ԫ����Ϣ��tunnelID�ϼ�<�ǿ�>
 *               EgnProtoResultInfo   *pstProtRetInfo : ʶ��������Ҫ�������ࡢС�ࡢӦ�÷����Լ����ط��ࡣ<�ǿ�>
 *               EGN_VOID             *pvFlowHandle : ���Ự��Ϣ��NGE�ĻỰָ��ͻỰ�汾��<�ǿ�>
 *               EGN_UINT16            usTimeOut : �ϻ�ʱ�䣬��λ��<��Ϊȫf����ʾ����Ҫ�ϻ���>
 *        InOut: NA
 *       Output: NA
 *       Return: EGN_VOID
 *      Caution:
 *        Since: V300R006C00
 *    Reference: PFEgnAddPeerList
 *------------------------------------------------------------------------------
 *  Modification History
 *  DATE         NAME                    DESCRIPTION
 *------------------------------------------------------------------------------
 *
*******************************************************************************/
 typedef EGN_VOID  (*PFEgnAddPeerList)
(
     IN EGN_CONST EgnPeerListTupleInfo *pstTuple,
     IN           EgnProtoResultInfo   *pstProtRetInfo,
     IN           EGN_VOID             *pvFlowHandle,
     IN           EGN_UINT16            usTimeOut
);

 /*******************************************************************************
 *    Func Name: PFEgnDelPeerList
 *      Purpose:  ɾ��������Ϣ�·��ӿ�
 *  Description: ��ucIPNum��ucPortNum��ֵ��Ϊ0ʱ��ɾ������Э��IDΪulProtID�Ĺ������
 *               ��ucIPNum��ucPortNum������0ʱ��ɾ��Э��IDΪulProtID��������Ԫ���е�ip�Ͷ˿��ڷֱ���б��еı��
 *               ��ucIPNum��ucPortNum����һ�����0ʱ��ɾ��Э��IDΪulProtID��������Ԫ���ж�Ӧip��˿����б��еı��
 *        Input: EGN_UINT32     ulProtID    : ��ɾ���Ĺ�����Ϣ�ķ�������
                 EGN_UINT32     ulTunnelID  : Tunnel ID
                 EGN_UINT8      ucPortNum   : �˿���������<��Ϊ0��ɾ��ʱ����ע�˿�����>
                 EgnPortCond   *pstPortList : �˿������б�<��ucPortNumΪ0��ɾ��ʱ����ע�˿�������>
                 EGN_UINT8      ucIPNum     : IP��������<��Ϊ0��ɾ��ʱ����עIP������>
                 EgnIpAddrCond *pstIPAddrList : IP�����б�<��ucIPNumΪ0��ɾ��ʱ����עIP������>
 *        InOut: NA
 *       Output: NA
 *       Return: EGN_VOID
 *      Caution:
 *        Since: V300R006C00
 *    Reference: PFEgnDelPeerList
 *------------------------------------------------------------------------------
 *  Modification History
 *  DATE         NAME                    DESCRIPTION
 *------------------------------------------------------------------------------
 *
*******************************************************************************/
 typedef EGN_VOID  (*PFEgnDelPeerList)
(
    IN           EGN_UINT32   ulProtoID,
    IN           EGN_UINT32   ulTunnelID,
    IN           EGN_UINT8    ucPortNum,
    IN EGN_CONST EgnPortCond *pstPortList,
    IN           EGN_UINT8    ucIPNum,
    IN EGN_CONST EgnIpAddrCond   *pstIPAddrList
);

/* ��ҪNGFW��Ʒע��Ļص����� */

/*******************************************************************************
 *    Func Name: PFEgnHAAddPattern
 *      Purpose: ���ģʽ����Ӳ��״̬����
 *  Description: ���ģʽ����Ӳ��״̬����
 *        Input: EGN_UINT8      ucHAPattSetID : ��ǰģʽ��Ҫ��ӵ���Ӳ��ģʽ����ID
                 EGN_UINT8      ucRuleLibID   : ��ǰģʽ�����ڵ�֪ʶ��ID
                 EGN_UCHAR     *pucPattern    : ��ǰҪ��ӵ�ģʽ������<�ǿ�>
                 EGN_UINT16     usPatternLen  : ģʽ������
                 EGN_UINT32     ulPatternID   : ģʽ��ID
                 EgnPatternAtt *pstPatternAtt : ģʽ������<�ǿ�>
 *        InOut: NA
 *       Output: NA
 *       Return: EGN_VOID
 *      Caution:
 *        Since: V300R006C00
 *    Reference:
 *------------------------------------------------------------------------------
 *  Modification History
 *  DATE         NAME                    DESCRIPTION
 *------------------------------------------------------------------------------
 *
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnHAAddPattern)
(
    IN      EGN_UINT8       ucHAPattSetID,      /* ��ǰģʽ��Ҫ��ӵ���Ӳ��ģʽ����ID */
    IN      EGN_UINT8       ucRuleLibID,        /* ��ǰģʽ�����ڵ�֪ʶ��ID */
    IN      EGN_UCHAR      *pucPattern,         /* ��ǰҪ��ӵ�ģʽ������ */
    IN      EGN_UINT16      usPatternLen,       /* ģʽ������ */
    IN      EGN_UINT32      ulPatternID,        /* ģʽ��ID */
    IN      EgnPatternAtt  *pstPatternAtt       /* ģʽ������ */
);

/*******************************************************************************
 *    Func Name: PFEgnHADeletePatternAll
 *      Purpose: ɾ��ָ��ģʽ�����е�����ģʽ��
 *  Description: ɾ��ָ��ģʽ�����е�����ģʽ��
 *        Input: EGN_UINT8      ucHAPattSetID : ��ǰģʽ��Ҫ��ӵ���Ӳ��ģʽ����ID
                 EGN_UINT8      ucRuleLibID   : ��ǰģʽ�����ڵ�֪ʶ��ID
 *        InOut: NA
 *       Output: NA
 *       Return: EGN_VOID
 *      Caution:
 *        Since: V300R006C00
 *    Reference:
 *------------------------------------------------------------------------------
 *  Modification History
 *  DATE         NAME                    DESCRIPTION
 *------------------------------------------------------------------------------
 *
*******************************************************************************/
typedef EGN_UINT32 (*PFEgnHADeletePatternAll)
(
    IN      EGN_UINT8       ucHAPattSetID,      /* ��ǰģʽ��Ҫ��ӵ���Ӳ��ģʽ����ID */
    IN      EGN_UINT8       ucRuleLibID         /* ��ǰģʽ�����ڵ�֪ʶ��ID */
);

/*STRUCT< ϵͳ�����ܵĻص��������� >*/
typedef struct _EgnSspFunc
{
    EGN_UINT32              ulMagic;            /* SSP CBack magic,�û������ע,�벻Ҫ�޸� */
#ifdef EGN_64
    EGN_UINT8               aucReserved[4];     /* 64λ���뱣���ֽ� */
#endif
    PFEgnSspMemAlloc        pfMemAlloc;         /* �ڴ����ص�������pfMemAlloc��pfMemFree��������Ҫô��ע�ᣬҪô����ע�� ��ѡ */
    PFEgnSspMemFree         pfMemFree;          /* �ڴ��ͷŻص�������pfMemAlloc��pfMemFree��������Ҫô��ע�ᣬҪô����ע�� ��ѡ */
    PFEgnSspMemCreateBuf    pfMemCreateBuf;     /* �����ڴ���ƿ麯�� AR����ע�� */
    PFEgnSspMemReleaseBuf   pfMemReleaseBuf;    /* �ͷ��ڴ���ƿ麯�� AR����ע�� */
    PFEgnSspMemResetBuf     pfMemResetBuf;      /* ��λ�ڴ���ƿ麯�� AR����ע�� */
    PFEgnSspMemBufAlloc     pfMemBufAlloc;      /* ����Memcp�Ĺ���ṹ���� AR����ע�� */
    PFEgnSspMemBufFree      pfMemBufFree;       /* �ͷ�Buffer�ڴ溯�� AR����ע�� */
    PFEgnSspMemBufGetSize   pfMemBufGetSize;    /* ��ѯ�����ڴ����� AR����ע�� */
    PFEgnSspMemSet          pfMemSet;           /* �ڴ�memset�ص����� ���� */
    PFEgnSspMemCpy          pfMemCpy;           /* �ڴ渴�ƻص����� ���� */
    PFEgnSspMemCmp          pfMemCmp;           /* �ڴ�Ƚϻص����� ���� */
    PFEgnSspStrLen          pfStrLen;           /* �ַ������ȼ���ص����� ���� */
    PFEgnSspFileOpen        pfFopen;            /* ���ļ��ص����� ��ѡ */
    PFEgnSspFileSeek        pfFseek;            /* �ƶ��ļ�ָ��ص����� ��ѡ */
    PFEgnSspFileRead        pfFread;            /* ��ȡ�ļ��ص����� ��ѡ */
    PFEgnSspFileTell        pfFtell;            /* ��ȡ�ļ�ָ��λ�ûص����� ��ѡ */
    PFEgnSspFileClose       pfFclose;           /* �ر��ļ��ص����� ��ѡ */
    PFEgnTimerGrpCreate     pfTimerGrpCreate;   /* ������ʱ����ص����� ���� */
    PFEgnTimerGrpStart      pfTimerGrpStart;    /* ������ʱ���ص����� ���� */
    PFEgnTimerGrpStop       pfTimerGrpStop;     /* ֹͣ��ʱ���ص����� ���� */
    PFEgnTimerGrpDestroy    pfTimerGrpDestroy;  /* �ͷŶ�ʱ����ص����� ���� */
    PFEgnRWLockCreate       pfRWLCreate;        /* �������ص����� ���� */
    PFEgnRWLock             pfRWLWLock;         /* ��д���ص����� ���� */
    PFEgnRWUnlock           pfRWLWUnlock;       /* ��д���ص����� ���� */
    PFEgnRWLock             pfRWLRLock;         /* �Ӷ����ص����� ���� */
    PFEgnRWUnlock           pfRWLRUnlock;       /* ������ص����� ���� */
    PFEgnRWLockDelete       pfRWLockDelete;     /* ɾ����д���ص����� ���� */
    PFEgnSspStrNCmp         pfStrNCmp;          /* �ַ����Ƚ� ���� */
    PFEgnFuncPeerSynAdd     pfPeerSynAdd;       /* ������ͬ���ص����� ��ѡ */

    PFEgnHAAddPattern       pfHAAddPattern;     /* ��֧��NGFW��Ʒ Ӳ���������Ӳ��ģʽ�� */
    PFEgnHADeletePatternAll pfHADeletePatternAll; /* ��֧��NGFW��Ʒ Ӳ������ɾ��ȫ��ģʽ�� */

    PFEgnAtomicAdd          pfAtomicAdd;        /* ԭ�Ӽ� ���� */
    PFEgnAtomicSub          pfAtomicSub;        /* ԭ�Ӽ� ���� */
    PFEgnFeedWatchdog       pfFeedWatchdog;     /* ���Ź���λ ��ѡ */
    PFEgnIsInspectTimeOut   pfIsInspectTimeOut; /* ��֧��TD_RNC��Ʒ��ʶ��ʱ���Ƿ�ʱ ��ѡ��Ĭ�ϱ���Ϊ�� */
} EgnSspFunc;

/*STRUCT< �¼�����ص����� >*/
typedef struct _EgnEventFunc
{
     EGN_UINT32              ulMagic;            /* event magic,�û������ע,�벻Ҫ�޸� */
#ifdef EGN_64
     EGN_UINT8               aucReserved[4];     /* 64λ���뱣���ֽ� */
#endif
    PFEgnAddPeerList      pfAddPeerList;    /* ��ӹ����·����� */
    PFEgnDelPeerList      pfDelPeerList;    /* ɾ�������·����� */
} EgnEventFunc;

/*******************************************************************************
*    Func Name: EgnApiInitSspFuncParam
*      Purpose: ��ʼ��ָ��ϵͳ����ص������Ľṹ���ָ�롣
*  Description: ����EgnApiInitSspFuncParam���ṹ��pstSspParam��ÿ���ص�������ָ�붼��ֵΪ�գ�
                ����ĳ���ص�������ָ��û�и�ֵ�����²���Ԥ֪�Ĵ���
*        Input: NA
*        InOut: EgnSspFunc* pstSspParam:ϵͳ�������<�ǿ�>
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ����ָ��pstSspParam����Ϊ�գ������ʼ������
*        Since: V100R001C01
*    Reference: EgnApiRegSspFunc
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiInitSspFuncParam
(
    INOUT  EgnSspFunc *pstSspParam
);

/*******************************************************************************
*    Func Name: EgnApiRegSspFunc
*      Purpose: ע��ϵͳ����ص������������
*  Description: ϵͳ������Ҫ�ṩ�����ڴ桢�ͷ��ڴ桢�ļ���������ʱ�����̵߳ļӽ����ȹ��ܡ�
                �������Ҫʹ��ʱ�������ⲿ�ṩ�ĺ�������ɻ����Ĺ��ܡ���������ļ�ʱ�������ⲿ�ṩ���ļ�����������
*        Input: EgnSspFunc* pstSspParam:ϵͳ����ص�����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ������˵���⣬����APIӦ�ڳɹ����ø�API֮����ܱ�ʹ�á�
                ����EgnApiRegSspFuncע��ϵͳ����ص�����ǰ���ȵ���EgnApiInitSspFuncParam��
                ʹ�ṹ��pstSspParam��ÿ���ص�������ָ�붼��ֵΪ�գ�����ĳ���ص�������ָ��û�и�ֵ��
                ���²���Ԥ֪�Ĵ���
*        Since: V100R001C01
*    Reference: EgnApiInitSspFuncParam
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiRegSspFunc
(
    IN EgnSspFunc *pstSspParam
);

/*******************************************************************************
*    Func Name: EgnApiRegEventFunc
*      Purpose: ע��event�ص������������
*  Description: Event��Ҫ����������ӡ�����ɾ��������
*        Input: EgnEventFunc* pstEventParam:Event�ص�����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ����ʶ��ʵ����ʼ��֮����ܵ��á�
*        Since: V300R006C00
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiRegEventFunc
(
    IN EgnEventFunc *pstEventParam
);

/*******************************************************************************
*    Func Name: EgnApiRegAssertFn
*      Purpose: ע����ԵĻص�������
*  Description: ע����Իص������󣬿���ͨ����������ص�������ѯ�����Ķ�ջ��Ϣ��
*        Input: PFEgnFuncAssert pCallbackFunc:<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V100R001C01
*    Reference: PFEgnFuncAssert
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiRegAssertFn
(
    IN PFEgnFuncAssert  pfCallbackFunc
);

/*******************************************************************************
*    Func Name: EgnApiRegTraceSendFn
*      Purpose: ע�������Ϣ����Ļص�������
*  Description: ע�������Ϣ����ص������󣬿���ͨ��������Ϣ����ص�������ӡ������Ϣ��
*        Input: PFEgnFuncTraceSend pCallbackFunc:<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V100R001C01
*    Reference: PFEgnFuncTraceSend
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiRegTraceSendFn
(
    IN PFEgnFuncTraceSend pfCallbackFunc
);

/*******************************************************************************
*    Func Name: EgnApiRegStatSendFn
*      Purpose: ע��ͳ����Ϣ����Ļص�������
*  Description: ע��ͳ����Ϣ����ص������󣬿���ͨ��ͳ����Ϣ����ص�������ӡͳ����Ϣ��
*        Input: PFEgnFuncStatSend pCallbackFunc:<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V100R001C01
*    Reference: PFEgnFuncStatSend
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiRegStatSendFn
(
    IN PFEgnFuncStatSend pfCallbackFunc
);

/*******************************************************************************
*    Func Name: EgnApiRegLogSendFn
*      Purpose: ע����־��Ϣ����ص�����
*  Description: ע����־��Ϣ����ص������󣬿���ͨ����־����ص�������ӡ��־��Ϣ��
*        Input: PFEgnFuncLogSend pCallbackFunc:��־�ص�����<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V100R001C01
*    Reference: PFEgnFuncLogSend
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiRegLogSendFn
(
    IN  PFEgnFuncLogSend  pfCallbackFunc
);

/*******************************************************************************
*    Func Name: EgnApiRegDebugPrintFn
*      Purpose: ע�������Ϣ����Ļص�����
*  Description: ע�������Ϣ����Ļص������󣬿���ͨ��������Ϣ����ص�������ӡ������Ϣ��
*        Input: PFEgnFuncDbgPrint pCallbackFunc:<�ǿ�>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��API��ʹ��EgnApiRegSspFunc�ɹ�ע��ϵͳ����ص�����֮ǰ�ɱ����á�
*        Since: V100R001C01
*    Reference: PFEgnFuncDbgPrint
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiRegDebugPrintFn
(
    IN  PFEgnFuncDbgPrint pfCallbackFunc
);

/*******************************************************************************
*    Func Name: EgnApiDebugControl
*      Purpose: ���Ƶ�����Ϣ�����
*  Description: �ýӿڸ��ݵ�����Ϣ������ƿ���ulCommand�����Ƶ�����Ϣ�Ƿ�����Լ������Ϣ�ļ���
*        Input: EGN_UINT32 ulCommand:������Ϣ������ƿ���<EGN_DBGCMD_ONOFF_SWITCH(DEBUG����)��EGN_DBGCMD_LEVEL_SWITCH(������Ϣ�������)>
*               EGN_UINT8* pucContent:��Ӧ����ֵ<ulCommandΪEGN_DBGCMD_ONOFF_SWITCHʱȡEGN_DEBUG_ON/EGN_DEBUG_OFF
                                                ulCommandΪEGN_DBGCMD_LEVEL_SWITCHʱȡEGN_DEBUG_LEVEL_FATAL~EGN_DEBUG_LEVEL_INFO>
*        InOut: NA
*       Output: NA
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��API��ʹ�ù����̳߳�ʼ��֮��ſɱ����á�
*        Since: V200R002C01
*    Reference: EgnApiGetDebugControl
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiDebugControl
(
   IN               EGN_UINT32    ulCommand,
   IN  EGN_CONST    EGN_UINT8    *pucContent
);

/*******************************************************************************
*    Func Name: EgnApiGetDebugControl
*      Purpose: ��ѯ������Ϣ�Ƿ�����Լ������Ϣ�ļ���
*  Description: �ýӿڸ��ݵ�����Ϣ������ƿ���ulCommand����ѯ������Ϣ�Ƿ�����Լ������Ϣ�ļ���
*        Input: EGN_UINT32 ulCommand:������Ϣ������ƿ���<EGN_DBGCMD_ONOFF_SWITCH(DEBUG����)��EGN_DBGCMD_LEVEL_SWITCH(������Ϣ�������)>
*        InOut: NA
*       Output: EGN_UINT32* pucContent:������Ϣ<�ǿ�>
*       Return: EGN_UINT32���ɹ�����ʧ�ܵĴ����롣
*      Caution: ��API��ʹ�ù����̳߳�ʼ��֮��ſɱ����á�
*        Since: V100R001C01
*    Reference: EgnApiDebugControl
*------------------------------------------------------------------------------
*  Modification History
*  DATE         NAME                    DESCRIPTION
*------------------------------------------------------------------------------
*
*******************************************************************************/
EGN_UINT32 EgnApiGetDebugControl
(
    IN    EGN_UINT32    ulCommand,
    OUT   EGN_UINT32   *pulContent
);

/*STRUCT< ά���ӿڶ��� >*/
typedef struct _EgnSmpFunc
{
    PFEgnFuncAssert     pfEgnAssert;     /* ���Խӿ� */
    PFEgnFuncLogSend    pfEgnLogSend;    /* �����־�ӿ� */
    PFEgnFuncStatSend   pfEgnStatSend;   /* ���ͳ����־�ӿ� */
    PFEgnFuncTraceSend  pfEgnTraceSend;  /* ������ٽӿ� */
    PFEgnFuncDbgPrint   pfEgnDbgSend;    /* ���������Ϣ�ӿ� */
} EgnSmpFunc;

/*STRUCT< SMP�������ö��� >*/
typedef struct _EgnSmpParam
{
    EGN_UINT32          ulDebugSwtich;   /* ���Կ���,������μ�#EGN_DBG_SWTICH_EN */
    EGN_UINT32          ulDebugLevel;    /* ���Եȼ���������μ�#EGN_DEBUG_LEVEL_EN */
}EgnSmpParam;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __EGN_API_SSP_SMP_H__ */

