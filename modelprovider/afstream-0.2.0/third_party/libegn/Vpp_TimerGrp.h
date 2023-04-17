/******************************************************************************

                  ��Ȩ���� (C), 2001-2011, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : Vpp_TimerGrp.h
  �� �� ��   : ����
  ��    ��   : ��
  ��������   : ��
  ����޸�   :
  ��������   : ��ʱ�������ݽṹ����������
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

******************************************************************************/


#ifdef __cplusplus
extern "C" {
#endif

#ifndef __VPP_TimerGrp_H__
#define __VPP_TimerGrp_H__

#include "Vpp_typedef.h"

#define VPP_WIN32           1
#define VPP_SOLARIS_POSIX   2
#define VPP_AIX             3
#define VPP_VXWORKS         4
#define VPP_LINUX_POSIX     5
#define VPP_HP              6

#ifndef VPP_OS_VER
#error "must define VPP_OS_VER: VPP_WIN32, VPP_SOLARIS_POSIX, VPP_AIX, VPP_VXWORKS, VPP_LINUX_POSIX"
#endif


#ifdef VPP_OS_VER
#if ( VPP_OS_VER == VPP_WIN32 )
#include <windows.h>
#elif (VPP_OS_VER == VPP_SOLARIS_POSIX)
#include "pthread.h"
#elif (VPP_OS_VER == VPP_LINUX_POSIX)
#include "pthread.h"
#include "sys/time.h"
#elif (VPP_OS_VER == VPP_AIX)
#include "pthread.h"
#elif (VPP_OS_VER == VPP_HP)
#include "pthread.h"
#elif (VPP_OS_VER == VPP_VXWORKS)
#include "Time.h"
#include "intLib.h"
struct timeval
{
    long tv_sec;
    long tv_usec;
};
#endif
#endif /* VPP_OS_VER */


#ifdef VPP_OS_VER
#if ( VPP_OS_VER == VPP_WIN32 )
RTL_CRITICAL_SECTION VPP_CriticalSection;
#elif ( VPP_OS_VER == VPP_SOLARIS_POSIX || VPP_OS_VER == VPP_AIX || VPP_OS_VER == VPP_HP || VPP_OS_VER == VPP_LINUX_POSIX)
pthread_mutex_t VPP_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
#endif /* VPP_OS_VER */

#define G_SYSCALLBACK     g_stGlobal.stSysCallback;

#define G_RUNTIMERLIST    g_stGlobal.stRunTimerList;

#define VPP_MALLOC (*g_stGlobal.stSysCallback.pfMalloc)
#define VPP_FREE   (*g_stGlobal.stSysCallback.pfFree)
#define VPP_MEMCPY (*g_stGlobal.stSysCallback.pfMemcpy)
#define VPP_MEMSET (*g_stGlobal.stSysCallback.pfMemset)

/* [[SWED12582][2008-12-17][chenhongshan 103208]] Added begin: */
#ifdef VPP_DEBUG
extern int printf(const char *, ...);
#define VPP_DEBUG_HELP          0
#define VPP_DEBUG_TIMER_LIST    1
#define VPP_LOG    printf
#endif
/* [[SWED12582][2008-12-17][chenhongshan 103208]] Added end. */

/* [2007-11-01][add by c103208] begin: ���ӳ�ʼ���������ʱ�������ӿ� */
#define VPP_MIN_TIMER_NUM    20000           /* ��С��ʱ��������2�� */
#define VPP_MAXRUNTIMER_NUM  g_maxtimer_num  /* ȫ�ֱ������������ʱ���� */
/* [2007-11-01][add by c103208] end: ���ӳ�ʼ���������ʱ�������ӿ� */

/* [[SWED12582][2008-12-17][chenhongshan]]  begin:TimerGrp �½�������������󻺳�����С*/
#define VPP_MAX_TIMEER_CACHE   512
/* [[SWED12582][2008-12-17][chenhongshan]]  end. */


typedef VPP_VOID (*PTVppFuncIterate)
(
    IN    PVPPTIMER*      ppTimer
);

typedef enum VPP_TIMER_STATE_E
{
    VPP_TIMER_IDLE,
    VPP_TIMER_TICKING,
    VPP_TIMER_STATEBUTT
} VPP_TIMER_STATE_EN;


typedef struct VPP_TIMERGRP_NODE_ST
{
    VPP_UINT32          ulTmIndex;
    VPP_UINT8           ucTmState;
    VPP_UINT8           ucTmMode;
    VPP_UINT16          usReserved;
    VPP_UINT32          ulTmLength;
    VPP_UINT32          ulTmName;
    VPP_UINT32          ulParam;
    VPP_UINT32          ulRunIndex;
    struct timeval      stNextTime; /* ��һ�γ�ʱʱ�� */
    PTVppFuncTimeout    pfTimeout;
    PVPPTIMER*          ppTimer;     /* ��¼����ʱ���ڶ�ʱ�����е�λ�� */
}VPP_TIMERGRP_NODE_ST;

typedef struct VPP_TIMERGRP_UNIT_S
{
    VPP_UINT32                  ulMaxNum;
    VPP_ADDRESS                  *pData;
    struct VPP_TIMERGRP_UNIT_S  *pNextUnit;
}VPP_TIMERGRP_UNIT_ST;

typedef struct VPP_TIMERGRP_S
{
    VPP_UINT32                  ulMaxNum;
    PTVppFuncTimeout            pfTimeout;
    VPP_TIMERGRP_UNIT_ST        *pFirstTimerGrpUnit; /* ��ʱ���鵥Ԫ����ͷָ�� */
    struct VPP_TIMERGRP_S       *pNextGrp;
    struct VPP_TIMERGRP_S       *pPrevGrp;
}VPP_TIMERGRP_ST,*P_VPP_TIMERGRP_ST;


typedef struct VPP_TIMERGRP_LIST_S
{
    VPP_UINT32                  ulCount;
    VPP_ADDRESS                 *pArray;
} VPP_TIMERGRP_LIST_ST;

typedef struct VPP_TIMERGRP_GLOBAL_S
{
    VPP_UINT32                   ulInitFlag;
    VPP_TIMERGRP_SYS_CALLBACK_ST stSysCallback;
    VPP_TIMERGRP_CONFIG_ST       stConfig;
    VPP_TIMERGRP_LIST_ST         stRunTimerList;
    VPP_TIMERGRP_ST             *pGrpTimerList;  /*��ʱ������У�ָ��ʱ�������ͷָ��*/

    /* [[SWED12582][2008-12-17][chenhongshan]]  begin: TimerGrp����������*/
    PVPPTIMER                    ahTimerBuffer[VPP_MAX_TIMEER_CACHE];/*���建����*/
    VPP_UINT32                   ulFreeCount;                        /*����Ŀǰ����������Ч���п�����*/
    /* [[SWED12582][2008-12-17][chenhongshan]]  end. */

} VPP_TIMERGRP_GLOBAL_ST;

/*****************************************************************************
 �� �� ��  : VppTimerGrpCreateUnit
 ��������  : ���붨ʱ���鵥Ԫ��
 �������  : ulMaxTimerNums  ��ǰ��ʱ���鵥Ԫ�ڶ�ʱ���������Ŀ
 �������  : ppTimerGrpUnit  ��ʱ���鵥Ԫ���ָ�룬�ڴ��ɶ�ʱ����ģ����䡣
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpCreateUnit
(
    OUT   VPP_TIMERGRP_UNIT_ST**    ppTimerGrpUnit,
    IN    VPP_UINT32                ulMaxTimerNums
);

/*****************************************************************************
 �� �� ��  : VppTimerStart
 ��������  : ����ĳ����ʱ��
 �������  : ulTmName     ��ʱ������
             ulTmLength   ��ʱ�����ȣ���λ�Ǻ���
             ucTmMode     ��ʱ���Ĺ���ģʽ��VPP_TIMER_NOLOOP����ѭ������ VPP_TIMER_LOOP��ѭ����
             pfTimeout    ��ʱ����Ӧ�ĳ�ʱ������
 �������  : ppstTimer    ��ʱ��ָ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerStart
(
    OUT  PVPPTIMER*              ppstTimer,
    IN   VPP_UINT32              ulTmLength,
    IN   VPP_UINT32              ulTmName,
    IN   VPP_UINT32              ulTmParam,
    IN   VPP_UINT8               ucTmMode,
    IN   PTVppFuncTimeout        pfTimeout
);

/*****************************************************************************
 �� �� ��  : VppTimerStop
 ��������  : ֹͣĳ����ʱ��
 �������  : ppstTimer    ��ʱ�����ָ��
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  : VppTimerGrpListDeleteNode
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerStop
(
    IN  PVPPTIMER*   ppstTimer
);

/*****************************************************************************
 �� �� ��  : VppTimerGrpListAddNode
 ��������  : ��һ����ʱ���������ж�ʱ��������
 �������  : pstTimerNode    ��ʱ�����ָ��
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpListAddNode
(
    IN  PVPPTIMER    pstTimerNode
);

/*****************************************************************************
 �� �� ��  : VppTimerGrpListDeleteNode
 ��������  : �Ӷ�ʱ��������ɾ��һ����ʱ��
 �������  : pstTimerNode    ��ʱ�����ָ��
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpListDeleteNode
(
    IN  PVPPTIMER    pstTimerNode
);

/*****************************************************************************
 �� �� ��  : Vpp_InitLock
 ��������  : ��ʼ���ź���
 �������  : void
 �������  : ��
 �� �� ֵ  : VPP_INT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_INT32 Vpp_InitLock( void );

/*****************************************************************************
 �� �� ��  : Vpp_Lock
 ��������  : �����ź���
 �������  : VPP_INT *pLockKey
 �������  : ��
 �� �� ֵ  : VPP_INT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_INT32 Vpp_Lock(VPP_INT *pLockKey);

/*****************************************************************************
 �� �� ��  : Vpp_Unlock
 ��������  : �ͷ��ź���
 �������  : VPP_INT lockKey
 �������  : ��
 �� �� ֵ  : VPP_INT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_INT32 Vpp_Unlock(VPP_INT lockKey);

/*****************************************************************************
 �� �� ��  : Vpp_GetTime
 ��������  : ��ȡ��ǰʱ��
 �������  : struct timeval *pstTime
 �������  : ��
 �� �� ֵ  : VPP_VOID
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�
*****************************************************************************/
VPP_VOID Vpp_GetTime(struct timeval *pstTime);

/*****************************************************************************
 �� �� ��  : VppTimerGrpGet
 ��������  : ��ȡ��ʱ�����е�һ����ʱ��
 �������  : IN VPP_TIMERGRP_ST*         pTimerGrp
             IN VPP_UINT32               ulTmSn
             OUT PVPPTIMER**             pppTimer
 �������  : ��
 �� �� ֵ  : VPP_UINT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpGet
(
    IN VPP_TIMERGRP_ST*         pTimerGrp,
    IN VPP_UINT32               ulTmSn,
    OUT PVPPTIMER**             ppTimer
);

/*****************************************************************************
 �� �� ��  : VppTimerGrpSet
 ��������  : ���ö�ʱ������һ����ʱ��������
 �������  : IN VPP_TIMERGRP_ST*         pTimerGrp
             IN VPP_UINT32               ulTmSn
             OUT VPP_VOID*               pTimer
 �������  : ��
 �� �� ֵ  : VPP_UINT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpSet
(
    IN VPP_TIMERGRP_ST*         pTimerGrp,
    IN VPP_UINT32               ulTmSn,
    OUT VPP_VOID*               pTimer
);

/*****************************************************************************
 �� �� ��  : VppTimerGrpIterateStop
 ��������  : ֹͣ��ʱ��
 �������  : PVPPTIMER       *ppTimer
 �������  : ��
 �� �� ֵ  : VPP_VOID
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_VOID VppTimerGrpIterateStop
(
    PVPPTIMER       *ppTimer
);

/*****************************************************************************
 �� �� ��  : VppTimerGrpIterateFree
 ��������  : �ͷŶ�ʱ��
 �������  : PVPPTIMER       *ppTimer
 �������  : ��
 �� �� ֵ  : VPP_VOID
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_VOID VppTimerGrpIterateFree
(
    PVPPTIMER       *ppTimer
);

/*****************************************************************************
 �� �� ��  : VppTimerGrpIterate
 ��������  : ʹ�ûص���������ʱ����
 �������  : pTimerGrp  Ҫ����Ķ�ʱ����
             pfIterate  �ص�����ָ��
 �������  : ��
 �� �� ֵ  : VPP_UINT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpIterate
(
    IN VPP_TIMERGRP_ST*        pTimerGrp,
    IN PTVppFuncIterate        pfIterate
);

/* [[SWED13909] [2009-01-12] [Z00108581]] ��ҵ�������� 200812270221��TimerGropu�����Ҫ�ṩ֧��suse10 64λϵͳ BEGIN */
#define Vpp_ExchangeValue(a, b, type) \
{\
    type tmp;\
    tmp = a;\
    a = b;\
    b = tmp;\
}
/* [SWED13909] [2009-01-12] [Z00108581]   End */

/*****************************************************************************
 �� �� ��  : Vpp_AddToBinTree
 ��������  : ����ʱ���ӽ�����Bin��
 �������  : PVPPTIMER  pstTimerNode
             VPP_UINT32 ulIndex
             VPP_UINT32 *pTreeArray
 �������  : ��
 �� �� ֵ  : VPP_VOID
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_VOID Vpp_AddToBinTree
(
    IN  PVPPTIMER  pstTimerNode,
    IN  VPP_UINT32 ulIndex,
    IO  VPP_ADDRESS *pTreeArray
);


/*****************************************************************************
 �� �� ��  : VppTimerReset
 ��������  : ��������ĳ����ʱ��
 �������  : ppstTimer       ��ʱ�����ָ��
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  : VppTimerStart
             VppTimerStop
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerReset
(
    IN  PVPPTIMER*   ppstTimer
);

/*****************************************************************************
 �� �� ��  : VppTimerGrpAllocTimer
 ��������  : �ӻ�������ȡ�����е�һ���ڵ㣬��ֱ�������ڴ�
 �������  : PVPPTIMER  pstTimer
 �������  : ��
 �� �� ֵ  : VPP_VOID
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2008��12��17��
    ��    ��   : �º�ɽ 00103208
    �޸�����   : ��������

*****************************************************************************/
VPP_VOID VppTimerGrpAllocTimer
(
    PVPPTIMER  *pstTimer
);

/*****************************************************************************
 �� �� ��  : VppTimerGrpFreeTimer
 ��������  : ��һ����ʱ���Żػ������У���ֱ���ͷ��ڴ�
 �������  : PVPPTIMER  pstTimer
 �������  : ��
 �� �� ֵ  : VPP_UINT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2008��12��17��
    ��    ��   : �º�ɽ 00103208
    �޸�����   : ��������

*****************************************************************************/
VPP_VOID VppTimerGrpFreeTimer
(
    PVPPTIMER  *pstTimer
);


#endif /*__VPP_TimerGrp_H__*/

#ifdef __cplusplus
}
#endif
