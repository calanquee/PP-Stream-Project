/******************************************************************************

                  ��Ȩ���� (C), 2001-2011, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : Vpp_typedef.h
  �� �� ��   : ����
  ��    ��   : ���컶 60015914
  ��������   : 2006��7��29��
  ����޸�   :
  ��������   : ��ʱ�������ݽṹ
  �����б�   :
  �޸���ʷ   :
  �޸���ʷ   :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

******************************************************************************/

 
#ifdef __cplusplus
extern "C" {
#endif

#ifndef __VPP_typedef_H__
#define __VPP_typedef_H__

#define IN
#define OUT
#define IO

#define VPP_VOID       void
#define VPP_CHAR       char
#define VPP_UCHAR      unsigned char
#define VPP_UINT8      unsigned char
#define VPP_UINT16     unsigned short int
#define VPP_UINT32     unsigned int
#define VPP_ADDRESS    unsigned long
#define VPP_INT32      long
#define VPP_INT        int
#define VPP_NULL_PTR   0L

#define VPP_TRUE        1L
#define VPP_FALSE       0L

/***************************************
ϵͳ�ص�����
***************************************/
typedef VPP_CHAR* (*PTVppFuncMalloc)
(
    IN    VPP_UINT32     ulSize
);

typedef VPP_VOID (*PTVppFuncFree)
(
    IN    VPP_VOID       *pAddr
);
typedef VPP_VOID (*PTVppFuncMemcpy)
(
    IN    VPP_VOID*    pDestAddr,
    IN    VPP_VOID*    pSrcAddr,
    IN    VPP_UINT32    ulSize
); 
typedef VPP_VOID (*PTVppFuncMemset)
(
    IN    VPP_VOID*    pAdd,
    IN    VPP_CHAR    value,
    IN    VPP_UINT32  ulSize
);

typedef struct VPP_TIMERGRP_SYS_CALLBACK_S
{
    PTVppFuncMalloc       pfMalloc;
    PTVppFuncFree         pfFree;
    PTVppFuncMemcpy       pfMemcpy;
    PTVppFuncMemset       pfMemset;
}VPP_TIMERGRP_SYS_CALLBACK_ST;

typedef struct VPP_TIMERGRP_CONFIG_S
{
    VPP_UINT32  ulTicksPerSecond;
}VPP_TIMERGRP_CONFIG_ST;

typedef VPP_VOID (*PTVppFuncTimeout)
(
    IN  VPP_UINT32        ulTmSn,  /* ��Զ�ʱ�������The serial number of the relative timer */
    IN  VPP_UINT32        ulTmName /* ��ʱ������ The timer name */
);

typedef struct VPP_TIMERGRP_NODE_ST *PVPPTIMER;

typedef enum VPP_TIMER_MODE_E
{
    VPP_TIMER_NOLOOP,
    VPP_TIMER_LOOP,
    VPP_TIMER_MODEBUTT
} VPP_TIMER_MODE_EN;

typedef enum VPP_TIMERGRP_RET_E
{
    VPP_SUCCESS,
    VPP_FAILURE,          /* normal error */
    VPP_ERR_INITLOCK,     /* init Lock error */
    VPP_ERR_LOCK,
    VPP_ERR_UNLOCK,
    VPP_ERR_MALLOCFAIL,   /* allocate memory failed */
    VPP_ERR_INPUTNULL,    /* input param is NULL */
    VPP_ERR_TIMERNUMS,    /* timer numbers of group is error */
    VPP_ERR_TIMEOUTLEN,   /* input length of timer equal 0 */
    VPP_ERR_TIMERGRPSN,   /* index is large than number of TimerGrp */
    VPP_ERR_TIMERMODE,       /* mode err */
    VPP_ERR_TMNODEINVALID,/* timer not exist */
    VPP_ERR_TMSNINVALUD,  /* timer index error */
    VPP_ERR_REINIT,       /* REINIT */
    VPP_ERR_STARTED,      /* Started before */
    VPP_ERR_RUNNINGTIMER, /* number of running timers out of 100000*/
    VPP_ERR_RESIZE        /* newSize is error */
}VPP_TIMERGRP_RET_EN;

#endif /*__VPP_typedef_H__*/

#ifdef __cplusplus
}
#endif

