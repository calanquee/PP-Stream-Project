/******************************************************************************

                  ��Ȩ���� (C), 2001-2011, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : Vpp_TimerGrp.c
  �� �� ��   : ����
  ��    ��   : ��
  ��������   : ��
  ����޸�   :
  ��������   : ��ʱ�����ܺ���
  �����б�   :
              Vpp_AddToBinTree
              Vpp_ExchangeValue
              Vpp_GetTime
              Vpp_InitLock
              Vpp_Lock
              Vpp_Unlock
              VppTimerGrpCreate
              VppTimerGrpCreateUnit
              VppTimerGrpDestroy
              VppTimerGrpGet
              VppTimerGrpIsRun
              VppTimerGrpIterate
              VppTimerGrpIterateFree
              VppTimerGrpIterateStop
              VppTimerGrpListAddNode
              VppTimerGrpListDeleteNode
              VppTimerGrpModuleInit
              VppTimerGrpMoudleDeInit
              VppTimerGrpReset
              VppTimerGrpResize
              VppTimerGrpSet
              VppTimerGrpStart
              VppTimerGrpStop
              VppTimerGrpTrigger
              VppTimerRestart
              VppTimerStart
              VppTimerStop
  �޸���ʷ   :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

******************************************************************************/

#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif
#define VPP_OS_VER VPP_LINUX_POSIX
#include "Vpp_TimerGrp.h"

/* [2007-11-01][add by c103208] begin: ���ӳ�ʼ���������ʱ�������ӿ� */
VPP_UINT32 g_maxtimer_num = 200000;   /* Ĭ�����ʱ������20�� */
/* [2007-11-01][add by c103208] end: ���ӳ�ʼ���������ʱ�������ӿ� */


VPP_TIMERGRP_GLOBAL_ST     g_stGlobal;

/*****************************************************************************
 �� �� ��  : VppTimerSetMaxTimerNum
 ��������  : ��ʼ�����ÿ��õ����ʱ������������ڵ���20000��
             ��ʼ�����ܵ��ñ��ӿڣ�Ĭ�����ʱ������20��
 �������  : IN VPP_UINT32 ulMaxTimerNum ���ʱ����
 �������  : ��
 �� �� ֵ  : VPP_UINT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2007��11��02��
    ��    ��   : ������ 37398
    �޸�����   : �����ɺ�����

*****************************************************************************/
VPP_UINT32   VppTimerSetMaxTimerNum
(
    IN VPP_UINT32 ulMaxTimerNum
)
{
    if (ulMaxTimerNum < VPP_MIN_TIMER_NUM)
    {
        return VPP_FAILURE;
    }

    if(g_stGlobal.ulInitFlag == VPP_FALSE)
    {
        g_maxtimer_num = ulMaxTimerNum;
    }
    else
    {
        return VPP_ERR_REINIT;
    }

    return VPP_SUCCESS;

}

/*****************************************************************************
 �� �� ��  : VppTimerGrpModuleInit
 ��������  : ��ʼ����ʱ����ģ�飬������ز�����ע��ص�����ָ��?
 �������  : *pstSysCallBack
             *pstConfig
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpModuleInit
(
    IN  VPP_TIMERGRP_SYS_CALLBACK_ST     *pstSysCallBack,
    IN  VPP_TIMERGRP_CONFIG_ST           *pstConfig
)
{
    if ((VPP_NULL_PTR == pstSysCallBack) || (VPP_NULL_PTR == pstConfig))
    {
        return VPP_ERR_INPUTNULL;
    }

    if ((VPP_NULL_PTR == pstSysCallBack->pfMalloc)
       ||(VPP_NULL_PTR == pstSysCallBack->pfFree)
       ||(VPP_NULL_PTR == pstSysCallBack->pfMemcpy)
       ||(VPP_NULL_PTR == pstSysCallBack->pfMemset))
    {
        return VPP_ERR_INPUTNULL;
    }

    if(g_stGlobal.ulInitFlag == VPP_FALSE)
    {
        /* [[SWED13909] [2009-01-15] [Z00108581]] ��ҵ�������� 200812270221��TimerGropu�����Ҫ�ṩ֧��suse10 64λϵͳ BEGIN */
        /* Fix Review problem, InitLock Fail, then Module can't be inited again */
        if (VPP_SUCCESS != Vpp_InitLock())
        {
            return VPP_ERR_INITLOCK;
        }
        /* [SWED13909] [2009-01-15] [Z00108581]   End */

        g_stGlobal.ulInitFlag = VPP_TRUE;

        /*���ص�����ע�ᵽ��ʱ��ģ��,������Ӧ�Ļص�����ָ�뵽g_stGlobal*/
        g_stGlobal.stSysCallback.pfMalloc = pstSysCallBack->pfMalloc;
        g_stGlobal.stSysCallback.pfFree = pstSysCallBack->pfFree;
        g_stGlobal.stSysCallback.pfMemcpy = pstSysCallBack->pfMemcpy;
        g_stGlobal.stSysCallback.pfMemset = pstSysCallBack->pfMemset;

        /* ���ò��� */
        g_stGlobal.stConfig.ulTicksPerSecond = pstConfig->ulTicksPerSecond;

        /*��ʼ����ʱ�����ж���g_stGlobal.stRunTimerList;*/
        g_stGlobal.stRunTimerList.ulCount = 0;
        g_stGlobal.stRunTimerList.pArray = VPP_NULL_PTR;

        g_stGlobal.pGrpTimerList = VPP_NULL_PTR;

        /* Fix Review problem, Free CB Num In Cache must Init to zero */
        g_stGlobal.ulFreeCount = 0;

    }
    else
    {
        return VPP_ERR_REINIT;
    }

    pstSysCallBack = pstSysCallBack;/* for pc_lint */
    pstConfig = pstConfig;/* for pc_lint */
    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpCreate
 ��������  : ���붨ʱ���飬���������ʱ���鵥Ԫ��
 �������  : ulMaxTimerNums  ��ʱ�����ڶ�ʱ���������Ŀ
             pfTimeout       ��ʱ����ʱ����ص�����ָ��
 �������  : ppTimerGrp      ��ʱ������ָ�룬�ڴ��ɶ�ʱ����ģ����䡣APP���뱣���ָ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpCreate
(
    OUT  VPP_VOID**              ppTimerGrp,
    IN   VPP_UINT32              ulMaxTimerNums,
    IN   PTVppFuncTimeout        pfTimeout
)
{
    VPP_TIMERGRP_ST         *pTempTimerGrp = VPP_NULL_PTR;
    VPP_TIMERGRP_UNIT_ST    *pTimerGrpUnit = VPP_NULL_PTR;
    VPP_TIMERGRP_ST         *pTimerGrpLast = VPP_NULL_PTR;
    VPP_UINT32              ulRetVal;

    if(VPP_NULL_PTR == ppTimerGrp)
    {
        return VPP_ERR_INPUTNULL;
    }

    /* ���������ʱ�������Ϊ0 */
    if(0 == ulMaxTimerNums)
    {
        return VPP_ERR_TIMERNUMS;
    }

    /* �������pfTimeoutΪ�� */
    if (VPP_NULL_PTR == pfTimeout)
    {
        return VPP_ERR_INPUTNULL;
    }

    /*���붨ʱ������Դ������ʱ��������ڴ�*/
    pTempTimerGrp = (VPP_TIMERGRP_ST*)(VPP_VOID*)malloc(sizeof(VPP_TIMERGRP_ST));
    if (VPP_NULL_PTR == pTempTimerGrp)
    {
        return VPP_ERR_MALLOCFAIL;
    }

    /* ��ʼ����ʱ������Դ,������������浽��ʱ����ṹ��*/
    memset(pTempTimerGrp,0,sizeof(VPP_TIMERGRP_ST));

    ulRetVal = VppTimerGrpCreateUnit(&pTimerGrpUnit, ulMaxTimerNums);
    if(ulRetVal != VPP_SUCCESS)
    {
        VPP_FREE(pTempTimerGrp);
        pTempTimerGrp = VPP_NULL_PTR;
        return ulRetVal;
    }

    pTempTimerGrp->pFirstTimerGrpUnit = pTimerGrpUnit;
    pTempTimerGrp->ulMaxNum = ulMaxTimerNums;
    pTempTimerGrp->pfTimeout = pfTimeout;

    /* �����ʱ������ָ��*/
    *ppTimerGrp = pTempTimerGrp;

    pTimerGrpLast = g_stGlobal.pGrpTimerList;
    if(pTimerGrpLast == VPP_NULL_PTR)
    {
        g_stGlobal.pGrpTimerList = pTempTimerGrp;
    }
    else
    {
        while(pTimerGrpLast->pNextGrp != VPP_NULL_PTR)
        {
            pTimerGrpLast = pTimerGrpLast->pNextGrp;
        }

        pTimerGrpLast->pNextGrp = pTempTimerGrp;
        pTempTimerGrp->pPrevGrp = pTimerGrpLast;
    }

    return VPP_SUCCESS;
}

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
)
{
    VPP_TIMERGRP_UNIT_ST        *pTimerGrpUnit;
    VPP_UINT32                  ulUnitSize;

    if((ppTimerGrpUnit == VPP_NULL_PTR)
    ||(*ppTimerGrpUnit != VPP_NULL_PTR))
    {
        return VPP_ERR_INPUTNULL;
    }

    pTimerGrpUnit = (VPP_TIMERGRP_UNIT_ST*)(VPP_VOID*)malloc(sizeof(VPP_TIMERGRP_UNIT_ST));
    if(pTimerGrpUnit == VPP_NULL_PTR)
    {
        return VPP_ERR_MALLOCFAIL;
    }

    memset(pTimerGrpUnit, 0, sizeof(VPP_TIMERGRP_UNIT_ST));

    ulUnitSize = sizeof(VPP_ADDRESS);
    pTimerGrpUnit->pData = (VPP_ADDRESS*)(VPP_VOID*)malloc(ulUnitSize * ulMaxTimerNums);
    if(pTimerGrpUnit->pData == VPP_NULL_PTR)
    {
        VPP_FREE(pTimerGrpUnit);
        pTimerGrpUnit = VPP_NULL_PTR;
        return VPP_ERR_MALLOCFAIL;
    }

    memset(pTimerGrpUnit->pData, 0, ulUnitSize * ulMaxTimerNums);

    pTimerGrpUnit->pNextUnit = VPP_NULL_PTR;
    pTimerGrpUnit->ulMaxNum = ulMaxTimerNums;

    *ppTimerGrpUnit = pTimerGrpUnit;

    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpResize
 ��������  : ����ʱ�����ж�ʱ���ĸ�����
 �������  : ulNewSize       ��ǰ��ʱ������Ҫ�Ķ�ʱ���������Ŀ
             pTimerGrp       ��ʱ������ָ��
 �������  : pTimerGrp       ��ʱ������ָ�룬�����Ķ�ʱ���ڴ��ɶ�ʱ����ģ�����?
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpResize
(
    IO  VPP_VOID*               pTimerGrp,
    IN  VPP_UINT32              ulNewSize
)
{
    VPP_TIMERGRP_ST         *pTempTimerGrp;
    VPP_TIMERGRP_UNIT_ST    *pTimerGrpUnit = VPP_NULL_PTR;
    VPP_TIMERGRP_UNIT_ST    *pTimerGrpUnitTmp = VPP_NULL_PTR;
    VPP_UINT32              ulAddSize;
    VPP_UINT32              ulRetValue;
    VPP_INT                 lockKey = 0;

    if(pTimerGrp == VPP_NULL_PTR)
    {
        return VPP_ERR_INPUTNULL;
    }

    pTempTimerGrp = (VPP_TIMERGRP_ST*)pTimerGrp;
    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
        return VPP_ERR_LOCK;
    }

    if(pTempTimerGrp->ulMaxNum < ulNewSize)
    {
        /* ���Ҫ��� */
        ulAddSize = ulNewSize - pTempTimerGrp->ulMaxNum;

        pTimerGrpUnitTmp = pTempTimerGrp->pFirstTimerGrpUnit;
        while(pTimerGrpUnitTmp->pNextUnit != VPP_NULL_PTR)
        {
            pTimerGrpUnitTmp = pTimerGrpUnitTmp->pNextUnit;
        }

        ulRetValue = VppTimerGrpCreateUnit(&pTimerGrpUnit, ulAddSize);
        if(ulRetValue != VPP_SUCCESS)
        {
            if (VPP_SUCCESS != Vpp_Unlock(lockKey))
            {
                return VPP_ERR_UNLOCK;
            }
            return ulRetValue;
        }

        pTimerGrpUnitTmp->pNextUnit = pTimerGrpUnit;
    }
    else if(pTempTimerGrp->ulMaxNum > ulNewSize)
    {
        if (VPP_SUCCESS != Vpp_Unlock(lockKey))
        {
            return VPP_ERR_UNLOCK;
        }
        /* ��ʱ��ʵ�� */
        return VPP_ERR_RESIZE;
    }

    pTempTimerGrp->ulMaxNum = ulNewSize;

    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }

    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpUnlockDestroy
 ��������  : û������ɾ��TimerGrp����
 �������  : IO   VPP_VOID**              ppTimerGrp
 �������  : ��
 �� �� ֵ  : VPP_UINT32
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2007��12��11��
    ��    ��   : weihongkang
    �޸�����   : �����ɺ���

*****************************************************************************/
VPP_UINT32 VppTimerGrpUnlockDestroy
(
    IO   VPP_VOID**              ppTimerGrp
)
{
    VPP_TIMERGRP_ST         *pTempTimerGrp = VPP_NULL_PTR;
    VPP_TIMERGRP_UNIT_ST    *pTimerGrpUnit = VPP_NULL_PTR;
    VPP_TIMERGRP_UNIT_ST    *pTimerGrpUnitNext = VPP_NULL_PTR;
    VPP_UINT32              ulRetValue;

    if(VPP_NULL_PTR == ppTimerGrp)
    {
        return VPP_ERR_INPUTNULL;
    }

    pTempTimerGrp = (VPP_TIMERGRP_ST*)*ppTimerGrp;

    /* ֹͣ�����������еĶ�ʱ�� */
    ulRetValue = VppTimerGrpIterate(pTempTimerGrp, VppTimerGrpIterateStop);
    if(VPP_SUCCESS != ulRetValue)
    {
        return ulRetValue;
    }

    /* �ͷŶ�ʱ����ṹ������ָ��;
    �����������;*/
    pTempTimerGrp->ulMaxNum = 0;
    pTempTimerGrp->pfTimeout = VPP_NULL_PTR;

    pTimerGrpUnit = pTempTimerGrp->pFirstTimerGrpUnit;
    while(pTimerGrpUnit != VPP_NULL_PTR)
    {
        pTimerGrpUnitNext = pTimerGrpUnit->pNextUnit;
        VPP_FREE(pTimerGrpUnit->pData);
        pTimerGrpUnit->pData = VPP_NULL_PTR;
        VPP_FREE(pTimerGrpUnit);
        pTimerGrpUnit = pTimerGrpUnitNext;
    }

    if(pTempTimerGrp->pPrevGrp == VPP_NULL_PTR)
    {
        if(pTempTimerGrp->pNextGrp == VPP_NULL_PTR)
        {
            g_stGlobal.pGrpTimerList = VPP_NULL_PTR;
        }
        else
        {
            pTempTimerGrp->pNextGrp->pPrevGrp = VPP_NULL_PTR;
            g_stGlobal.pGrpTimerList = pTempTimerGrp->pNextGrp;
        }
    }
    else
    {
        pTempTimerGrp->pPrevGrp->pNextGrp = pTempTimerGrp->pNextGrp;
        if(pTempTimerGrp->pNextGrp != VPP_NULL_PTR)
        {
            pTempTimerGrp->pNextGrp->pPrevGrp = pTempTimerGrp->pPrevGrp;
        }
    }

    VPP_FREE(pTempTimerGrp);
    *ppTimerGrp = VPP_NULL_PTR;

    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpDestroy
 ��������  : �ͷŶ�ʱ���������ж�ʱ��
 �������  : ppTimerGrp    ��ʱ������ָ��
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpDestroy
(
    IO   VPP_VOID**  ppTimerGrp
)
{
    VPP_UINT32              ulRetValue;
    VPP_INT                 lockKey = 0;

    ppTimerGrp = ppTimerGrp;
    if(VPP_NULL_PTR == ppTimerGrp)
    {
        return VPP_ERR_INPUTNULL;
    }

    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
        return VPP_ERR_LOCK;
    }

    ulRetValue = VppTimerGrpUnlockDestroy(ppTimerGrp);

    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }

    return ulRetValue;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpMoudleDeInit
 ��������  : ע����ʱ����ģ�飬ɾ�����ж�ʱ����
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpMoudleDeInit()
{
    VPP_TIMERGRP_ST     *pTimerGrp = VPP_NULL_PTR;
    VPP_UINT32          ulRetValue;

    pTimerGrp = g_stGlobal.pGrpTimerList;
    while(pTimerGrp)
    {
        ulRetValue = VppTimerGrpUnlockDestroy((VPP_VOID**)(VPP_ADDRESS)(&pTimerGrp));
        if(ulRetValue != VPP_SUCCESS)
        {
            return ulRetValue;
        }

        pTimerGrp = g_stGlobal.pGrpTimerList;
    }

    /* [[SWED12582][2008-12-17][chenhongshan]]begin: ȥ��ʼ��ʱ���ͷŻ������Ķ�ʱ����Դ*/
    while (0 < g_stGlobal.ulFreeCount)
    {
        g_stGlobal.ulFreeCount--;
        VPP_FREE(g_stGlobal.ahTimerBuffer[g_stGlobal.ulFreeCount]);
    }
    /* [[SWED12582][2008-12-17][chenhongshan]]end. */

    /* ������ж��� */
    if (g_stGlobal.stRunTimerList.pArray != VPP_NULL_PTR)
    {
        VPP_FREE(g_stGlobal.stRunTimerList.pArray);
        g_stGlobal.stRunTimerList.pArray = VPP_NULL_PTR;
    }
    g_stGlobal.stRunTimerList.ulCount = 0;

    memset(&g_stGlobal, 0, sizeof(VPP_TIMERGRP_GLOBAL_ST));

    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpStart
 ��������  : ������ʱ�����е�ĳ����ʱ��
 �������  : pucTimeGrp    ��ʱ������ָ��
             ulTmSn        Ҫ��������Զ�ʱ�������
             ulTmName      ��ʱ������
             ulTmLength    ��ʱ�����ȣ���λ�Ǻ���
             ucTmMode      ��ʱ���Ĺ���ģʽ��VPP_TIMER_NOLOOP����ѭ������ VPP_TIMER_LOOP��ѭ����
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
VPP_UINT32 VppTimerGrpStart
(
    IN  VPP_VOID*               pTimerGrp,
    IN  VPP_UINT32              ulTmSn,
    IN  VPP_UINT32              ulTmLength,
    IN  VPP_UINT32              ulTmName,
    IN  VPP_UINT8               ucTmMode
)
{
    VPP_TIMERGRP_ST*    pTempTimerGrp = (VPP_TIMERGRP_ST*)pTimerGrp;
    PVPPTIMER*          ppTempTimer = VPP_NULL_PTR;
    VPP_UINT32          ulReturnVal   = 0;
    VPP_INT             lockKey = 0;

    if(VPP_NULL_PTR == pTempTimerGrp)
    {
        return VPP_ERR_INPUTNULL;
    }

    /*if(0 == ulTmLength)
    {
        return VPP_ERR_TIMEOUTLEN;
    }*/

    if(ulTmSn >= pTempTimerGrp->ulMaxNum)
    {
        return VPP_ERR_TIMERGRPSN;
    }

    if((VPP_TIMER_LOOP != ucTmMode)&&(VPP_TIMER_NOLOOP != ucTmMode))
    {
        return VPP_ERR_TIMERMODE;
    }

    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
        return VPP_ERR_LOCK;
    }
    ulReturnVal = VppTimerGrpGet(pTempTimerGrp, ulTmSn, &ppTempTimer);
    if((ulReturnVal == VPP_SUCCESS)&&(VPP_NULL_PTR != *ppTempTimer))
    {
        if (VPP_TIMER_TICKING == (*ppTempTimer)->ucTmState)
        {
            /* ֹͣ�ö�ʱ��*/
            ulReturnVal = VppTimerStop(ppTempTimer);
            if(VPP_SUCCESS != ulReturnVal)
            {
                if (VPP_SUCCESS != Vpp_Unlock(lockKey))
                {
                    return VPP_ERR_UNLOCK;
                }
                return ulReturnVal;
            }
        }
        *ppTempTimer = VPP_NULL_PTR;
    }

    /* �����ö�ʱ��*/
    ulReturnVal = VppTimerStart(ppTempTimer,ulTmLength,ulTmName,ulTmSn,ucTmMode,pTempTimerGrp->pfTimeout);
    if(ulReturnVal != VPP_SUCCESS)
    {
        if (VPP_SUCCESS != Vpp_Unlock(lockKey))
        {
            return VPP_ERR_UNLOCK;
        }
        return ulReturnVal;
    }

    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }
    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpIsRun
 ��������  : ��ѯ��Ӧ�Ķ�ʱ���Ƿ�������
 �������  : pucTimeGrp    ��ʱ������ָ��
             ulTmSn        Ҫ��������Զ�ʱ�������

 �������  : pRunFlag      ��ǰ�Ƿ������еı�ʶ
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpIsRun
(
    IN  VPP_VOID*               pTimerGrp,
    IN  VPP_UINT32              ulTmSn,
    OUT VPP_UINT32*             pRunFlag
)
{
    VPP_TIMERGRP_ST*    pTempTimerGrp = (VPP_TIMERGRP_ST*)pTimerGrp;
    PVPPTIMER*          ppTempTimer = VPP_NULL_PTR;
    VPP_UINT32          ulReturnVal   = 0;
    VPP_INT             lockKey = 0;

    if((VPP_NULL_PTR == pTempTimerGrp)||(VPP_NULL_PTR == pRunFlag))
    {
        return VPP_ERR_INPUTNULL;
    }

    if(ulTmSn >= pTempTimerGrp->ulMaxNum)
    {
        return VPP_ERR_TIMERGRPSN;
    }

    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
       return VPP_ERR_LOCK;
    }

    *pRunFlag = VPP_FALSE;
    ulReturnVal = VppTimerGrpGet(pTempTimerGrp, ulTmSn, &ppTempTimer);
    if((ulReturnVal == VPP_SUCCESS)&&(VPP_NULL_PTR != *ppTempTimer))
    {
        if (VPP_TIMER_TICKING == (*ppTempTimer)->ucTmState)
        {
            *pRunFlag = VPP_TRUE;
        }
    }

    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }
    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerRestart
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
VPP_UINT32 VppTimerRestart
(
    IN  VPP_VOID**   ppstTimer
)
{
    VPP_UINT32       ulReturnVal = 0;
    VPP_INT          lockKey = 0;

    if (VPP_NULL_PTR == ppstTimer)
    {
        return VPP_ERR_INPUTNULL;
    }

    /* [SWED10833][2007-09-06][chenhongshan 103208]: add begin: �������� */
    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
        return VPP_ERR_LOCK;
    }
    /* [SWED10833][2007-09-06][chenhongshan 103208]: add end: �������� */

    /*����VppTimerReset()�����ö�ʱ��*/
    ulReturnVal = VppTimerReset((PVPPTIMER *)ppstTimer);

    /* [SWED10833][2007-09-06][chenhongshan 103208]: add begin: �������� */
    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }
    /* [SWED10833][2007-09-06][chenhongshan 103208]: add end: �������� */

    return ulReturnVal;

}

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
)
{
    PVPPTIMER  pTempTimer = VPP_NULL_PTR;
    VPP_UINT32 ulTmLength = 0;
    VPP_UINT32 ulTmParam = 0;
    VPP_UINT32 ulTmName = 0;
    VPP_UINT8  ucTmMode = 0;
    PTVppFuncTimeout pfTimeout   = VPP_NULL_PTR;
    VPP_UINT32       ulReturnVal = 0;

    if (VPP_NULL_PTR == ppstTimer)
    {
        return VPP_ERR_INPUTNULL;
    }

    if (VPP_NULL_PTR == *ppstTimer)
    {
        return VPP_ERR_INPUTNULL;
    }

    pTempTimer = *ppstTimer;

    /* �ȱ������ݣ�ֹͣ��ʱ�����ԭ��������ɾ�� */
    ulTmLength = pTempTimer->ulTmLength;
    ulTmName = pTempTimer->ulTmName;
    ucTmMode = pTempTimer->ucTmMode;
    ulTmParam = pTempTimer->ulParam;
    pfTimeout = pTempTimer->pfTimeout;
    if(VPP_TIMER_TICKING == pTempTimer->ucTmState)
    {
        /*����VppTimerStop()ֹͣ�ö�ʱ��*/
        ulReturnVal = VppTimerStop(ppstTimer);
        if(VPP_SUCCESS != ulReturnVal)
        {
            return ulReturnVal;
        }
    }

    /*����VppTimerStart()�����ö�ʱ��*/
    ulReturnVal = VppTimerStart(ppstTimer,
                                ulTmLength,
                                ulTmName,
                                ulTmParam,
                                ucTmMode,
                                pfTimeout);

    return ulReturnVal;

}

/*****************************************************************************
 �� �� ��  : VppTimerRelStart
 ��������  : ����һ����Զ�ʱ��
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
VPP_UINT32 VppTimerRelStart
(
    OUT  VPP_VOID**              ppstTimer,
    IN   VPP_UINT32              ulTmLength,
    IN   VPP_UINT32              ulTmName,
    IN   VPP_UINT32              ulTmParam,
    IN   VPP_UINT8               ucTmMode,
    IN   PTVppFuncTimeout        pfTimeout
)
{
    VPP_UINT32       ulReturnVal   = 0;
    VPP_INT          lockKey = 0;

    if(VPP_NULL_PTR == ppstTimer)
    {
        return VPP_ERR_INPUTNULL;
    }

    if(VPP_NULL_PTR == pfTimeout)
    {
        return VPP_ERR_INPUTNULL;
    }

    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
        return VPP_ERR_LOCK;
    }

    ulReturnVal = VppTimerStart((PVPPTIMER *)ppstTimer,
                                ulTmLength,
                                ulTmName,
                                ulTmParam,
                                ucTmMode,
                                pfTimeout);

    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }

    return ulReturnVal;
}





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
)
{
    PVPPTIMER   pstTempTimer = VPP_NULL_PTR;
    VPP_UINT32  ulReturnVal = 0;

    if(VPP_NULL_PTR == ppstTimer)
    {
        return VPP_ERR_INPUTNULL;
    }

    if (VPP_NULL_PTR == pfTimeout)
    {
        return VPP_ERR_INPUTNULL;
    }

    /*������ʱ��*ppstTimer�����ڴ�*/
    /* [[SWED12582][2008-12-17][chenhongshan]]  begin: ����ʱ�������ڴ�*/
    /* /pstTempTimer = (PVPPTIMER)(VPP_VOID*)malloc(sizeof(struct VPP_TIMERGRP_NODE_ST)); */
    VppTimerGrpAllocTimer(&pstTempTimer);
    /* [[SWED12582][2008-12-17][chenhongshan]]  end. */
    if(VPP_NULL_PTR == pstTempTimer)
    {
        return VPP_ERR_MALLOCFAIL;
    }

    /*��д��ʱ������*/
    pstTempTimer->ulTmIndex = ulTmParam;
    pstTempTimer->ucTmState = VPP_TIMER_IDLE;
    pstTempTimer->ucTmMode = ucTmMode;
    pstTempTimer->ulTmLength = ulTmLength;
    pstTempTimer->ulTmName = ulTmName;
    pstTempTimer->ulParam = ulTmParam;
    Vpp_GetTime(&(pstTempTimer->stNextTime));
    pstTempTimer->stNextTime.tv_sec += (long)(ulTmLength / 1000);
    pstTempTimer->stNextTime.tv_usec += (long)((ulTmLength % 1000) * 1000);
    if (pstTempTimer->stNextTime.tv_usec >= 1000000)
    {
        pstTempTimer->stNextTime.tv_sec++;
        pstTempTimer->stNextTime.tv_usec -= 1000000;
    }
    pstTempTimer->pfTimeout = pfTimeout;
    pstTempTimer->ppTimer = ppstTimer;
    pstTempTimer->ulRunIndex = 0;

    /* ���ýڵ���뵽���ж����� */
    ulReturnVal = VppTimerGrpListAddNode(pstTempTimer);
    if(VPP_SUCCESS != ulReturnVal)
    {
        /* VPP_FREE(pstTempTimer); */
        /* Fix Review problem, Timer CB should be put to cache, it will be better */
        VppTimerGrpFreeTimer(&pstTempTimer);
        pstTempTimer = VPP_NULL_PTR;
        return ulReturnVal;
    }

    *ppstTimer = pstTempTimer;

    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpStop
 ��������  : ֹͣ��ʱ�����е�ĳ����ʱ��
 �������  : pTimerGrp    ��ʱ������ָ��
             ulTmSn       Ҫֹͣ����Զ�ʱ�������
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpStop
(
    IN  VPP_VOID*               pTimerGrp,
    IN  VPP_UINT32              ulTmSn
)
{
    VPP_TIMERGRP_ST*     pTempTimerGrp = VPP_NULL_PTR;
    PVPPTIMER*           ppTempTimer   = VPP_NULL_PTR;
    VPP_UINT32           ulReturnVal   = 0;
    VPP_INT              lockKey = 0;

    if(VPP_NULL_PTR == pTimerGrp)
    {
        return VPP_ERR_INPUTNULL;
    }

    pTempTimerGrp = (VPP_TIMERGRP_ST*)pTimerGrp;
    if(ulTmSn >= pTempTimerGrp->ulMaxNum)
    {
        return VPP_ERR_TIMERGRPSN;
    }

    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
        return VPP_ERR_LOCK;
    }
    ulReturnVal = VppTimerGrpGet(pTempTimerGrp, ulTmSn, &ppTempTimer);
    if((ulReturnVal != VPP_SUCCESS )||(VPP_NULL_PTR == *ppTempTimer))
    {
        if (VPP_SUCCESS != Vpp_Unlock(lockKey))
        {
            return VPP_ERR_UNLOCK;
        }
        return VPP_ERR_TMSNINVALUD;
    }

    /* �ö�ʱ���������� */
    if((*ppTempTimer)->ucTmState == VPP_TIMER_TICKING)
    {
        ulReturnVal = VppTimerStop(ppTempTimer);
        if (VPP_SUCCESS != ulReturnVal)
        {
            if (VPP_SUCCESS != Vpp_Unlock(lockKey))
            {
                return VPP_ERR_UNLOCK;
            }
            return ulReturnVal;
        }
    }

    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }
    return VPP_SUCCESS;
}


/*****************************************************************************
 �� �� ��  : VppTimerRelStop
 ��������  : ֹͣһ����Զ�ʱ��
 �������  : pTimerGrp    ��ʱ������ָ��
             ulTmSn       Ҫֹͣ����Զ�ʱ�������
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2007��9��6��
    ��    ��   : �º�ɽ 103208
    �޸�����   : ���ŵ�����ʱ���ӿ�

*****************************************************************************/
VPP_UINT32 VppTimerRelStop
(
    IN  VPP_VOID**   ppstTimer
)
{
    VPP_UINT32       ulReturnVal   = 0;
    VPP_INT          lockKey = 0;

    if(VPP_NULL_PTR == ppstTimer)
    {
        return VPP_ERR_INPUTNULL;
    }

    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
        return VPP_ERR_LOCK;
    }

    ulReturnVal = VppTimerStop((PVPPTIMER *)ppstTimer);

    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }

    return ulReturnVal;
}

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
)
{
    VPP_UINT32  ulReturnVal = 0;

    if(VPP_NULL_PTR == ppstTimer)
    {
        return VPP_ERR_INPUTNULL;
    }

    /*���ýڵ�����ж�����ɾ��*/
    ulReturnVal = VppTimerGrpListDeleteNode(*ppstTimer);
    if(VPP_SUCCESS != ulReturnVal)
    {
        return ulReturnVal;
    }

    ppstTimer = ppstTimer;
    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpReset
 ��������  : ���ö�ʱ���飬�ָ�����ʼ״̬
 �������  : pucTimeGrp    ��ʱ������ָ��
 �������  : ��
 �� �� ֵ  : ��ȷִ�з���VPP_SUCCESS�����򷵻�ֵ������Ĵ�����
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_UINT32 VppTimerGrpReset
(
    IN  VPP_VOID*               pTimerGrp
)
{
    VPP_TIMERGRP_ST    *pTempTimerGrp = (VPP_TIMERGRP_ST*)pTimerGrp;
    VPP_UINT32          ulRetValue;
    VPP_INT             lockKey = 0;

    if(VPP_NULL_PTR == pTimerGrp)
    {
        return VPP_ERR_INPUTNULL;
    }

    /* [SWED10833][2007-09-06][chenhongshan 103208]: add begin: �������� */
    if (VPP_SUCCESS != Vpp_Lock(&lockKey))
    {
        return VPP_ERR_LOCK;
    }
    /* [SWED10833][2007-09-06][chenhongshan 103208]: add end: �������� */

    /*����ʱ����Դ���е����ж�ʱ��״̬��Ϊ����̬*/
    ulRetValue = VppTimerGrpIterate(pTempTimerGrp, VppTimerGrpIterateFree);
    if(VPP_SUCCESS != ulRetValue)
    {
        /* [SWED10833][2007-09-06][chenhongshan 103208]: add begin: �������� */
        if (VPP_SUCCESS != Vpp_Unlock(lockKey))
        {
            return VPP_ERR_UNLOCK;
        }
        /* [SWED10833][2007-09-06][chenhongshan 103208]: add end: �������� */
        return ulRetValue;
    }

    /*������ж���*/
    g_stGlobal.stRunTimerList.ulCount = 0;
    if (g_stGlobal.stRunTimerList.pArray != VPP_NULL_PTR)
    {
        memset(g_stGlobal.stRunTimerList.pArray, 0, VPP_MAXRUNTIMER_NUM * sizeof(VPP_ADDRESS));
    }

    /* [SWED10833][2007-09-06][chenhongshan 103208]: add begin: �������� */
    if (VPP_SUCCESS != Vpp_Unlock(lockKey))
    {
        return VPP_ERR_UNLOCK;
    }
    /* [SWED10833][2007-09-06][chenhongshan 103208]: add end: �������� */

    return VPP_SUCCESS;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpTrigger
 ��������  : ɨ�趨ʱ���飬Ӧ��ģ��Ӧ����tick�¼�����ʱ���ñ�������
 �������  : ultick
 �������  : ��
 �� �� ֵ  : VPP_VOID
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��29��
    ��    ��   : ���컶 60015914
    �޸�����   : ����ɼ�

*****************************************************************************/
VPP_VOID VppTimerGrpTrigger
(
    IN  VPP_UINT32              ultick
)
{
    VPP_INT32       rc = 0 ; /*for PC_lint;  */
    VPP_INT         lockKey = 0;
    /* ��ȡ�� */
    if (VPP_SUCCESS != Vpp_Lock(&lockKey)) /* �����жϷ���ֵ���岻�� */
    {
        return;
    }

    while (g_stGlobal.stRunTimerList.ulCount != 0)
    {
        struct timeval now;
        struct timeval nextTime;
        PVPPTIMER      headTimer = (PVPPTIMER)g_stGlobal.stRunTimerList.pArray[1];

        /*ȡ���ж����е�ͷ�ڵ�Ļص�ʱ��*/
        nextTime.tv_sec = headTimer->stNextTime.tv_sec;
        nextTime.tv_usec = headTimer->stNextTime.tv_usec;

        Vpp_GetTime(&now);

        /* �ж��Ƿ�ʱ */
        if (
            (nextTime.tv_sec < now.tv_sec) ||
            ((nextTime.tv_sec == now.tv_sec) && (nextTime.tv_usec <= now.tv_usec))
            )
        {
            PTVppFuncTimeout pShouldExecute = headTimer->pfTimeout;
            VPP_UINT32 index = headTimer->ulTmIndex;
            VPP_UINT32 name = headTimer->ulTmName;

            /* ��ʱ��Ϊѭ����ʱ�� */
            if(VPP_TIMER_LOOP == headTimer->ucTmMode)
            {
                /* [SWED10833][2007-09-06][chenhongshan 103208]: add begin: ���·�װ������ʱ���ڲ��ӿ� */
                /*����VppTimerReset()�����ö�ʱ��*/
                rc = (VPP_INT32)VppTimerReset(headTimer->ppTimer); /* �����жϷ���ֵ���岻�� */
                /* [SWED10833][2007-09-06][chenhongshan 103208]: add end: ���·�װ������ʱ���ڲ��ӿ� */
            }
            else
            {
                /*����VppTimerStop(),ֹͣ�ö�ʱ��*/
                rc = (VPP_INT32)VppTimerStop(&headTimer); /* �����жϷ���ֵ���岻�� */
            }

            /* ���ûص�����                          */
            /* ע��: ��ʱû���ͷ���������û��ص���  */
            /*       ���������������������        */
            pShouldExecute(index, name);
        }
        else
        {
            break;
        }
    }

    /* �ͷ��� */
    rc = Vpp_Unlock(lockKey); /* �����жϷ���ֵ���岻�� */

    rc = rc; /*for PC_lint;  */
    ultick = ultick;
    return;
}

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
    OUT PVPPTIMER**             pppTimer
)
{
    VPP_TIMERGRP_UNIT_ST       *pTimerGrpUnit;

    if(pTimerGrp == VPP_NULL_PTR)
    {
        return VPP_ERR_INPUTNULL;
    }

    if(ulTmSn >= pTimerGrp->ulMaxNum)
    {
        return VPP_ERR_TIMERNUMS;
    }

    if((pppTimer == VPP_NULL_PTR)||(*pppTimer != VPP_NULL_PTR))
    {
        return VPP_ERR_INPUTNULL;
    }

    pTimerGrp = pTimerGrp;
    pTimerGrpUnit = pTimerGrp->pFirstTimerGrpUnit;
    while(pTimerGrpUnit != VPP_NULL_PTR)
    {
        if(ulTmSn < pTimerGrpUnit->ulMaxNum)
        {
            *pppTimer = (PVPPTIMER*)(&pTimerGrpUnit->pData[ulTmSn]);
            return VPP_SUCCESS;
        }
        else
        {
            ulTmSn -= pTimerGrpUnit->ulMaxNum;

            pTimerGrpUnit = pTimerGrpUnit->pNextUnit;
        }
    }

    return VPP_ERR_TMNODEINVALID;
}

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
)
{
    VPP_TIMERGRP_UNIT_ST       *pTimerGrpUnit;

    if(pTimerGrp == VPP_NULL_PTR)
    {
        return VPP_ERR_INPUTNULL;
    }

    if(ulTmSn >= pTimerGrp->ulMaxNum)
    {
        return VPP_ERR_TIMERNUMS;
    }

    if(pTimer == VPP_NULL_PTR)
    {
        return VPP_ERR_INPUTNULL;
    }

    pTimerGrp = pTimerGrp;
    pTimerGrpUnit = pTimerGrp->pFirstTimerGrpUnit;
    while(pTimerGrpUnit != VPP_NULL_PTR)
    {
        if(ulTmSn < pTimerGrpUnit->ulMaxNum)
        {
            pTimerGrpUnit->pData[ulTmSn] = (VPP_ADDRESS)pTimer;
            return VPP_SUCCESS;
        }
        else
        {
            ulTmSn -= pTimerGrpUnit->ulMaxNum;

            pTimerGrpUnit = pTimerGrpUnit->pNextUnit;
        }
    }

    return VPP_ERR_TMNODEINVALID;
}

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
)
{
    VPP_INT32 rc;

    if(ppTimer == VPP_NULL_PTR)
    {
        return ;
    }

    rc = (VPP_INT32)VppTimerStop(ppTimer);  /* �����жϷ���ֵ���岻�� */

    rc = rc; /*for PC_lint;  */
}

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
)
{
    if(ppTimer == VPP_NULL_PTR)
    {
        return ;
    }

    VPP_FREE(*ppTimer);
    *ppTimer = VPP_NULL_PTR;
}

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
)
{
    VPP_TIMERGRP_UNIT_ST       *pTimerGrpUnit;
    VPP_UINT32                  ulLoop;

    if((pTimerGrp == VPP_NULL_PTR)||(pfIterate == VPP_NULL_PTR))
    {
        return VPP_ERR_INPUTNULL;
    }

    pTimerGrpUnit = pTimerGrp->pFirstTimerGrpUnit;
    while(pTimerGrpUnit != VPP_NULL_PTR)
    {
        for(ulLoop = 0 ; ulLoop < pTimerGrpUnit->ulMaxNum; ulLoop ++)
        {
            if(pTimerGrpUnit->pData[ulLoop] != VPP_NULL_PTR)
            {
                pfIterate(((PVPPTIMER*)&pTimerGrpUnit->pData[ulLoop]));
            }
        }

        pTimerGrpUnit = pTimerGrpUnit->pNextUnit;
    }

    pTimerGrp = pTimerGrp;
    return VPP_SUCCESS;
}

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
)
{
    VPP_UINT32  ulIndex  = 0;
    VPP_ADDRESS *pArray  = VPP_NULL_PTR;

    if(VPP_NULL_PTR == pstTimerNode)
    {
        return VPP_ERR_INPUTNULL;
    }

    if (g_stGlobal.stRunTimerList.pArray == VPP_NULL_PTR)
    {
        g_stGlobal.stRunTimerList.pArray = (VPP_ADDRESS *)(VPP_VOID*)malloc(VPP_MAXRUNTIMER_NUM*sizeof(VPP_ADDRESS));
        if (g_stGlobal.stRunTimerList.pArray == VPP_NULL_PTR)
        {
            return VPP_ERR_MALLOCFAIL;
        }
        memset(g_stGlobal.stRunTimerList.pArray,0,VPP_MAXRUNTIMER_NUM*sizeof(VPP_ADDRESS));
    }
    /* �����ж�ʱ������Ϊ0 */
    if(0 == g_stGlobal.stRunTimerList.ulCount)
    {
        /*pstTimerNode�������ͷ*/
        g_stGlobal.stRunTimerList.pArray[1] = (VPP_ADDRESS)pstTimerNode;
        pstTimerNode->ulRunIndex = 1;
        pstTimerNode->ucTmState = VPP_TIMER_TICKING;

        /*���ж�ʱ��������1;*/
        g_stGlobal.stRunTimerList.ulCount++;
        return VPP_SUCCESS;
    }

/* BEGIN modify: [[SWED06479] [2006/8/1] [���컶 60015914]]
   �޸�ԭ��: ��1�����ڴ�Խ�� */
    if (g_stGlobal.stRunTimerList.ulCount >= VPP_MAXRUNTIMER_NUM - 1)
    {
        return VPP_ERR_RUNNINGTIMER;
    }
/* END   modify: [[SWED06479] [2006/8/1] [���컶 60015914]] */
    ulIndex = g_stGlobal.stRunTimerList.ulCount + 1;
    pArray = g_stGlobal.stRunTimerList.pArray;
    pArray[ulIndex] = (VPP_ADDRESS)pstTimerNode;/* �ȷŵ����һ�� */
    pstTimerNode->ulRunIndex = ulIndex;
    /*����������*/
    Vpp_AddToBinTree(pstTimerNode,ulIndex,pArray);

    /*�ö�ʱ��״̬��Ϊ��ʱ״̬;*/
    pstTimerNode->ucTmState = VPP_TIMER_TICKING;
    /*���ж�ʱ��������1*/
    g_stGlobal.stRunTimerList.ulCount++;

    return VPP_SUCCESS;
}

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
)
{
    PVPPTIMER*  ppTemp = VPP_NULL_PTR;
    PVPPTIMER   pstTempTNode1 = VPP_NULL_PTR;
    PVPPTIMER   pstTempTNode2 = VPP_NULL_PTR;
    VPP_UINT32  ulIndex  = 0;
    VPP_ADDRESS *pArray  = VPP_NULL_PTR;

    if(VPP_NULL_PTR == pstTimerNode)
    {
        return VPP_ERR_INPUTNULL;
    }

    if ((pstTimerNode->ulRunIndex == 0)
        || (pstTimerNode->ulRunIndex > g_stGlobal.stRunTimerList.ulCount))
    {
        return VPP_ERR_TMNODEINVALID;
    }
    /* �ö�ʱ����״̬Ϊ��ʱ״̬ */
    if (VPP_TIMER_TICKING == pstTimerNode->ucTmState)
    {
        ulIndex = pstTimerNode->ulRunIndex;
        pArray = g_stGlobal.stRunTimerList.pArray;

        /* while(1) */
        for(;;)
        {
            if (ulIndex*2 >= VPP_MAXRUNTIMER_NUM)
            {
                pstTempTNode1 = VPP_NULL_PTR;
                pstTempTNode2 = VPP_NULL_PTR;
            }
            else if ((ulIndex*2 + 1) >= VPP_MAXRUNTIMER_NUM)
            {
                pstTempTNode1 = (PVPPTIMER)pArray[ulIndex*2];
                pstTempTNode2 = VPP_NULL_PTR;
            }
            else
            {
                pstTempTNode1 = (PVPPTIMER)pArray[ulIndex*2];
                pstTempTNode2 = (PVPPTIMER)pArray[ulIndex*2 +1];
            }

            if (pstTempTNode1 == VPP_NULL_PTR)
            {/* �ӽڵ��Ϊ�գ������һ������ */
                if (ulIndex == g_stGlobal.stRunTimerList.ulCount)
                {/* �պ������һ�� */
                    pArray[g_stGlobal.stRunTimerList.ulCount] = 0;
                    break;
                }
                else
                {
                    Vpp_ExchangeValue(((PVPPTIMER )pArray[ulIndex])->ulRunIndex,((PVPPTIMER)pArray[g_stGlobal.stRunTimerList.ulCount])->ulRunIndex, VPP_UINT32);
                    Vpp_ExchangeValue(pArray[ulIndex],pArray[g_stGlobal.stRunTimerList.ulCount], VPP_ADDRESS);
                    pArray[g_stGlobal.stRunTimerList.ulCount] = 0;
                    /* �Ƚϵ�ǰ�ڵ��Ƿ���Ϲ��򣬴��ڸ��ڵ� */
                    Vpp_AddToBinTree((PVPPTIMER)pArray[ulIndex],ulIndex,pArray);
                    break;
                }
            }
            else if (pstTempTNode2 == VPP_NULL_PTR)
            {/* ���ӽڵ�Ϊ�� */
                Vpp_ExchangeValue(((PVPPTIMER)pArray[ulIndex])->ulRunIndex,((PVPPTIMER)pArray[ulIndex*2])->ulRunIndex, VPP_UINT32);
                Vpp_ExchangeValue(pArray[ulIndex],pArray[ulIndex*2], VPP_ADDRESS);
                pArray[g_stGlobal.stRunTimerList.ulCount] = 0;
                break;
            }
            else
            {/* �ӽڵ㶼��Ϊ�� */

                /* �������С���ӽڵ㽻�� */
                if (
                    (pstTempTNode1->stNextTime.tv_sec < pstTempTNode2->stNextTime.tv_sec) ||
                    ((pstTempTNode1->stNextTime.tv_sec == pstTempTNode2->stNextTime.tv_sec)
                    && (pstTempTNode1->stNextTime.tv_usec <= pstTempTNode2->stNextTime.tv_usec))
                    )/*  */
                {/* ���ӽڵ�ĳ�ʱʱ��С�ڵ������ӽڵ�ĳ�ʱʱ�� */
                    Vpp_ExchangeValue(((PVPPTIMER)pArray[ulIndex])->ulRunIndex, ((PVPPTIMER )pArray[ulIndex*2])->ulRunIndex, VPP_UINT32);
                    Vpp_ExchangeValue(pArray[ulIndex], pArray[ulIndex*2], VPP_ADDRESS);
                    ulIndex = ulIndex*2;
                }
                else
                {
                    Vpp_ExchangeValue(((PVPPTIMER )pArray[ulIndex])->ulRunIndex, ((PVPPTIMER)pArray[ulIndex*2 +1])->ulRunIndex, VPP_UINT32);
                    Vpp_ExchangeValue(pArray[ulIndex], pArray[ulIndex*2 +1], VPP_ADDRESS);
                    ulIndex = ulIndex*2 + 1;
                }
            }
        }

        /* �ͷŶ�ʱ���ڴ� */
        ppTemp = pstTimerNode->ppTimer;

        /* [[SWED12582][2008-12-17][chenhongshan]]  begin:�ͷŻ�������ʱ���ڴ�*/
        /* VPP_FREE(*ppTemp); */
        VppTimerGrpFreeTimer(ppTemp);
        /* [[SWED12582][2008-12-17][chenhongshan]]  end. */

        *ppTemp = VPP_NULL_PTR;

        /*���ж��ж�ʱ��������1*/
        g_stGlobal.stRunTimerList.ulCount--;
        if (g_stGlobal.stRunTimerList.ulCount == 0)
        {
            g_stGlobal.stRunTimerList.pArray[1] = VPP_NULL_PTR;
        }
        return VPP_SUCCESS;
    }

    pstTimerNode = pstTimerNode;
    return VPP_FAILURE;
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpAllocTimer
 ��������  : �ӻ�������ȡ�����е�һ���ڵ㣬���������ޣ���ֱ�������ڴ�
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
VPP_VOID VppTimerGrpAllocTimer(OUT PVPPTIMER  *pstTimer )
{
    /* ���������п��п��ƿ飬��ֱ��ʹ�ÿ��п飬��������¿��ƿ� */
    if (g_stGlobal.ulFreeCount > 0)
    {
        g_stGlobal.ulFreeCount--;
        *pstTimer = (g_stGlobal.ahTimerBuffer[g_stGlobal.ulFreeCount]);
    }
    else
    {
        /*lint -save -e826 */
        *pstTimer =(PVPPTIMER)malloc(sizeof(struct VPP_TIMERGRP_NODE_ST));
    }
}

/*****************************************************************************
 �� �� ��  : VppTimerGrpFreeTimer
 ��������  : ��һ����ʱ���Żػ������У�����������ֱ���ͷ��ڴ�
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
VPP_VOID VppTimerGrpFreeTimer(IN PVPPTIMER  *pstTimer )
{
    /* ��������δ�������ͷŵĿ��ƿ���ڻ������С�*/
    if (g_stGlobal.ulFreeCount < VPP_MAX_TIMEER_CACHE)
    {
        g_stGlobal.ahTimerBuffer[g_stGlobal.ulFreeCount] = *pstTimer;
        g_stGlobal.ulFreeCount++;
    }
    else
    {
        VPP_FREE(*pstTimer);
    }

    pstTimer = pstTimer;
}



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
VPP_INT32 Vpp_InitLock( void )
{
    VPP_INT32 nRet = VPP_FAILURE;

#ifdef VPP_OS_VER
#if ( VPP_OS_VER == VPP_WIN32 )
{
    InitializeCriticalSection( &VPP_CriticalSection );
    nRet = VPP_SUCCESS;
}
#elif ( VPP_OS_VER == VPP_SOLARIS_POSIX || VPP_OS_VER == VPP_AIX || VPP_OS_VER == VPP_HP)
{
    pthread_mutexattr_t  attr;
    nRet = pthread_mutexattr_init(&attr);
    if (nRet != 0)
        return nRet;
    nRet = pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
    if (nRet != 0)
        return nRet;
    nRet = pthread_mutex_init(&VPP_mutex, &attr);
    if (nRet != 0)
        return nRet;
}
#elif ( VPP_OS_VER == VPP_LINUX_POSIX)
{
    pthread_mutexattr_t  attr;
    nRet = pthread_mutexattr_init(&attr);
    if (nRet != 0)
        return nRet;
    nRet = pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE_NP);
    if (nRet != 0)
        return nRet;
    nRet = pthread_mutex_init(&VPP_mutex, &attr);
    if (nRet != 0)
        return nRet;
}
#elif (VPP_OS_VER == VPP_VXWORKS)
    nRet = VPP_SUCCESS;
#endif /* VPP_OS_VER */
#endif /* VPP_OS_VER */

    return nRet;
}

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
VPP_INT32 Vpp_Lock(VPP_INT *pLockKey)
{
    VPP_INT32 nRet = VPP_FAILURE;

    pLockKey = pLockKey;
#ifdef VPP_OS_VER
#if ( VPP_OS_VER == VPP_WIN32 )
{
    EnterCriticalSection( &VPP_CriticalSection );
    nRet = VPP_SUCCESS;
}
#elif ( VPP_OS_VER == VPP_SOLARIS_POSIX || VPP_OS_VER == VPP_AIX || VPP_OS_VER == VPP_HP || VPP_OS_VER == VPP_LINUX_POSIX)
{
    nRet = pthread_mutex_lock(&VPP_mutex);
}
#elif (VPP_OS_VER == VPP_VXWORKS)
{
    *pLockKey = intLock();
    nRet = VPP_SUCCESS;
}
#endif /* VPP_OS_VER */
#endif /* VPP_OS_VER */

    return nRet;
}

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
VPP_INT32 Vpp_Unlock(VPP_INT lockKey)
{
    VPP_INT32 nRet = VPP_FAILURE;

    lockKey = lockKey;
#ifdef VPP_OS_VER
#if ( VPP_OS_VER == VPP_WIN32 )
{
    LeaveCriticalSection ( &VPP_CriticalSection );
    nRet = VPP_SUCCESS;
}
#elif ( VPP_OS_VER == VPP_SOLARIS_POSIX || VPP_OS_VER == VPP_AIX || VPP_OS_VER == VPP_HP || VPP_OS_VER == VPP_LINUX_POSIX)
{
    nRet = pthread_mutex_unlock(&VPP_mutex);

}
#elif (VPP_OS_VER == VPP_VXWORKS)
{
    intUnlock(lockKey);
    nRet = VPP_SUCCESS;
}
#endif /* VPP_OS_VER */
#endif /* VPP_OS_VER ==*/

    return nRet;
}

#ifdef VPP_OS_DOPRA
typedef struct TIME_STRU
{
    VPP_UINT8 ucHour;  /* ʱ */
    VPP_UINT8 ucMinute;/* �� */
    VPP_UINT8 ucSecond;/* �� */
    VPP_UINT8 ucPadding;
} TIME_T;

typedef struct DATE_STRU
{
    VPP_UINT16 uwYear; /* �� */
    VPP_UINT8 ucMonth; /* �� */
    VPP_UINT8 ucDate;  /* �� */
} DATE_T;
#endif

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
VPP_VOID Vpp_GetTime(struct timeval *pstTime)
{
    #if ( VPP_OS_VER == VPP_WIN32 )
    {
        /* FIX: GetTickCount() ����32bit�ĺ�������*/
        /* ϵͳ����49.7�����������             */
        VPP_UINT32 millis = GetTickCount();
        pstTime->tv_sec = (long)(millis / 1000);
        pstTime->tv_usec =  (millis % 1000) * 1000;
    }
    #elif ( VPP_OS_VER == VPP_SOLARIS_POSIX || VPP_OS_VER == VPP_AIX || VPP_OS_VER == VPP_HP || VPP_OS_VER == VPP_LINUX_POSIX)
    {
        VPP_UINT32    ulValue = 0;

        #ifdef  VPP_OS_DOPRA
        {
            DATE_T        stDate;
            TIME_T        stTime;
            extern VPP_UINT32 VOS_TmSince1970( VPP_UINT32 *pulTimeInSecHigh,
                                                     VPP_UINT32 *pulTimeInSecLow );
            extern  VOS_TmGet( DATE_T     *pDate,
                                 TIME_T     *pTime,
                                 VPP_UINT32 *pulMillSecs );

            VOS_TmGet(&stDate, &stTime,&ulValue);
            pstTime->tv_usec = ulValue*1000;
            VOS_TmSince1970(&ulValue, (VPP_UINT32*)&pstTime->tv_sec);
        }
        #else
        {
            /* get time since 1970 in microsec */
            gettimeofday(pstTime, 0);
        }
        #endif


    }
    #elif (VPP_OS_VER == VPP_VXWORKS)
    {
        clock_gettime(0, (struct timespec *)pstTime);
        pstTime->tv_usec /= 1000;
    }
    #endif
}


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
VPP_VOID Vpp_AddToBinTree(PVPPTIMER  pstTimerNode, VPP_UINT32 ulIndex,VPP_ADDRESS *pTreeArray)
{
    PVPPTIMER   pstTempTNode = VPP_NULL_PTR;

    pstTempTNode = (PVPPTIMER)pTreeArray[ulIndex/2];
    for(;
        pstTempTNode != VPP_NULL_PTR;)
    {
        pstTempTNode = (PVPPTIMER)pTreeArray[ulIndex/2];
        /* ����ڵ�ĳ�ʱʱ��С�ڵ�ǰ�ڵ�ĳ�ʱʱ�� */
        if (
            (pstTimerNode->stNextTime.tv_sec < pstTempTNode->stNextTime.tv_sec) ||
            ((pstTimerNode->stNextTime.tv_sec == pstTempTNode->stNextTime.tv_sec)
            && (pstTimerNode->stNextTime.tv_usec < pstTempTNode->stNextTime.tv_usec))
            )/*  */
        {
            Vpp_ExchangeValue(pTreeArray[ulIndex/2], pTreeArray[ulIndex], VPP_ADDRESS);
            Vpp_ExchangeValue(((PVPPTIMER )pTreeArray[ulIndex/2])->ulRunIndex, ((PVPPTIMER)pTreeArray[ulIndex])->ulRunIndex, VPP_UINT32);
            ulIndex = ulIndex/2;
            if (ulIndex == 1)
            {/* �����ڵ��� */
                break;
            }
        }
        else
        {
            break;
        }
    }
    pstTimerNode = pstTimerNode;

}

/*****************************************************************************
 �� �� ��  : VppTimerGrpDebugControl
 ��������  : ���Կ��ƽӿڣ��ڲ�����ʹ�ã�����ͷ�ļ��г��֡�
 �������  : IN VPP_UINT32 ulCommand,����������
             IN VPP_UINT8 *pucParam, ��������ִ����Ҫ�Ĳ���
 �������  : ��
 �� �� ֵ  : VPP_VOID
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2008��12��17��
    ��    ��   : �º�ɽ 00103208
    �޸�����   : �����ɺ���

*****************************************************************************/
#ifdef VPP_DEBUG
VPP_VOID VppTimerGrpDebugControl
(
    IN VPP_UINT32 ulCommand,
    IN VPP_UINT8 *pucParam
)
{
    switch(ulCommand)
    {
        case VPP_DEBUG_HELP:
            VPP_LOG("\r\nVPP TIMERGRP Support Following Debug Command:\r\n");
            VPP_LOG("\t [0] show current free timer count\r\n");
            break;

        case VPP_DEBUG_TIMER_LIST:
            VPP_LOG("\t FreeTimerCount = %d\r\n", g_stGlobal.ulFreeCount);
            break;

        default:
            break;
    }
}
#endif

/*****************************************************************************
 �� �� ��  : VppTimerGrpGetVersion
 ��������  : ��ȡ�汾��
 �������  : VPP_VOID
 �������  : ��
 �� �� ֵ  : ��ʱ���İ汾��
 ���ú���  :
 ��������  :

 �޸���ʷ      :
  1.��    ��   : 2006��7��31��
    ��    ��   : ���컶 60015914
    �޸�����   : �����ɺ���

*****************************************************************************/
const VPP_CHAR *VppTimerGrpGetVersion(VPP_VOID)
{
#ifdef VPP_DEBUG
    return "VPP TimerGrp Library debug version 1.3.0.13\r\n\
            Copyright(C) 2003 - 2008 Huawei Technologies Co., Ltd.All rights reserved.\r\n";
#else
    return "VPP TimerGrp Library release version 1.3.0.13\r\n\
            Copyright(C) 2003 - 2008 Huawei Technologies Co., Ltd.All rights reserved.\r\n";
#endif
}

#ifdef  __cplusplus
}
#endif
