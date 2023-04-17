/*
 ******************************************************************************
 ��Ȩ���� (C), 2001-2011, ��Ϊ�������޹�˾
 ******************************************************************************
  �� �� ��   : egnapitype.h
  �� �� ��   : ����
  ��    ��   : EGN_TEAM
  ��������   : 2008��7��18��
  ����޸�   :
  ��������   : EGN�������Ͷ���
  �����б�   :
  �޸���ʷ   :
  1.��    ��   : 2008��7��18��
    ��    ��   : EGN_TEAM
    �޸�����   : �����ļ�

******************************************************************************/
/**@file  egnapitype.h
  *    EGN�������Ͷ���
*******************************************************/

#ifndef __EGN_API_TYPE_H__
#define __EGN_API_TYPE_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

/**
 * @defgroup common  ������ϵͳ�����ϵͳ����API
 */

/** ���庯�������еİ������ţ� ����ʱ��Ч */
#ifndef IN
#define IN      /*   input parameter */
#endif

#ifndef OUT
#define OUT     /*   output parameter */
#endif

#ifndef INOUT
#define INOUT   /*   input and output parameter */
#endif

/* ���û������Ͷ��� */
typedef signed char    EGN_INT8;
typedef unsigned char  EGN_UINT8;
typedef char           EGN_CHAR;
typedef unsigned char  EGN_UCHAR;

typedef signed short   EGN_INT16;
typedef unsigned short EGN_UINT16;

typedef signed int     EGN_INT32;
typedef unsigned int   EGN_UINT32;
typedef EGN_UINT32     EGN_BOOL;

typedef signed long    EGN_LONG;
typedef unsigned long  EGN_ULONG;

#define EGN_VOID       void    /*   void */
#define EGN_ZERO       0       /*   The number 0 */

/** ���ش����� */
#define EGN_RET_ERR(_phase, _ret) return((_ret)|(((__LINE__) >> 1) << 12)|__FILE_ID__|(_phase))

/** ���طǴ����� */
#define EGN_RET_VAL(_code) return(_code)

/** ���÷���ֵ */
#define EGN_RET_SET(_ret, _phase) ((_ret)|(((__LINE__) >> 1) << 12)|__FILE_ID__|(_phase))

/** û�з���ֵ */
#define EGN_RET_VOID return

/** ���ش����� */
#define EGN_RET_ERR_EXT(_ret)  EGN_RET_ERR(0, (_ret))

/** ȡ�ô����� */
#define EGN_RET_GETVAL(_ret) ((_ret) & 0xFF)

/* ���û����궨�� */
#define EGN_EMPTY_ARRAY    {0}                  /* ������ */
#define EGN_NULL_PTR       (EGN_VOID *)0x0L     /* ��ָ���ֵ */
#define EGN_INVALID_UINT8  0xFF                 /* �����ж� �޷����ַ����͵�����ֵ */
#define EGN_INVALID_UINT16 0xFFFF               /* �����ж� �޷��Ŷ����͵�����ֵ */
#define EGN_MAX_UINT32     0xFFFFFFFF           /* �����ж� �޷������͵�����ֵ */
#define EGN_INVALID_UINT32 EGN_MAX_UINT32       /* �����ж� �޷������͵�����ֵ */

#define EGN_EN_INVALID     (-1)                 /* �����ж�ö�ٵĿ�ʼֵ */
#define EGN_EN_BUTT        0x7FFFFFFFU          /* �����ж�ö�ٵĽ���ֵ */

#define EGN_FALSE          0                    /* ����ֵ:Ϊ�� */
#define EGN_TRUE           1                    /* ����ֵ:Ϊ�� */

/** MemCp��� */
typedef  EGN_VOID*    EgnMemCpHdl;

#define EGN_CONST const     /* ����˵�� */

#define EGN_OPER_SET 0      /* ͳ�Ʋ��� ��λ */
#define EGN_OPER_ADD 1      /* ͳ�Ʋ��� �� */
#define EGN_OPER_DEL 2      /* ͳ�Ʋ��� �� */

#define EGN_DYNAMIC  0       /* ��̬�ڴ������ */
#define EGN_STATIC   1       /* ��̬�ڴ������ */

#define EGN_CMP_EQUAL   0    /* �ȽϽ��:��� */
#define EGN_CMP_LOWER (-1)   /* �ȽϽ��:С�� */
#define EGN_CMP_BIGGER  1    /* �ȽϽ��:���� */

#define EGN_UNIT_NONE    0   /* �޵�λ */
#define EGN_UNIT_TIME_S  1   /* ʱ�䵥λ�� */
#define EGN_UNIT_TIME_M  2   /* ʱ�䵥λ�� */
#define EGN_UNIT_TIME_MS 3   /* ʱ�䵥λ���� */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __EGN_API_TYPE_H__ */

