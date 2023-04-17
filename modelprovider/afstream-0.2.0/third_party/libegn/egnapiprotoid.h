/*
******************************************************************************
��Ȩ���� (C), 2008-2009, ��Ϊ�������޹�˾
******************************************************************************
�� �� ��   : egnapiprotoid.h
�� �� ��   : ����
��    ��   : EGN_TEAM
��������   : 2009��05��22��
����޸�   :
��������   : EGN Э��ID
�����б�   :
�޸���ʷ   :
1.��    ��   : 2009��05��22��
��    ��   : EGN_TEAM
�޸�����   : �����ļ�

******************************************************************************/
/**@file  egnapiprotoid.h
  *    EGNЭ��IDͷ�ļ�
*******************************************************/

#ifndef __EGN_PROTO_ID_H__
#define __EGN_PROTO_ID_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#define EGN_CLASS_ID_MASK      (0xFF000000)                         /* ClassId���� */

/*ENUM< Э��ClassID���� >*/
typedef enum _EGN_CLASS_ID_EN
{
    EGN_CLASS_ID_BEGIN                      = EGN_EN_INVALID,
    EGN_CLASS_ID_P2P                        = 0x01,                 /* P2P������ */
    EGN_CLASS_ID_IM                         = 0x02,                 /* ��ʱͨѶ�� */
    EGN_CLASS_ID_VOIP                       = 0x03,                 /* VOIP�� */
    EGN_CLASS_ID_WEB_BROWSING               = 0x04,                 /* ��������� */
    EGN_CLASS_ID_GAME                       = 0x05,                 /* ��Ϸ�� */
    EGN_CLASS_ID_STREAMING                  = 0x06,                 /* STREAMING�� */
    EGN_CLASS_ID_ATTACK                     = 0x07,                 /* ������ */
    EGN_CLASS_ID_DATABASE                   = 0x08,                 /* ���ݿ��� */
    EGN_CLASS_ID_EMAIL                      = 0x09,                 /* �����ʼ��� */
    EGN_CLASS_ID_FILE_ACCESS                = 0x0A,                 /* �ļ���ȡ�� */
    EGN_CLASS_ID_NETWORK_ADMIN              = 0x0B,                 /* ��������� */
    EGN_CLASS_ID_NETWORK_STORAGE            = 0x0C,                 /* ����洢�� */
    EGN_CLASS_ID_NEWS_GROUP                 = 0x0D,                 /* ����Ⱥ���� */
    EGN_CLASS_ID_REMOTE_CONNECTIVITY        = 0x0E,                 /* Զ�������� */
    EGN_CLASS_ID_STOCK                      = 0x0F,                 /* ��Ʊ�� */
    EGN_CLASS_ID_TUNNELLING                 = 0x10,                 /* ͨ���� */
    EGN_CLASS_ID_OTHER                      = 0x11,                 /* ������ */
    EGN_CLASS_ID_END,

    EGN_CLASS_ID_BOTTOM = EGN_EN_BUTT
}EGN_CLASS_ID_EN;

/*ENUM< Э��AppID���� >*/
typedef enum _EGN_APP_ID_EN
{
    EGN_APP_ID_BEGIN                      = EGN_EN_INVALID,
    EGN_APP_ID_END,

    EGN_APP_ID_BOTTOM = EGN_EN_BUTT

}EGN_APP_ID_EN;

/*ENUM< Э��ProtoID���� >*/
typedef enum _EGN_PROTO_ID_EN
{
    EGN_PROTO_ID_BEGIN                      = EGN_EN_INVALID,

    EGN_PROTO_ID_INVALID                    = 0x00000000,

    /** DNS���Э��ID */
    EGN_PROTO_ID_DNS                        = 0x0000004F,       /* DNSЭ��ID */
    EGN_PROTO_ID_MDNS                       = 0x00000108,       /* MDNSЭ��ID */

    /** RTP���Э��ID */
    EGN_PROTO_ID_RTP                        = 0x000000F9,       /* RTPЭ��ID */
    EGN_PROTO_ID_RTCP                       = 0x000000FA,       /* RTCPЭ��ID */

    /** UUCall���Э��ID */
    EGN_PROTO_ID_UUCALL_PCCALL              = 0x000000AE,       /* UUCallЭ��PCCALL ID */
    EGN_PROTO_ID_UUCALL_TRANSFER            = 0x000000AD,       /* UUCallЭ��TRANSFER ID */

    /** GoogleTalk���Э��ID */
    EGN_PROTO_ID_GTALK_CONTROL              = 0x00000028,       /* GoogleTalkЭ�������ID */
    EGN_PROTO_ID_GTALK_DATA                 = 0x00000029,       /* GoogleTalkЭ��������ID */

    /** BT���Э��ID */
    EGN_PROTO_ID_BT_TRACKER                 = 0x0000000D,       /* BTЭ��TRACKER ID */
    EGN_PROTO_ID_BT_REG                     = 0x00000013,       /* BTЭ��REG ID */
    EGN_PROTO_ID_BT_LOGIN                   = 0x00000014,       /* BTЭ��LOGIN ID */
    EGN_PROTO_ID_BT_TRACKER_UDP             = 0x0000000C,       /* BTЭ��TRACKER_UDP ID */
    EGN_PROTO_ID_BT_DHT                     = 0x0000000E,       /* BTЭ��DHT ID */
    EGN_PROTO_ID_BT_DATA_TCP                = 0x0000000B,       /* BTЭ��DATA_TCP ID */
    EGN_PROTO_ID_BT_DATA_UDP                = 0x00000010,       /* BTЭ��DATA_UDP ID */
    EGN_PROTO_ID_BT_DATA_TCP_ENCREPT        = 0x00000012,       /* BTЭ��DATA_TCP_ENCREPT ID */

    /** RTSP���Э��ID */
    EGN_PROTO_ID_RTSP_CONTROL               = 0x00000045,       /* RTSPЭ��CONTROL ID */
    EGN_PROTO_ID_RTSP_DATA_RTP              = 0x00000046,       /* RTSPЭ��DATA_RTP ID */
    EGN_PROTO_ID_RTSP_DATA_RTCP             = 0x00000047,       /* RTSPЭ��DATA_RTCP ID */

    /** HTTP���Э��ID */
    EGN_PROTO_ID_HTTP                       = 0x0000004E,       /* HTTPЭ��HTTP ID */
    EGN_PROTO_ID_HTTP_CMCC                  = 1410,             /* HTTPЭ��HTTP_CMCC ID */

    /** FTP���Э��ID */
    EGN_PROTO_ID_FTP_CONTROL                = 0x0000004D,       /* FTPЭ��CONTROL ID */
    EGN_PROTO_ID_FTP_DATA                   = 0x0000004C,       /* FTPЭ��DATA ID */

    /** TFTP���Э��ID */
    EGN_PROTO_ID_TFTP_CONTROL               = 0x00000061,       /* TFTPЭ��CONTROL ID */
    EGN_PROTO_ID_TFTP_DATA                  = 0x00000062,       /* TFTPЭ��DATA ID */

    /** eDonkey���Э��ID */
    EGN_PROTO_ID_EDONKEY_CONTROL_TCP        = 0x00000017,       /* eDonkeyЭ��CONTROL_TCP ID */
    EGN_PROTO_ID_EDONKEY_CONTROL_UDP        = 0x00000018,       /* eDonkeyЭ��CONTROL_UDP ID */
    EGN_PROTO_ID_EDONKEY_DATA_TCP           = 0x00000019,       /* eDonkeyЭ��DATA_TCP ID */
    EGN_PROTO_ID_EDONKEY_DATA_UDP           = 0x0000001A,       /* eDonkeyЭ��DATA_UDP ID */

    /** emule����Э��ID */
    EGN_PROTO_ID_EMULE_ENCRYPTED            = 0x0000001B,       /* emuleЭ��ENCRYPTED ID */

    /** THUNDERЭ��ID */
    EGN_PROTO_ID_THUNDER                    = 0x0000006A,       /* THUNDERЭ��ID */

    /** MMS���Э��ID */
    EGN_PROTO_ID_MMS_CONTROL_DATA           = 0x00000050,       /* MMSЭ��CONTROL_DATA ID */
    EGN_PROTO_ID_MMS_DATA_TCP               = 0x00000051,       /* MMSЭ��DATA_TCP ID */
    EGN_PROTO_ID_MMS_DATA_UDP               = 0x00000052,       /* MMSЭ��DATA_UDP ID */

    /** YahooMSG���Э��ID */
    EGN_PROTO_ID_YAHOOMSG_CONTROL           = 0x0000003C,       /* YahooMSGЭ��CONTROL ID */
    EGN_PROTO_ID_YAHOOMSG_DATA_TRANSFER     = 0x0000003D,       /* YahooMSGЭ��DATA_TRANSFER ID */
    EGN_PROTO_ID_YAHOOMSG_AUDIO_DATA        = 0x00000040,       /* YahooMSGЭ��AUDIO_DATA ID */
    EGN_PROTO_ID_YAHOOMSG_AUDIO_CONTROL     = 0x0000003F,       /* YahooMSGЭ��AUDIO_CONTROL ID */

    /** MSN���Э��ID */
    EGN_PROTO_ID_MSN_OTHER                  = 0x00000034,       /* MSNЭ��OTHER ID */
    EGN_PROTO_ID_MSN_CONTORL                = 0x00000032,       /* MSNЭ��CONTORL ID */
    EGN_PROTO_ID_MSN_AUDIO_RTP              = 0x0000002F,       /* MSNЭ��AUDIO_RTP ID */
    EGN_PROTO_ID_MSN_VIDEO_RTP              = 0x00000031,       /* MSNЭ��VIDEO_RTP ID */
    EGN_PROTO_ID_MSN_TRANSFER_DATA          = 0x00000030,       /* MSNЭ��TRANSFER_DATA ID */
    EGN_PROTO_ID_MSN_SIP                    = 0x00000037,       /* MSNЭ��SIP ID */
    EGN_PROTO_ID_MSN_AUDIO_RTCP             = 0x00000039,       /* MSNЭ��AUDIO_RTCP ID */
    EGN_PROTO_ID_MSN_VIDEO_RTCP             = 0x00000038,       /* MSNЭ��VIDEO_RTCP ID */

    /** SKYPE���Э��ID */
    EGN_PROTO_ID_SKYPE_HTTP                 = 0x00000007,       /* SKYPEЭ��HTTP ID */
    EGN_PROTO_ID_SKYPE_IM                   = 0x00000004,       /* SKYPEЭ��IM ID */
    EGN_PROTO_ID_SKYPE_LOGIN                = 0x00000006,       /* SKYPEЭ��LOGIN ID */
    EGN_PROTO_ID_SKYPE_PCTOPHONE            = 0x00000005,       /* SKYPEЭ��PCTOPHONE ID */

    /** IMAP4���Э��ID */
    EGN_PROTO_ID_IMAP4                      = 0x0000004A,       /* IMAP4Э��ID */

    /** SIP��ص�Э��ID */
    EGN_PROTO_ID_SIP                        = 0x000000AF,       /* SIPЭ��ID */

    /** QVOD���Э��ID */
    EGN_PROTO_ID_QVOD_CONTROL               = 0x000000A7,       /* QVODЭ��CONTROL ID */
    EGN_PROTO_ID_QVOD_DATA                  = 0x000000A9,       /* QVODЭ��DATA ID */

    /** WAP1���Э��ID */
    EGN_PROTO_ID_WAP1_CONN                  = 0x0000005C,       /* WAP1Э��CONN ID */
    EGN_PROTO_ID_WAP1_CONNLESS              = 0x0000005D,       /* WAP1Э��CONNLESS ID */

    /** QingYL_UDPЭ���� */
    EGN_PROTO_ID_QINGYL_UDP                 = 0x00000098,       /* QingYL_UDPЭ��ID */

    /** PPFILMЭ���� */
    EGN_PROTO_ID_PPFILM                     = 0x0000008C,       /* PPFILMЭ��ID */

    /** RTSP_RDTЭ���� */
    EGN_PROTO_ID_RTSP_RDT                   = 0x00000048,       /* RTSP_RDTЭ��ID */

    /** SipgateЭ���� */
    EGN_PROTO_ID_SIPGATE_CONTORL            = 0x000000DF,       /* SipgateЭ��CONTORL ID */
    EGN_PROTO_ID_SIPGATE_AUDIO              = 0x000000E0,       /* SipgateЭ��AUDIO ID */

    /** PPVAЭ���� */
    EGN_PROTO_ID_PPVA                       = 0x00000069,       /* PPVAЭ��ID */

    /** SOPCASTЭ���� */
    EGN_PROTO_ID_SOPCAST                    = 0x0000008A,       /* SOPCASTЭ��ID */

    /** FlashGetЭ���� */
    EGN_PROTO_ID_FLASHGET                   = 0x0000008F,       /* FlashGetЭ��ID */

    /** SocksЭ���� */
    EGN_PROTO_ID_SOCKS5_UDP_ASSOCIATE       = 0x000000FC,       /* SocksЭ��SOCKS5_UDP_ASSOCIATE ID */
    EGN_PROTO_ID_SOCKS5_UDP                 = 0x000000FD,       /* SocksЭ��SOCKS5_UDP ID */
    EGN_PROTO_ID_SOCKS5_TCP                 = 0x000000FB,       /* SocksЭ��SOCKS5_TCP ID */
    EGN_PROTO_ID_SOCKS4                     = 0x000000FE,       /* SocksЭ��SOCKS4 ID */
    EGN_PROTO_ID_SOCKS4A                    = 0x000000FF,       /* SocksЭ��SOCKS4A ID */

    /** ZOIPERЭ���� */
    EGN_PROTO_ID_ZOIPER_SIP                 = 0x00000109,       /* ZOIPERЭ��ZOIPER_SIP ID */

    /** IAX2Э���� */
    EGN_PROTO_ID_IAX2                       = 0x000000E7,       /* IAX2Ӳ���� */

    /** ARES���Э��ID */
    EGN_PROTO_ID_ARES_DOWNLOAD_DATA         = 0x00000150,       /* ARESЭ��DOWNLOAD_DATA ID */

    /** SSL���Э��ID */
    EGN_PROTO_ID_SSL                        = 0x00000201,       /* SSLӲ���� */

    /** H323���Э��ID */
    EGN_PROTO_ID_H323_H225_SIGNAL           = 0x000000ED,       /* H323Э��H225_SIGNAL ID */
    EGN_PROTO_ID_H323_H245_CONTROL          = 0x000000EE,       /* H323Э��H245_CONTROL ID */
    EGN_PROTO_ID_H323_MEDIA                 = 0x000000EF,       /* H323Э��MEDIA ID */
    EGN_PROTO_ID_H323_MEDIA_AUDIO           = 0x000000F0,       /* H323Э��MEDIA_AUDIO ID */
    EGN_PROTO_ID_H323_MEDIA_VIDEO           = 0x000000F1,       /* H323Э��MEDIA_VIDEO ID */

    /** RTMP���Э��ID */
    EGN_PROTO_ID_RTMP                       = 0x00000241,       /* RTMPӲ���� */

    /** Icecast���Э��ID */
    EGN_PROTO_ID_ICECAST                    = 0x0000025E,       /* IcecastӲ���� */
    EGN_PROTO_ID_SHOUTCAST                  = 0x0000025F,       /* IcecastЭ��SHOUTCAST ID */

    /** FTPS���Э��ID */
    EGN_PROTO_ID_FTPS_CONTROL               = 0x000002D1,       /* FTPSЭ��CONTROL ID */
    EGN_PROTO_ID_FTPS_DATA                  = 0x000002D2,       /* FTPSЭ��DATA ID */

    /** Citrix���Э��ID */
    EGN_PROTO_ID_CITRIX_SSL                 = 0x000002EA,       /* CitrixЭ��SSL ID */
    EGN_PROTO_ID_HTTPS                      = 0x000001AE,       /* CitrixЭ��HTTPS ID */

    /** VbuzzerЭ�� */
    EGN_PROTO_ID_VBUZZER_SSL                = 0x000002DC,       /* VbuzzerЭ��SSL ID */

    /** Nimbuzz���Э��ID */
    EGN_PROTO_ID_NIMBUZZ_CONTROL            = 0x000002DD,       /* NimbuzzЭ��CONTROL ID */
    EGN_PROTO_ID_NIMBUZZ_AUDIO_DATA         = 0x000002E6,       /* NimbuzzЭ��DATA ID */

    /** Globe7���Э��ID */
    EGN_PROTO_ID_GLOBE7_CONTROL             = 0x00000165,       /* Globe7Э��CONTROL ID */
    EGN_PROTO_ID_GLOBE7_DATA                = 0x00000164,       /* Globe7Э��DATA ID */

    /** Alicall���Э��ID */
    EGN_PROTO_ID_ALICALL_CONTROL            = 0x000000C4,       /* AlicallЭ��CONTROL ID */
    EGN_PROTO_ID_ALICALL_DATA               = 0x000002F8,       /* AlicallЭ��DATA ID */

    /** Net2Phone���Э��ID */
    EGN_PROTO_ID_NET2PHONE_CONTROL          = 0x000002E3,       /* Net2PhoneЭ��CONTROL ID */
    EGN_PROTO_ID_NET2PHONE_DATA             = 0x000002F7,       /* Net2PhoneЭ��DATA ID */

    /** BlackBerry */
    EGN_PROTO_ID_BLACKBERRY_MSG             =   0x000002E9,  /* Blackberry message */
    EGN_PROTO_ID_BLACKBERRY_MALI_OUT        =   0x000002E8,  /* Blackberry mai */
    EGN_PROTO_ID_BLACKBERRY_BROWSING        =   0x000002E7,  /* Blackberry browsing */

    EGN_PROTO_ID_END,

    EGN_PROTO_ID_BOTTOM = EGN_EN_BUTT
}EGN_PROTO_ID_EN;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __EGN_PROTO_ID_H__ */

