#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H
#include <QThread.h>
#include <QTreeView>
#include "sniffer.h"

class CaptureThread : public QThread
{
    Q_OBJECT
public:
    CaptureThread();
    Sniffer *sniffer;
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    int devNum;
    bool isStop;
    int count;
    bool loadFile;
    bool saveFile;
    bool loadDevs;
    QString filter;
    QString tempFile;

    QList <QString> info_frame_bytes_List;
    QList <QString> info_frame_Eth_Hdr_List;
    QList <QString> info_frame_Ip_Hdr_List;
    QList <QString> info_frame_Trans_Layer_List;

    QString frame_proto_ipHdr_str = "";
    QString info_frame_bytes = "";
    QString info_frame_bytes_child = "";
    QString info_frame_brief_protocol = "";
    QString info_frame_Eth_Hdr = "";
    QString info_frame_Eth_Hdr_child = "";

    QString info_frame_Ip_Hdr = "";
    QString info_frame_Ip_Hdr_child = "";
    QString info_frame_ip_brief_protocol = "";

    QString info_transport_Layer = "";
    QString info_transport_Layer_child = "";
protected:
    void run();
signals:
    void  sendData(QString str1,QString str2,QString str3,QString str4,QString str5);
    void  sendDetail(QList<QString> strList1,QList<QString> strList2,QList<QString> strList3,QList<QString> strList4);
    void sendDevs(pcap_if_t *alldevs);

};

#endif // CAPTURETHREAD_H
