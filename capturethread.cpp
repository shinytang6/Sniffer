#include "capturethread.h"
#include "protocoltype.h"
#include <QDebug>
#include <winsock2.h>

CaptureThread::CaptureThread(){

}

void CaptureThread::run(){

    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    sniffer->openNetDev(6);
    sniffer->setDevsFilter("arp");
    sniffer->captureOnce();

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = sniffer->header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    sniffer->analyze_frame(sniffer->pkt_data);
//    ethhdr *eth = (ethhdr*)(sniffer->pkt_data);
//    switch (ntohs(eth->type)) {
//        case 0x0806 :
//            qDebug() << "arp"<<ntohs(eth->type)<<endl;
//            break;
//        case 0x0800 :
//            qDebug() << "ipv4"<<ntohs(eth->type)<<endl;
//            break;
//        case 0x86dd :
//            qDebug() <<"ipv6" <<ntohs(eth->type)<<endl;
//            break;
//    }

//    qDebug() <<  eth->type<<endl;
//    // 获得 IP 协议头
//    iphdr *ih = (iphdr *)(sniffer->pkt_data+ 14);
//    u_int ip_len = (ih->ver_ihl & 0xf) * 4;
//    qDebug() << timestr << "," << local_tv_sec << "len: "<<ip_len ;

}
