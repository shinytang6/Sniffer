#include "capturethread.h"
#include "protocoltype.h"
#include <QDebug>

CaptureThread::CaptureThread(){

}

void CaptureThread::run(){

    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    sniffer->openNetDev(6);
    sniffer->setDevsFilter("ip and tcp");
    sniffer->captureOnce();

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = sniffer->header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

 //   qDebug() << timestr << "," <<header->ts.tv_usec << "len: "<<header->len ;
    // 获得 IP 协议头
    iphdr *ih = (iphdr *)(sniffer->pkt_data+ 14);
    u_int ip_len = (ih->ver_ihl & 0xf) * 4;
    qDebug() << "ip header length is " << ip_len<< endl ;
}
