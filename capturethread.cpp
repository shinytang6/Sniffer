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
    while(sniffer->captureOnce() >= 0){
//    sniffer->captureOnce();

    /* 将时间戳转换成可识别的格式 */
        local_tv_sec = sniffer->header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
        sniffer->analyze_frame(sniffer->pkt_data);
    }

}
