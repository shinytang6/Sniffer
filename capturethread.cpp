#include "capturethread.h"
#include "protocoltype.h"
#include <QDebug>
#include <winsock2.h>

CaptureThread::CaptureThread(){

}

void CaptureThread::run(){

    sniffer->openNetDev(6);
    sniffer->setDevsFilter("ip");
    sniffer->captureOnce();


    sniffer->analyze_frame(sniffer->pkt_data,sniffer->header);



//    while(sniffer->captureOnce() >= 0){
//        local_tv_sec = sniffer->header->ts.tv_sec;
//        ltime=localtime(&local_tv_sec);
//        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
//        sniffer->analyze_frame(sniffer->pkt_data);
//    }

}
