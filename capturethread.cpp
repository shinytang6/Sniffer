#include "capturethread.h"
#include "protocoltype.h"
#include <QDebug>
#include <winsock2.h>
#include <QStandardItem>
#include <iostream>
CaptureThread::CaptureThread(){
    devNum = 6;
    isStop = false;
}

void CaptureThread::run(){


    alldevs = sniffer->findAllDevs();
    emit sendDevs(alldevs);
    std::cout<<"ahah"<<devNum;
    sniffer->openNetDev(devNum);
    sniffer->setDevsFilter("ip");
    while(sniffer->captureOnce() >= 0 && !isStop){


//    sniffer->analyze_frame(sniffer->pkt_data,sniffer->header);
//    while(sniffer->captureOnce() >= 0){
//        local_tv_sec = sniffer->header->ts.tv_sec;
//        ltime=localtime(&local_tv_sec);
//        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
//        sniffer->analyze_frame(sniffer->pkt_data);
//    }

    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    ethhdr *eth = (ethhdr*)(sniffer->pkt_data);
    tempSnifferData *tmpData = new tempSnifferData();

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = sniffer->header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    tmpData->strTime = timestr;
    std::cout<<"type: "<<ntohs(eth->type)<<"\n";
    switch (ntohs(eth->type)) {
        case 0x0806 :{
//            analyze_arp(pkt_data,tmpData);
            std::cout<<"protocol: arp"<<"\n";
            break;
        }
        case 0x0800 :{
            // 获得 IP 协议头
            iphdr *ih = (iphdr *)(sniffer->pkt_data+ 14);
            u_int ip_len = (ih->ver_ihl & 0xf) * 4;
            char len[10];
            sprintf( len, "%d", ip_len);
            tmpData->strLength = len;
            char szSaddr[24], szDaddr[24];
            sprintf(szSaddr,"%d.%d.%d.%d:",ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
            sprintf(szDaddr," %d.%d.%d.%d:",ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
            tmpData->strSIP = szSaddr;
            tmpData->strDIP = szDaddr;
            std::cout<<"protocol: ipv4"<<"\n";
            std::cout<<"source:"<<tmpData->strSIP<<"\n";
            std::cout<<"dest:"<<tmpData->strDIP<<"\n";
            switch (ih->proto) {
                case TCP_SIG:{
                    tmpData->strProto = "TCP";
                    char sport[10], dport[10];
                    tcphdr *th = (tcphdr *)(sniffer->pkt_data + 14 + ip_len);		// 获得 TCP 协议头
                    sprintf( sport, "%d", ntohs(th->sport)); // 源端口
                    sprintf( dport, "%d", ntohs(th->dport)); // 目的端口
                    tmpData->strSIP = tmpData->strSIP + sport;
                    tmpData->strDIP = tmpData->strDIP + dport;

                    std::cout<<"protocol: TCP"<<"\n";
                    std::cout<<"sport:"<<ntohs(th->sport)<<"\n";
                    std::cout<<"dport:"<<ntohs(th->dport)<<"\n";
                    std::cout<<"source:"<<tmpData->strSIP<<"\n";
                    std::cout<<"dest:"<<tmpData->strDIP<<"\n";
                    std::cout<<"lengthaaa:"<<tmpData->strLength<<"\n";
                    emit sendData(QString::fromStdString(tmpData->strTime),QString::fromStdString(tmpData->strSIP),QString::fromStdString(tmpData->strDIP),QString::fromStdString(tmpData->strProto),QString::fromStdString(tmpData->strLength));
                    break;
                    }
                case UDP_SIG:{
                    tmpData->strProto = "UDP";
                    char sport[10], dport[10];
                    udphdr *uh = (udphdr *)(sniffer->pkt_data + 14 + ip_len);		// 获得 UDP 协议头
                    sprintf( sport, "%d", ntohs(uh->sport)); // 源端口
                    sprintf( dport, "%d", ntohs(uh->dport)); // 目的端口
                    tmpData->strSIP = tmpData->strSIP + sport;
                    tmpData->strDIP = tmpData->strDIP + dport;         
                    emit sendData(QString::fromStdString(tmpData->strTime),QString::fromStdString(tmpData->strSIP),QString::fromStdString(tmpData->strDIP),QString::fromStdString(tmpData->strProto),QString::fromStdString(tmpData->strLength));
                    std::cout<<"protocol: UDP"<<"\n";
                    std::cout<<"sport:"<<ntohs(uh->sport)<<"\n";
                    std::cout<<"dport:"<<ntohs(uh->dport)<<"\n";
                    std::cout<<"source:"<<tmpData->strSIP<<"\n";
                    std::cout<<"dest:"<<tmpData->strDIP<<"\n";
                    break;
                    }
                case ICMP_SIG:{
                    tmpData->strProto = "ICMP";
                    emit sendData(QString::fromStdString(tmpData->strTime),QString::fromStdString(tmpData->strSIP),QString::fromStdString(tmpData->strDIP),QString::fromStdString(tmpData->strProto),QString::fromStdString(tmpData->strLength));
                    break;
                }
                default:{
                    std::cout<<"something error"<<"\n";
                }
            }
            break;
        }
        case 0x86dd :{
//            analyze_ipv6(pkt_data,tmpData);
            std::cout<<"protocol: ipv6"<<"\n";
            break;
        }
     }
    }

}
