#include "capturethread.h"
#include "protocoltype.h"
#include <QDebug>
#include <winsock2.h>
#include <QStandardItem>
#include <iostream>
#include <QDir>
#include <QDateTime>
#include <QMetaType>
CaptureThread::CaptureThread(){
    devNum = 0;
    count = 1;
    isStop = false;
    filter = "";
    loadDevs = false;
    loadFile = false;
    saveFile = false;
    tempFile = QDir::tempPath() + "/sniffer.txt" ;

}

void CaptureThread::run(){

    alldevs = sniffer->findAllDevs();
    emit sendDevs(alldevs);
    if(loadDevs)
        return;
    sniffer->openNetDev(devNum);
    if (filter!=""){
        // 将QSrting类型转化为char*传入setDevsFilter函数
        QByteArray filter_byte = filter.toLatin1();
        std::cout<<"filter condition: "<<filter_byte.data();
        sniffer->setDevsFilter(filter_byte.data());
    }


    std::cout<<"save file name:"<<(const char *)tempFile.toLocal8Bit()<<endl;
    if(!tempFile.isEmpty() && !loadFile) {
         sniffer->openDumpFile((const char *)tempFile.toLocal8Bit());
    }

    int packNum = 1;
    while((sniffer->captureOnce() >= 0 && !isStop) || ( sniffer->openSavedDumpFile(tempFile.toLocal8Bit(),packNum)  &&loadFile) ){
        if(!tempFile.isEmpty() && !loadFile)
            sniffer->saveDumpFile();
        packNum = packNum + 1;
        std::cout<<"save file name:"<<(const char *)tempFile.toLocal8Bit()<<endl;

    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    // 比特流
    int cap_length = sniffer->header->caplen;
    int frame_length = sniffer->header->len;
    info_frame_bytes_child.sprintf("Frame %d (%d bytes on wire, %d bytes on captured)",
                                     count, frame_length, cap_length);
    info_frame_bytes_List.append(info_frame_bytes_child);
    info_frame_bytes_child.sprintf("Frame Number: %d",count);  info_frame_bytes_List.append(info_frame_bytes_child);
            info_frame_bytes_child.sprintf("Packet Length: %d bytes",frame_length);   info_frame_bytes_List.append(info_frame_bytes_child);
            info_frame_bytes_child.sprintf("Capture Length: %d bytes",cap_length);  info_frame_bytes_List.append(info_frame_bytes_child);


    ethhdr *eth = (ethhdr*)(sniffer->pkt_data);
    // 以太网帧
    info_frame_Eth_Hdr_child.sprintf("Ethernet II, Src: %02x:%02x:%02x:%02x:%02x:%02x, Dst: %02x:%02x:%02x:%02x:%02x:%02x",
                                      eth->src[0],eth->src[1],eth->src[2],
                                      eth->src[3],eth->src[4],eth->src[5],
                                      eth->dest[0],eth->dest[1],eth->dest[2],
                                      eth->dest[3],eth->dest[4],eth->dest[5]
                                      );
    info_frame_Eth_Hdr_List.append(info_frame_Eth_Hdr_child);
    info_frame_Eth_Hdr_child.sprintf("Destionation: %02x:%02x:%02x:%02x:%02x:%02x (%02x:%02x:%02x:%02x:%02x:%02x)",
                                             eth->dest[0],eth->dest[1],eth->dest[2],
                                             eth->dest[3],eth->dest[4],eth->dest[5],
                                             eth->dest[0],eth->dest[1],eth->dest[2],
                                             eth->dest[3],eth->dest[4],eth->dest[5]);
    info_frame_Eth_Hdr_List.append(info_frame_Eth_Hdr_child);

    info_frame_Eth_Hdr_child.sprintf("Source: %02x:%02x:%02x:%02x:%02x:%02x (%02x:%02x:%02x:%02x:%02x:%02x)",
                                             eth->src[0],eth->src[1],eth->src[2],
                                             eth->src[3],eth->src[4],eth->src[5],
                                             eth->src[0],eth->src[1],eth->src[2],
                                             eth->src[3],eth->src[4],eth->src[5]);
    info_frame_Eth_Hdr_List.append(info_frame_Eth_Hdr_child);

    info_frame_Eth_Hdr_child.sprintf("Type: 0x%04x (IP)",eth->type);
    info_frame_Eth_Hdr_List.append(info_frame_Eth_Hdr_child);

    tempSnifferData *tmpData = new tempSnifferData();

    /* 将时间戳转换成可识别的格式 */
    local_tv_sec = sniffer->header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
    tmpData->strTime = timestr;
    std::cout<<"type: "<<ntohs(eth->type)<<"\n";
    count++;
    switch (ntohs(eth->type)) {
        case 0x0806 :{
//            analyze_arp(pkt_data,tmpData);
            std::cout<<"protocol: arp"<<"\n";
            arphdr *arph = (arphdr *)(sniffer->pkt_data+ 14);
            char szSaddr[24], szDaddr[24];
            sprintf(szSaddr,"%x.%x.%x.%x.%x.%x",arph->ar_srcmac[0], arph->ar_srcmac[1], arph->ar_srcmac[2], arph->ar_srcmac[3],arph->ar_srcmac[4],arph->ar_srcmac[5]);
            sprintf(szDaddr,"%x.%x.%x.%x.%x.%x",arph->ar_destmac[0], arph->ar_destmac[1], arph->ar_destmac[2], arph->ar_destmac[3],arph->ar_destmac[4],arph->ar_destmac[5]);
            std::cout<<"arp source:"<<szSaddr<<endl;
            std::cout<<"arp dest:"<<szDaddr<<endl;
            tmpData->strSIP = szSaddr;
            tmpData->strDIP = szDaddr;
            tmpData->strProto = "ARP";
            tmpData->strLength = "28";

            info_frame_Ip_Hdr_child.sprintf("Address Resolution Protocol(reply)"
                                               );
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);

            info_frame_Ip_Hdr_child.sprintf("Hardware type: (%d)", htons(arph->ar_hrd));           info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Protocol type: %d", htons(arph->ar_pro));                               info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Hardware size: %d", htons(arph->ar_hln));                                       info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);

            info_frame_Ip_Hdr_child.sprintf("Protocol size: %d",  htons(arph->ar_pln));
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Opcode: 0x%04x",  htons(arph->ar_op));
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);

            info_frame_Ip_Hdr_child.sprintf("Sender Mac Address: %x.%x.%x.%x.%x.%x", arph->ar_srcmac[0],arph->ar_srcmac[1],arph->ar_srcmac[2],arph->ar_srcmac[3],arph->ar_srcmac[4],arph->ar_srcmac[5]);
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Sender IP Address: %u.%u.%u.%u", arph->ar_srcip[0],arph->ar_srcip[1],arph->ar_srcip[2],arph->ar_srcip[3]);
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Target Mac Address: %x.%x.%x.%x.%x.%x ", arph->ar_destmac[0],arph->ar_destmac[1],arph->ar_destmac[2],arph->ar_destmac[3],arph->ar_destmac[4],arph->ar_destmac[5]);
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Target IP Address: %u.%u.%u.%u", arph->ar_destip[0],arph->ar_destip[1],arph->ar_destip[2],arph->ar_destip[3]);
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
//            info_frame_Trans_Layer_List= ;
            emit sendDetail(info_frame_bytes_List,info_frame_Eth_Hdr_List,info_frame_Ip_Hdr_List,info_frame_Trans_Layer_List);
            emit sendData(QString::fromStdString(tmpData->strTime),QString::fromStdString(tmpData->strSIP),QString::fromStdString(tmpData->strDIP),QString::fromStdString(tmpData->strProto),QString::fromStdString(tmpData->strLength));
            break;
        }
        case 0x0800 :{
            // 获得 IP 协议头
            iphdr *ih = (iphdr *)(sniffer->pkt_data+ 14);
            u_int ip_len = (ih->ver_ihl & 0xf) * 4;

            info_frame_Ip_Hdr_child.sprintf("Internet Protocol, Src: %u.%u.%u.%u, Dst: %u.%u.%u.%u",
                                               ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3],
                                               ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]
                                               );
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Version: 4 ");                                                               info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Total Length: %d", htons(ih->tlen));                                   info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Identification: 0x%04x (%d)", htons(ih->identification), htons(ih->identification));           info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Fragment Offset: %d", htons(ih->flags_fo));                               info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Time to Live: %d", htons(ih->ttl));                                       info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child = QString("Protocol: %1 (%2)").arg(ih->proto).arg(ih->proto);
            info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Header Checksum: 0x%04x",  htons(ih->crc));                             info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Source: %u.%u.%u.%u", ih->saddr[0],ih->saddr[1],ih->saddr[2],ih->saddr[3]);     info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            info_frame_Ip_Hdr_child.sprintf("Destionation: %u.%u.%u.%u ", ih->daddr[0],ih->daddr[1],ih->daddr[2],ih->daddr[3]); info_frame_Ip_Hdr_List.append(info_frame_Ip_Hdr_child);
            char len[10];
            sprintf( len, "%d", ip_len);
            tmpData->strLength = len;
            char szSaddr[24], szDaddr[24];
            sprintf(szSaddr,"%d.%d.%d.%d",ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
            sprintf(szDaddr," %d.%d.%d.%d",ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
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
                    sprintf( sport, ":%d", ntohs(th->sport)); // 源端口
                    sprintf( dport, ":%d", ntohs(th->dport)); // 目的端口
                    tmpData->strSIP = tmpData->strSIP + sport;
                    tmpData->strDIP = tmpData->strDIP + dport;

                    info_transport_Layer_child = QString("%1").arg("Transmission Control Protocol");
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Src Port: %d",htons(th->sport));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Dest Port: %d",htons(th->dport));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Sequence Number: %d",htonl(th->seq_no));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Acknowledgment Number: %d", htonl(th->ack_no));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);

                    std::cout<<"protocol: TCP"<<"\n";
                    std::cout<<"sport:"<<ntohs(th->sport)<<"\n";
                    std::cout<<"dport:"<<ntohs(th->dport)<<"\n";
                    std::cout<<"source:"<<tmpData->strSIP<<"\n";
                    std::cout<<"dest:"<<tmpData->strDIP<<"\n";
                    std::cout<<"lengthaaa:"<<tmpData->strLength<<"\n";
                    std::cout<<"AAAAAAAAA:"<<info_frame_Ip_Hdr.toStdString()<<endl;
                    emit sendDetail(info_frame_bytes_List,info_frame_Eth_Hdr_List,info_frame_Ip_Hdr_List,info_frame_Trans_Layer_List);
                    emit sendData(QString::fromStdString(tmpData->strTime),QString::fromStdString(tmpData->strSIP),
                                  QString::fromStdString(tmpData->strDIP),QString::fromStdString(tmpData->strProto),
                                  QString::number(cap_length, 10));
                    break;
                    }
                case UDP_SIG:{
                    tmpData->strProto = "UDP";
                    char sport[10], dport[10];
                    udphdr *uh = (udphdr *)(sniffer->pkt_data + 14 + ip_len);		// 获得 UDP 协议头
                    sprintf( sport, ":%d", ntohs(uh->sport)); // 源端口
                    sprintf( dport, ":%d", ntohs(uh->dport)); // 目的端口
                    tmpData->strSIP = tmpData->strSIP + sport;
                    tmpData->strDIP = tmpData->strDIP + dport;

                    info_transport_Layer_child = QString("%1").arg("User Datagram Protocol");
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Src Port: %d",htons(uh->sport));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Dest Port: %d",htons(uh->dport));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Length: %d",htons(uh->len));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Checksum: 0x%04x", htons(uh->crc));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);

                    emit sendDetail(info_frame_bytes_List,info_frame_Eth_Hdr_List,info_frame_Ip_Hdr_List,info_frame_Trans_Layer_List);
                    emit sendData(QString::fromStdString(tmpData->strTime),QString::fromStdString(tmpData->strSIP),QString::fromStdString(tmpData->strDIP),QString::fromStdString(tmpData->strProto),QString::number(cap_length, 10));
                    std::cout<<"protocol: UDP"<<"\n";
                    std::cout<<"sport:"<<ntohs(uh->sport)<<"\n";
                    std::cout<<"dport:"<<ntohs(uh->dport)<<"\n";
                    std::cout<<"source:"<<tmpData->strSIP<<"\n";
                    std::cout<<"dest:"<<tmpData->strDIP<<"\n";
                    break;
                    }
                case ICMP_SIG:{
                    tmpData->strProto = "ICMP";
                    icmphdr *icmph = (icmphdr *)(sniffer->pkt_data + 14 + ip_len);
                    info_transport_Layer_child = QString("%1").arg("Internet Control Message Protocol");
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Type: %d",icmph->icmp_type);
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Code: %d",icmph->code);
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    info_transport_Layer_child.sprintf("Checksum: 0x%04x",htons(icmph->chk_sum));
                    info_frame_Trans_Layer_List.append(info_transport_Layer_child);
                    emit sendDetail(info_frame_bytes_List,info_frame_Eth_Hdr_List,info_frame_Ip_Hdr_List,info_frame_Trans_Layer_List);
                    emit sendData(QString::fromStdString(tmpData->strTime),QString::fromStdString(tmpData->strSIP),QString::fromStdString(tmpData->strDIP),QString::fromStdString(tmpData->strProto),QString::number(cap_length, 10));
                    break;
                }
                default:{
                    std::cout<<"something error"<<"\n";
                }
            }
            break;
        }
        case 0x86dd :{
            std::cout<<"protocol: ipv6"<<"\n";
            break;
        }
     }
    }

}
