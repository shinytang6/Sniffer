#include "sniffer.h"
#include "protocoltype.h"
#include <QDebug>
#include <iostream>

Sniffer::Sniffer()
{
    // 创建时就获取设备列表
    findAllDevs();
}

Sniffer::~Sniffer()
{

}

void Sniffer::findAllDevs(char *szFlag){
    if (pcap_findalldevs_ex(szFlag, NULL, &alldevs, errbuf) == -1) {
         qDebug() << "error " ;
     }

    /* 打印列表 */
    for(dev= alldevs; dev != NULL; dev= dev->next)
    {       iNetDevsNum++;
            qDebug() << dev->name << ":" <<dev->description;
    }
}

bool Sniffer::openNetDev(int devNum){
    int i;
    if(devNum < 1 || devNum > iNetDevsNum)
        {
            qDebug() << "\nInterface number out of range.\n";
            /* 释放设备列表 */
            freeDevsMem();
            return -1;
        }
        /* 跳转到选中的适配器 */
        for(dev=alldevs, i=0; i< devNum-1 ;dev=dev->next, i++);

        /* 打开设备 */
        if ( (adhandle= pcap_open(dev->name,          // 设备名
                                  65536,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                                  PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
                                  1000,             // 读取超时时间
                                  NULL,             // 远程机器验证
                                  errbuf            // 错误缓冲池
                                  ) ) == NULL)
        {
            qDebug() << "\nInterface number out of range.\n";"\nUnable to open the adapter. %s is not supported by WinPcap\n";
            /* 释放设备列表 */
            freeDevsMem();
            return -1;
        }
}

bool Sniffer::setDevsFilter(char *szFilter)
{
    /* 检查数据链路层，为了简单，我们只考虑以太网 */
        if(pcap_datalink(adhandle) != DLT_EN10MB)
        {
            qDebug() <<"\nThis program works only on Ethernet networks.\n" ;
            /* 释放设备列表 */
            freeDevsMem();
            return -1;
        }
        u_int	netmask;

        if(dev->addresses != NULL)
            /* 获得接口第一个地址的掩码 */
            netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
        else
            /* 如果接口没有地址，那么我们假设一个C类的掩码 */
            netmask=0xffffff;

        qDebug() <<"netmask is "<< adhandle<<endl;
        //编译过滤器
        if (pcap_compile(adhandle, &fcode, szFilter, 1, netmask) <0 )
        {
            freeDevsMem();
            return -1;
        }

        //设置过滤器
        if (pcap_setfilter(adhandle, &fcode)<0)
        {
            /* 释放设备列表 */
            freeDevsMem();
            return -1;
        }
}

void Sniffer::captureByCallBack(snifferCB func){
    /* 开始捕捉 */
    pcap_loop(adhandle, 0, func, NULL);
    qDebug() << adhandle;
}

int Sniffer::captureOnce(){
   return   pcap_next_ex( adhandle, &header, &pkt_data);
}

void Sniffer::freeDevsMem(){
    if(alldevs){
        pcap_freealldevs(alldevs);
        alldevs = NULL;
    }
}

void Sniffer::analyze_frame(const u_char *pkt_data){
    ethhdr *eth = (ethhdr*)(pkt_data);
    tempSnifferData *tmpData = new tempSnifferData();
    switch (ntohs(eth->type)) {
        case 0x0806 :
            analyze_arp(pkt_data,tmpData);
            break;
        case 0x0800 :
            analyze_ipv4(pkt_data,tmpData);
            break;
        case 0x86dd :
            analyze_ipv6(pkt_data,tmpData);
            break;
    }

}


void Sniffer::analyze_ipv4(const u_char *pkt_data,tempSnifferData *tmpData){
    // 获得 IP 协议头
    iphdr *ih = (iphdr *)(pkt_data+ 14);
    u_int ip_len = (ih->ver_ihl & 0xf) * 4;
//    char szLength[6];
//    sprintf(szLength, "%d", ip_len);
//    tmpData->strLength = szLength ;
    tmpData->strLength = ip_len;
    char szSaddr[24], szDaddr[24];
    sprintf(szSaddr,"%d.%d.%d.%d : ",ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
    sprintf(szDaddr," %d.%d.%d.%d : ",ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
    tmpData->strSIP = szSaddr;
    tmpData->strDIP = szDaddr;
    std::cout<<"protocol: ipv4"<<"\n";
    std::cout<<"source:"<<tmpData->strSIP<<"\n";
    std::cout<<"dest:"<<tmpData->strDIP<<"\n";

    switch (ih->proto) {
        case TCP_SIG:{
            analyze_tcp(pkt_data,tmpData);
            break;
            }
        case UDP_SIG:{
            analyze_udp(pkt_data,tmpData);
            break;
            }
        case ICMP_SIG:{
            analyze_icmp(pkt_data,tmpData);
            break;
        }
    }

}

void Sniffer::analyze_ipv6(const u_char *pkt_data,tempSnifferData *tmpData){

     std::cout<<"protocol: ipv6"<<"\n";
}

void Sniffer::analyze_arp(const u_char *pkt_data,tempSnifferData *tmpData){

     std::cout<<"protocol: arp"<<"\n";
}

void Sniffer::analyze_tcp(const u_char *pkt_data,tempSnifferData *tmpData){
     char sport[10], dport[10];
     tcphdr *th = (tcphdr *)(pkt_data + 14 + tmpData->strLength);		// 获得 TCP 协议头
     sprintf( sport, "%d", ntohs(th->sport)); // 源端口
     sprintf( dport, "%d", ntohs(th->dport)); // 目的端口
     tmpData->strSIP = tmpData->strSIP + sport;
     tmpData->strDIP = tmpData->strDIP + dport;

     std::cout<<"protocol: TCP"<<"\n";
     std::cout<<"sport:"<<ntohs(th->sport)<<"\n";
     std::cout<<"dport:"<<ntohs(th->dport)<<"\n";
     std::cout<<"source:"<<tmpData->strSIP<<"\n";
     std::cout<<"dest:"<<tmpData->strDIP<<"\n";
}

void Sniffer::analyze_udp(const u_char *pkt_data,tempSnifferData *tmpData){
    char sport[10], dport[10];
    udphdr *uh = (udphdr *)(pkt_data + 14 + tmpData->strLength);		// 获得 UDP 协议头
    sprintf( sport, "%d", ntohs(uh->sport)); // 源端口
    sprintf( dport, "%d", ntohs(uh->dport)); // 目的端口
    tmpData->strSIP = tmpData->strSIP + sport;
    tmpData->strDIP = tmpData->strDIP + dport;

    std::cout<<"protocol: UDP"<<"\n";
    std::cout<<"sport:"<<ntohs(uh->sport)<<"\n";
    std::cout<<"dport:"<<ntohs(uh->dport)<<"\n";
    std::cout<<"source:"<<tmpData->strSIP<<"\n";
    std::cout<<"dest:"<<tmpData->strDIP<<"\n";
}

void Sniffer::analyze_icmp(const u_char *pkt_data,tempSnifferData *tmpData){


    std::cout<<"protocol: ICMP"<<"\n";

}
