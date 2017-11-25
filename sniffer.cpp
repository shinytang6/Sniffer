#include "sniffer.h"
#include "protocoltype.h"
#include <QDebug>
Sniffer::Sniffer()
{

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
   int res =   pcap_next_ex( adhandle, &header, &pkt_data);
   /* 将时间戳转换成可识别的格式 */
   local_tv_sec = header->ts.tv_sec;
   ltime=localtime(&local_tv_sec);
   strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

//   qDebug() << timestr << "," <<header->ts.tv_usec << "len: "<<header->len ;
   // 获得 IP 协议头
   iphdr *ih = (iphdr *)(pkt_data+ 14);
   u_int ip_len = (ih->ver_ihl & 0xf) * 4;
   qDebug() << "ip header length is " << ip_len ;
   return res;
}

void Sniffer::freeDevsMem(){
    if(alldevs){
        pcap_freealldevs(alldevs);
        alldevs = NULL;
    }
}

