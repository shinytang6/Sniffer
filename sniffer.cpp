#include "sniffer.h"
#include <QDebug>
#include <pcap.h>
    #define WPCAP
    #define HAVE_REMOTE
    #include <remote-ext.h>
Sniffer::Sniffer()
{

}

Sniffer::~Sniffer()
{

}

void Sniffer::findAllDevs(){
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
         qDebug() << "error " ;
     }

    /* 打印列表 */
    for(dev= alldevs; dev != NULL; dev= dev->next)
    {
            qDebug() << dev->name << ":" <<dev->description;
    }
}
