#ifndef SNIFFER_H
#define SNIFFER_H
#include "pcap.h"

class Sniffer
{
public:
    Sniffer();
    ~Sniffer();

    void findAllDevs();			// 获取全部网络设备列表信息
    /*void createDevsStr(char *source, char *szFileName);				// WinPcap语法创建一个源字符串
    void freeNetDevsMem();											// 释放网络设备信息占据的堆内存
    bool openNetDev(char *szDevName);								// 根据名称打开网络设备
    bool openNetDev(int iDevNum);									// 根据序号打开网络设备
    bool closeNetDev();												// 关闭当前打开的网络设备
    bool setDevsFilter(char *szFilter);								// 对当前打开设备设置过滤器
    int	 captureOnce();												// 捕获一次网络数据包
    bool captureByCallBack(pSnifferCB func);						// 以回调函数方式捕获数据

    // 只有当接口打开时，调用 openDumpFile() 才是有效的
    bool openDumpFile(char *szFileName);							// 打开堆文件（文件保存数据包）
    void saveCaptureData(u_char *, struct pcap_pkthdr *, u_char *);	// 保存捕获的数据到文件
    void closeDumpFile();											// 关闭堆文件

    void consolePrint();	*/										// 控制台打印网络设备信息

protected:
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

};
#endif // SNIFFER_H
