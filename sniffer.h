#ifndef SNIFFER_H
#define SNIFFER_H
#include "pcap.h"
#define WPCAP
#define HAVE_REMOTE
#include <remote-ext.h>
#include <windows.h>
#include <string>

// 捕获的数据结构
struct tempSnifferData
{
    std::string	strNum;			// 序号
    std::string strTime;		// 时间
    std::string strSIP;			// 源 IP 地址，格式 IP:port
    std::string strDIP;			// 目标 IP 地址，格式 IP:port
    std::string strProto;		// 使用的协议
    int	strLength;		// 数据长度
    std::string strData;		// 原始数据
};

class Sniffer
{
public:
    Sniffer();
    ~Sniffer();
    typedef void (*snifferCB)(u_char *, const struct pcap_pkthdr *, const u_char *);

    void findAllDevs(char *szFlag = PCAP_SRC_IF_STRING);			// 获取全部网络设备列表信息
    void freeDevsMem();											// 释放网络设备信息占据的堆内存
    void openNetDev(char *szDevName);								// 根据名称打开网络设备
    bool openNetDev(int iDevNum);									// 根据序号打开网络设备
    bool setDevsFilter(char *szFilter);                             // 对当前打开设备设置过滤器
    int	 captureOnce();												// 捕获一次网络数据包
    void captureByCallBack(snifferCB func);						// 以回调函数方式捕获数据

    void analyze_frame(const u_char *pkt_data,struct pcap_pkthdr *header);     // 分析Mac帧
    void analyze_ipv4(const u_char *pkt_data,tempSnifferData *tmpData);      // 分析ipv4
    void analyze_ipv6(const u_char *pkt_data,tempSnifferData *tmpData);      // 分析ipv6
    void analyze_arp(const u_char *pkt_data,tempSnifferData *tmpData);       // 分析arp
    void analyze_tcp(const u_char *pkt_data,tempSnifferData *tmpData);       // 分析tcp
    void analyze_udp(const u_char *pkt_data,tempSnifferData *tmpData);       // 分析udp
    void analyze_icmp(const u_char *pkt_data,tempSnifferData *tmpData);       // 分析icmp
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

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
    int				iNetDevsNum;					// 网络设备数量
    struct bpf_program fcode;
    pcap_t			*adhandle;						// 当前打开的设备句柄（指针）


};
#endif // SNIFFER_H
