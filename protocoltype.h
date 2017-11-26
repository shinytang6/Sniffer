#ifndef PROTOCOLTYPE_H
#define PROTOCOLTYPE_H

// IP 协议头 协议(Protocol) 字段标识含义
//      协议      协议号
#define IP_SIG			00
#define ICMP_SIG		01
#define IGMP_SIG		02
#define GGP_SIG			03
#define IP_ENCAP_SIG	04
#define ST_SIG			05
#define TCP_SIG			06
#define EGP_SIG			08
#define PUP_SIG			12
#define UDP_SIG			17
#define HMP_SIG			20
#define XNS_IDP_SIG		22
#define RDP_SIG			27
#define TP4_SIG			29
#define XTP_SIG			36
#define DDP_SIG			37
#define IDPR_CMTP_SIG	39
#define RSPF_SIG		73
#define VMTP_SIG		81
#define OSPFIGP_SIG		89
#define IPIP_SIG		94
#define ENCAP_SIG		98


//Mac帧头 占14个字节
typedef struct ethhdr
{
    u_char dest[6];         //6个字节 目标地址
    u_char src[6];              //6个字节 源地址
    u_short type;               //2个字节 类型
};

//ARP头
typedef struct arphdr
{
    u_short ar_hrd;                     //硬件类型
    u_short ar_pro;                     //协议类型
    u_char ar_hln;                      //硬件地址长度
    u_char ar_pln;                      //协议地址长度
    u_short ar_op;                      //操作码，1为请求 2为回复
    u_char ar_srcmac[6];            //发送方MAC
    u_char ar_srcip[4];             //发送方IP
    u_char ar_destmac[6];           //接收方MAC
    u_char ar_destip[4];                //接收方IP
};

// IPv4头部（20字节）
typedef struct iphdr
{
    unsigned char		ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    unsigned char		tos;            // 服务类型(Type of service)
    unsigned short		tlen;           // 总长(Total length)
    unsigned short		identification; // 标识(Identification)
    unsigned short		flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
    unsigned char		ttl;            // 存活时间(Time to live)
    unsigned char		proto;          // 协议(Protocol)
    unsigned short		crc;			// 首部校验和(Header checksum)
    unsigned char		saddr[4];		// 源地址(Source address)
    unsigned char		daddr[4];		// 目标地址(Destination address)
    unsigned int		op_pad;         // 选项与填充(Option + Padding)
};

// ICMP头部（4字节）
typedef struct icmphdr
{
    unsigned char	icmp_type;	// 类型
    unsigned char	code;		// 代码
    unsigned short	chk_sum;	// 16位检验和
}icmp_header;

// TCP头部（20字节）
typedef struct tcphdr
{
    unsigned short	sport;			// 源端口号
    unsigned short	dport;			// 目的端口号
    unsigned int	seq_no;				// 序列号
    unsigned int	ack_no;				// 确认号
    unsigned char	thl:4;				// tcp头部长度
    unsigned char	reserved_1:4;		// 保留6位中的4位首部长度
    unsigned char	reseverd_2:2;		// 保留6位中的2位
    unsigned char	flag:6;				// 6位标志
    unsigned short	wnd_size;			// 16位窗口大小
    unsigned short	chk_sum;			// 16位TCP检验和
    unsigned short	urgt_p;				// 16为紧急指针
};

// UDP头部（8字节）
typedef struct udphdr
{
    unsigned short	sport;		// 源端口(Source port)
    unsigned short	dport;		// 目的端口(Destination port)
    unsigned short	len;		// UDP数据包长度(Datagram length)
    unsigned short	crc;		// 校验和(Checksum)
};

//定义IPv6
typedef struct iphdr6
{
//#if defined(BIG_ENDIAN)
    u_int version:4,                //版本
            flowtype:8,         //流类型
            flowid:20;              //流标签
/*#elif defined(LITTLE_ENDIAN)
u_int  flowid:20,               //流标签
            flowtype:8,         //流类型
            version:4;              //版本
//#endif*/
    u_short plen;                   //有效载荷长度
    u_char nh;                      //下一个头部
    u_char hlim;                    //跳限制
    u_short saddr[8];           //源地址
    u_short daddr[8];           //目的地址
};
#endif // PROTOCOLTYPE_H
