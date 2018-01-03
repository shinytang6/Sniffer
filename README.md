## Sniffer

> 一个简单的网络数据嗅探器，基于Qt 5.9.3 && Wincap库（windows下）

#### 环境

* Qt 5.9.3（[https://www.qt.io/](https://www.qt.io/)）
* Wincap ([http://www.ferrisxu.com/WinPcap/html/index.html](http://www.ferrisxu.com/WinPcap/html/index.html))


#### 使用方法
	
	1. git clone https://github.com/shinytang6/Sniffer
	2. 需要下载 Wincap驱动和DLL安装包
	3. 解压缩Wincap包到本地任意位置（并不一定要在工程文件夹下）并进行相关配置
		以下是我在Windows平台下配置文件sniffer.pro的配置：
			INCLUDEPATH += "G:/WpdPack_4_1_2/WpdPack/Include"
			LIBS += G:/WpdPack_4_1_2/WpdPack/Lib/wpcap.lib G:/WpdPack_4_1_2/WpdPack/Lib/packet.lib
	4. 安装 Qt 5.9版本并导入.pro文件（注：低版本Qt可能无法运行项目）
	

#### 完成功能

* 侦听特定网卡进出的数据包（可选择要侦听的网卡），并解析数据包中的内容（数据部分已包含ARP/IP/ICMP/TCP/UDP协议）
* TCP/UDP/ICMP/ARP数据包的全部数据显示（包括Mac头/IP头等等信息）
* 包过滤（能够根据指定源、目的IP地址，指定源、目的端口，指定主机名，指定协议等等条件过滤数据包）
* 数据包查询（能够根据数据包内容查询并显示所有符合条件的数据包）
* 数据保存（能够保存单次捕获的所有数据包）
* 导入数据包（能够将已经保存下来的数据导入系统显示）
* 添加了选中/滑动等不同效果）



