/*
 * @file nids.h
 *
 * @author Akagi201
 * @date 2014/04/24
 *
 * libnids定义的数据结构和函数的声明集中在头文件nids.h中.
 * 使用libnids的应用程序必须包含这个文件, 并且要与libnids.a(或者libnids.so.x.y)进行连接.
 *
 * 利用Libnids开发的流程
 * 1. 用函数nids_init()进行初始化. 打开网络接口, 打开文件, 编译过滤规则, 设置过滤规则, 判断网络链路层类型等初始化工作
 * 2. 然后注册相应的回调函数. 不同的回调函数实现不同的功能
 * 3. 最后利用函数nids_run()进入循环捕获数据包的状态
 *
 * 应用程序的main函数一般是这种框架
 *
 int main (void) {
 // 应用程序的是有处理, 与libnids无关
 // libnids一些可选参数的修改
 if (!nids_init()) {
 // 如果哪里出错了, 终止
 // 注册回调函数
 nids_run();
 }
 // 通常情况下, 不会运行到这里
 }
 */

/*
 Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
 See the file COPYING for license details.
 */

#ifndef _NIDS_NIDS_H
# define _NIDS_NIDS_H

# include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <pcap.h>

# ifdef __cplusplus
extern "C" {
# endif

// libnids的现行版本
# define NIDS_MAJOR (1)
# define NIDS_MINOR (24)

/*
 * @brief 报警类型
 */
enum {
	NIDS_WARN_IP = 1, // IP数据包异常
	NIDS_WARN_TCP, // TCP数据包异常
	NIDS_WARN_UDP, // UDP数据包异常
	NIDS_WARN_SCAN // 表示有扫描攻击发出
};

/*
 * @brief 报警类型
 */
enum {
	NIDS_WARN_UNDEFINED = 0, // 表示未定义
	NIDS_WARN_IP_OVERSIZED, // 表示IP数据包超长
	NIDS_WARN_IP_INVLIST, // 表示无效的碎片队列
	NIDS_WARN_IP_OVERLAP, // 表示发生重叠
	NIDS_WARN_IP_HDR, // 表示无效IP首部, IP数据包发生异常
	NIDS_WARN_IP_SRR, // 表示源路由IP数据包
	NIDS_WARN_TCP_TOOMUCH, // 表示tcp数据个数太多, 因为在libnids中在同一时刻捕获的tcp个数最大值为tcp连接参数的哈希表长度3/4
	NIDS_WARN_TCP_HDR, // 表示无效TCP首部, TCP数据包发生异常
	NIDS_WARN_TCP_BIGQUEUE, // 表示TCP接收的队列数据过多
	NIDS_WARN_TCP_BADFLAGS // 表示错误标记
};

/*
 * libnids状态
 *
 * 在对TCP数据流进行重组时, 必须考虑到TCP的连接状态, 在libnids中为了方便开发而定义了6种libnids状态(描述的是连接的逻辑状态)
 */
# define NIDS_JUST_EST (1) // 表示tcp连接建立
# define NIDS_DATA (2) // 表示接收数据的状态
# define NIDS_CLOSE (3) // 表示tcp连接正常关闭
# define NIDS_RESET (4) // 表示tcp连接被重置关闭
# define NIDS_TIMED_OUT (5) // 表示由于超时tcp连接被关闭
# define NIDS_EXITING   (6)	/* nids is exiting; last chance to get data */ // 表示libnids正在退出

// 校验和
# define NIDS_DO_CHKSUM  (0) // 表示告诉libnids要计算校验和
# define NIDS_DONT_CHKSUM (1) // 表示告诉libnids不需要计算校验和

/*
 * @brief TCP连接参数4元组
 *
 * 此数据结构是libnids中最基本的一种数据结构, 用于描述一个地址端口对
 */
struct tuple4 {
	u_short source; // 源端口
	u_short dest; // 目的端口
	u_int saddr; // 源地址
	u_int daddr; // 目的地址
};

/*
 * @brief TCP连接一侧的所有信息, 可以是客户端也可以是服务端
 *
 * structure describing one side of a TCP connection
 */
struct half_stream {
	char state; // socket state (ie TCP_ESTABLISHED) //表示套接字的状态, 也就是tcp连接状态
	/* if >0, then data should be stored in
	 * "data" buffer; else
	 * data flowing in this direction will be ignored
	 * have a look at samples/sniff.c for an example
	 * how one can use this field
	 */
	/*
	 * if >0, 那么数据应该被存放到data缓冲区中. 否则,
	 * 这个方向的数据流将被忽略
	 * 看一下samples/sniff.c文件如何使用这个域
	 */
	char collect; //表示是否存储数据到data中, 如果大于0就存储, 否则忽略
	// 类似地, 是否存储紧急数据到urgdata中,如果大于0就存储,否则忽略
	char collect_urg; // analogically, determines if to collect urgent data

	char *data; // buffer for normal data // 存储正常接收的数据

	/*
	 * offset (in data stream) of first byte stored in
	 * the "data" buffer; additional explanations follow
	 */
	int offset; // 存储在data中数据的第一个字节的偏移量

	/*
	 * how many bytes has been appended to buffer "data"
	 * since the creation of a connection
	 */
	int count; // 自连接建立以来已经有多少字节已经发送到data缓冲区中 //表示从tcp连接开始已经存储到data中的数据的字节数

	/*
	 * how many bytes were appended to "data" buffer
	 * last (this) time; if == 0, no new data arrived
	 */
	int count_new; // 多少字节将被发送到data缓冲区中last (this) time; // 表示有多少新数据存到data中
	int bufsize;
	int rmem_alloc;

	int urg_count;
	u_int acked;
	u_int seq;
	u_int ack_seq;
	u_int first_data_seq;
	u_char urgdata; // one-byte buffer for urgent data // 用来存储紧急数据
	u_char count_new_urg; // if != 0, new urgent data arrived 如果不等于0, 新的紧急数据到达 //表示是否有新的紧急数据到达
	u_char urg_seen;
	u_int urg_ptr;
	u_short window;
	u_char ts_on;
	u_char wscale_on;
	u_int curr_ts;
	u_int wscale;
	struct skbuff *list;
	struct skbuff *listtail;
};

/*
 * @brief 描述的是一个TCP连接的所有信息
 */
struct tcp_stream {
	struct tuple4 addr; // connections params (saddr, daddr, sport, dport) 是一个tuple4类型的成员,它表示一个tcp连接的四个重要信息
	char nids_state; // logical state of the connection 连接的逻辑状态
	struct lurker_node *listeners;
	struct half_stream client; // structure describing client side of the connection 描述连接的客户端的结构
	struct half_stream server; // structure describing server side of the connection 描述连接的服务端的结构
	struct tcp_stream *next_node;
	struct tcp_stream *prev_node;
	int hash_index;
	struct tcp_stream *next_time;
	struct tcp_stream *prev_time;
	int read;
	struct tcp_stream *next_free;
	void *user;
};

/*
 * @brief 描述libnids的一些全局参数信息
 *
 * nids_params变量中的syslog域在默认情况下包含函数nids_syslog的地址, 如下声明:
 *
 * void nids_syslog (int type, int errnum, struct ip *iph, void *data);
 *
 * 函数nids_params.syslog用于报告一些不寻常的情形, 例如端口扫描请求, 无效TCP头标记等等.
 * 这个域应该被分配一个自定义事件日志函数的地址.
 * 函数nids_syslog(在 libnids.c中定义)举例说明了如何解读传递给nids_params.syslog的参数.
 * nids_syslog日志信息传给系统守护进程syslogd中, 忽视像消息速率和可用磁盘空间之类的事情(这就是为什么他应该被替换掉).
 */
struct nids_prm {
	/*
	 * size of the hash table used for storing structures
	 * tcp_stream; libnis will follow no more than
	 * 3/4 * n_tcp_streams connections simultaneously
	 * default value: 1040. If set to 0, libnids will
	 * not assemble TCP streams.
	 */
	/*
	 * 用于存储tcp_stream结构信息的Hash表的大小
	 * libnis将只能同时跟踪 3/4 * n_tcp_streams连接的数据流
	 * 默认值: 1040
	 * 如果设置为0，Libnids将不再进行TCP流的组装
	 */
	int n_tcp_streams; //表示哈希表大小, 此哈希表用来存放tcp_stream数据结构,

	/*
	 * size of the hash table used for storing info on
	 * IP defragmentation; default value: 256
	 */
	/*
	 * 用于存储关于IP碎片重组的信息的Hash表的大小
	 * 默认值: 256
	 *
	 */
	int n_hosts; // 表示存放ip碎片信息的哈希表的大小

	/*
	 * interface on which libnids will listen for packets;
	 * default value == NULL, in which case device will
	 * be determined by call to pcap_lookupdev; special
	 * value of "all" results in libnids trying to
	 * capture packets on all interfaces (this works only
	 * with Linux kernel > 2.2.0 and libpcap >= 0.6.0);
	 * see also doc/LINUX
	 */
	/*
	 * Libnids用于监听数据包的设备接口
	 * 默认值: NULL, 将通过调用pcap_lookupdev函数来接决定.
	 * 特殊值all将致使Libnids试图通过所有的设备接口截获数据包
	 * (这个参数在高于2.2.0Linux 核心版本有效)
	 * 参见 doc/NEW_LIBPCAP
	 */
	char *device;

	/*
	 * capture filename from which to read packets;
	 * file must be in libpcap format and device must
	 * be set to NULL; default value: NULL
	 */
	char *filename; // 用来存储网络数据捕获文件. 如果设置了文件, 与此同时就应该设置成员device为null, 默认值为NULL

	/*
	 * size of struct sk_buff, a structure defined by
	 * Linux kernel, used by kernel for packets queuing. If
	 * this parameter has different value from
	 * sizeof(struct sk_buff), libnids can be bypassed
	 * by attacking resource managing of libnis (see TEST
	 * file). If you are paranoid, check sizeof(sk_buff)
	 * on the hosts on your network, and correct this
	 * parameter. Default value: 168
	 */
	/*
	 * 结构sk_buff的大小, 这个结构是由Linux核心定义的, 核心用于
	 * 数据包排列, 如果这个参数和sizeof(struct sk_buff)地值不同,
	 * Libnids可以通过攻击其资源管理而被绕过. 见TEST文件.
	 * 如果你是一个喜欢妄想的人, 那么检查你网络中主机的sizeof(sk_buff)
	 * 并调整这个参数, 默认值: 168
	 */
	int sk_buff_size; // 表示数据结构sk_buff的大小. 数据结构sk_buff是linux内核中一个重要的数据结构, 是用来进行数据包队列操作的

	/*
	 * how many bytes in structure sk_buff is reserved for
	 * information on net interface; if dev_addon==-1, it
	 * will be corrected during nids_init() according to
	 * type of the interface libnids will listen on.
	 * Default value: -1.
	 */
	/*
	 * 在sk_buff结构中保留了多少字节用于存储网络接口信息; 如果dev_addon==-1,
	 * 将在nids_init()中根据Libnids监听的接口的类型进行改正.
	 * 默认值: -1.
	 */
	int dev_addon; // 表示在数据结构sk_buff中用于网络接口上信息的字节数, 如果是-1(默认值), 那么libnids会根据不同的网络接口进行修正

	/*
	 * see description below the nids_params definition
	 */
	/*
	 * 参见nids_params定义部分的描述
	 * 函数定义类型为nids_syslog(int type,int errnum,struct ip_header * iph,void *data)
	 */
	void (*syslog)(); // 函数指针, 默认值为nids_syslog()函数. 在syslog中可以检测入侵攻击, 如: 网络扫描攻击

	/*
	 * if nids_params.syslog==nids_syslog, then this field
	 * determines loglevel used by reporting events by
	 * system daemon syslogd; default value: LOG_ALERT
	 */
	/*
	 * 如果 nids_params.syslog==nids_syslog, 那么这个域将决定
	 * 系统守护进程syslogd报告事件所使用的等级loglevel.
	 * 默认值: LOG_ALERT
	 */
	int syslog_level; // 表示日志等级, 默认值为LOG_ALERT.

	/*
	 * size of hash table used for storing info on port
	 * scanning; the number of simultaneuos port
	 * scan attempts libnids will detect. if set to
	 * 0, port scanning detection will be turned
	 * off. Default value: 256.
	 */
	/*
	 * 用于存储关于端口扫描的信息的Hash表的大小; Libndis能够检测
	 * 到的同时发生的端口扫描企图. 如果设置为0, 端口扫描检测将被关闭
	 * 默认值: 256
	 */
	int scan_num_hosts; // 表示存储端口扫描信息的哈希表的大小

	/*
	 * with no more than scan_delay milisecond pause
	 * between two ports, in order to make libnids report
	 * portscan attempt. Default value: 3000
	 */
	/*
	 * 两个端口之间最大的扫描间隔
	 * 用于使Libnids可以报告端口扫描企图
	 * 默认值: 3000
	 */
	int scan_delay; // 表示在扫描检测中, 两端口扫描的间隔时间

	/*
	 * how many TCP ports has to be scanned from the same
	 * source. Default value: 10.
	 */
	/*
	 * 多少个TCP端口必须被同一个源地址扫描
	 * 默认值: 10
	 */
	int scan_num_ports; // 表示相同源地址必须扫描的tcp端口数目

	/*
	 * called when libnids runs out of memory; it should
	 * terminate the current process
	 */
	/*
	 * 当Libndis的内存资源耗尽时调用此函数
	 * 它应该终止当前进程
	 */
	void (*no_mem)(char *); // 当libnids发生内存溢出时被调用

	/*
	 * this function is consulted when an IP
	 * packet arrives; if ip_filter returns non-zero, the
	 * packet is processed, else it is discarded. This way
	 * one can monitor traffic directed at selected hosts
	 * only, not entire subnet. Default function
	 * (nids_ip_filter) always returns 1
	 */
	/*
	 * 这个参数当IP数据包到达时才会被考虑
	 * 如果ip_filter返回non-zero, 处理这个包否则忽略掉
	 * 通过这种方式, 可以只监控所选中的主机, 而不是整个子网
	 * 默认函数: (nids_ip_filter), 一般返回值为: 1
	 */
	/*
	 * 函数指针, 此函数可以用来分析ip数据包, 当有ip数据包到达时, 此函数被调用. 默认值为nids_ip_filter, 该函数的定义如下:
	 * static int nids_ip_filter(struct ip * x,int len)
	 */
	int (*ip_filter)();

	/*
	 * filter string to hand to pcap(3). Default is
	 * NULL. be aware that this applies to the
	 * link-layer, so filters like "tcp dst port 23"
	 * will NOT correctly handle fragmented traffic; one
	 * should add "or (ip[6:2] & 0x1fff != 0)" to process
	 * all fragmented packets
	 */
	/*
	 * 用于pcap地过滤字符串, 默认情况下为NULL.
	 * 需要了解的是这强应用到link-layer, 所以象"tcp dst port 23"
	 * 一样的过滤器无法控制碎片传输.
	 */
	char *pcap_filter; // 表示过滤规则

	/*
	 * if non-zero, the device(s) libnids reads packets
	 * from will be put in promiscuous mode. Default: 1
	 */
	/*
	 * 如果非零, Libnids读取数据包的设备将被设置为混杂模式
	 * 默认值为: 1
	 */
	int promisc; // 表示网卡模式, 非0为混杂模式, 否则为非混杂模式, 默认值为1

	/*
	 * disabled by default; see the explanation
	 */
	/*
	 * 默认情况下不可用
	 */
	int one_loop_less; // 表示捕获数据返回的时间, 以豪秒计算. 默认值为1024

	/*
	 * the "timeout" parameter to pcap_open_live
	 * 1024 (ms) by default ; change to a lower value
	 * if you want a quick reaction to traffic; this
	 * is present starting with libnids-1.20
	 */
	int pcap_timeout;

	/*
	 * start ip defragmentation and tcp stream assembly in a
	 * different thread parameter to a nonzero value and
	 * compiling libnids in an environment where  glib-2.0 is
	 * available enables libnids to use two different threads
	 * - one for receiving IP fragments from libpcap,
	 * and one, with lower priority, to process fragments,
	 * streams and to notify callbacks. Preferrably using
	 * nids_run() this behavior is invisible to the user.
	 * Using this functionality with nids_next() is quite
	 * useless since the thread must be started and stopped
	 * for every packet received.
	 * Also, if it is enabled, global variables (nids_last_pcap_header
	 * and nids_last_pcap_data) may not point to the
	 * packet currently processed by a callback
	 */
	int multiproc;

	/*
	 * limit on the number of packets to be queued;
	 * used only when multiproc=true; 20000 by default
	 */
	int queue_limit;

	/*
	 * enable (hopefully harmless) workarounds for some
	 * non-rfc-compliant TCP/IP stacks
	 */
	int tcp_workarounds;

	/*
	 * pcap descriptor
	 */
	pcap_t *pcap_desc;
};

struct tcp_timeout {
	struct tcp_stream *a_tcp;
	struct timeval timeout;
	struct tcp_timeout *next;
	struct tcp_timeout *prev;
};

int nids_init(void);
void nids_register_ip_frag(void (*));
void nids_unregister_ip_frag(void (*));
void nids_register_ip(void (*));
void nids_unregister_ip(void (*));
void nids_register_tcp(void (*));
void nids_unregister_tcp(void (*x));
void nids_register_udp(void (*));
void nids_unregister_udp(void (*));
void nids_killtcp(struct tcp_stream *);
void nids_discard(struct tcp_stream *, int);
int nids_run(void);
void nids_exit(void);
int nids_getfd(void);
int nids_dispatch(int);
int nids_next(void);
void nids_pcap_handler(u_char *, struct pcap_pkthdr *, u_char *);
struct tcp_stream *nids_find_tcp_stream(struct tuple4 *);
void nids_free_tcp_stream(struct tcp_stream *);

extern struct nids_prm nids_params;
extern char *nids_warnings[];
extern char nids_errbuf[];
extern struct pcap_pkthdr *nids_last_pcap_header;
extern u_char *nids_last_pcap_data;
extern u_int nids_linkoffset;
extern struct tcp_timeout *nids_tcp_timeouts;

/*
 * @brief 计算校验和
 */
struct nids_chksum_ctl {
	u_int netaddr;
	u_int mask;
	u_int action; // 表示动作, 如果是NIDS_DO_CHKSUM, 表示要计算校验和; 如果是NIDS_DONT_CHKSUM表示不计算校验和
	u_int reserved;
};
extern void nids_register_chksum_ctl(struct nids_chksum_ctl *, int);

# ifdef __cplusplus
}
# endif

#endif /* _NIDS_NIDS_H */
