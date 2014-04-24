
/*
 * @file nids.h
 *
 * @author Akagi201
 * @date 2014/04/24
 *
 * libnids定义的数据结构和函数的声明集中在头文件nids.h中.
 * 使用libnids的应用程序必须包含这个文件, 并且要与libnids.a(或者libnids.so.x.y)进行连接.
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

# define NIDS_MAJOR 1
# define NIDS_MINOR 24

enum
{
  NIDS_WARN_IP = 1,
  NIDS_WARN_TCP,
  NIDS_WARN_UDP,
  NIDS_WARN_SCAN
};

enum
{
  NIDS_WARN_UNDEFINED = 0,
  NIDS_WARN_IP_OVERSIZED,
  NIDS_WARN_IP_INVLIST,
  NIDS_WARN_IP_OVERLAP,
  NIDS_WARN_IP_HDR,
  NIDS_WARN_IP_SRR,
  NIDS_WARN_TCP_TOOMUCH,
  NIDS_WARN_TCP_HDR,
  NIDS_WARN_TCP_BIGQUEUE,
  NIDS_WARN_TCP_BADFLAGS
};

# define NIDS_JUST_EST (1)
# define NIDS_DATA (2)
# define NIDS_CLOSE (3)
# define NIDS_RESET (4)
# define NIDS_TIMED_OUT (5)
# define NIDS_EXITING   (6)	/* nids is exiting; last chance to get data */

# define NIDS_DO_CHKSUM  (0)
# define NIDS_DONT_CHKSUM (1)

/*
 * @brief TCP连接参数4元组
 */
struct tuple4
{
  u_short source; // 源端口
  u_short dest; // 目的端口
  u_int saddr; // 源地址
  u_int daddr; // 目的地址
};

/*
 * @brief TCP连接一侧的描述结构
 *
 * structure describing one side of a TCP connection
 */
struct half_stream
{
  char state; // socket state (ie TCP_ESTABLISHED)
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
  char collect;
  // 类似地, 判断是否为紧急数据
  char collect_urg; // analogically, determines if to collect urgent data

  char *data; // buffer for normal data 正常数据缓冲区

  /*
   * offset (in data stream) of first byte stored in
   * the "data" buffer; additional explanations follow
   */
  int offset;

  /*
   * how many bytes has been appended to buffer "data"
   * since the creation of a connection
   */
  int count; // 自连接建立以来已经有多少字节已经发送到data缓冲区中

  /*
   * how many bytes were appended to "data" buffer
   * last (this) time; if == 0, no new data arrived
   */
  int count_new; // 多少字节将被发送到data缓冲区中last (this) time;
  int bufsize;
  int rmem_alloc;

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata; // one-byte buffer for urgent data
  u_char count_new_urg; // if != 0, new urgent data arrived 如果不等于0, 新的紧急数据到达
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
 * @brief TCP流信息
 */
struct tcp_stream
{
  struct tuple4 addr; // connections params (saddr, daddr, sport, dport)
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
  void *user;
};

struct nids_prm
{
  int n_tcp_streams;
  int n_hosts;
  char *device;
  char *filename;
  int sk_buff_size;
  int dev_addon;
  void (*syslog) ();
  int syslog_level;
  int scan_num_hosts;
  int scan_delay;
  int scan_num_ports;
  void (*no_mem) (char *);
  int (*ip_filter) ();
  char *pcap_filter;
  int promisc;
  int one_loop_less;
  int pcap_timeout;
  int multiproc;
  int queue_limit;
  int tcp_workarounds;
  pcap_t *pcap_desc;
};

struct tcp_timeout
{
  struct tcp_stream *a_tcp;
  struct timeval timeout;
  struct tcp_timeout *next;
  struct tcp_timeout *prev;
};

int nids_init (void);
void nids_register_ip_frag (void (*));
void nids_unregister_ip_frag (void (*));
void nids_register_ip (void (*));
void nids_unregister_ip (void (*));
void nids_register_tcp (void (*));
void nids_unregister_tcp (void (*x));
void nids_register_udp (void (*));
void nids_unregister_udp (void (*));
void nids_killtcp (struct tcp_stream *);
void nids_discard (struct tcp_stream *, int);
int nids_run (void);
void nids_exit(void);
int nids_getfd (void);
int nids_dispatch (int);
int nids_next (void);
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

struct nids_chksum_ctl {
	u_int netaddr;
	u_int mask;
	u_int action;
	u_int reserved;
};
extern void nids_register_chksum_ctl(struct nids_chksum_ctl *, int);

# ifdef __cplusplus
}
# endif

#endif /* _NIDS_NIDS_H */
