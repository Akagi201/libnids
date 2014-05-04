/*
 * @file printal.c
 *
 * @author Akagi201
 * @date 2014/04/24
 *
 * 在stderr中显示Libnids所监视到的所有TCP连接所交换的数据
 *
 */

/*
 Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
 See the file COPYING for license details.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "nids.h"

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23

/*
 * @brief 下面的辅助函数生成一个类似 "10.0.0.1,1024,10.0.0.2,23" 的字符串来表示一个TCP连接信息
 * 格式为: 源地址,源端口,目的地址,目的端口
 * @param[in] addr: TCP连接的地址和端口
 * @return
 */
char *
adres(struct tuple4 addr) {
	static char buf[256] = { 0 };
	strcpy(buf, int_ntoa(addr.saddr));
	sprintf(buf + strlen(buf), ",%i,", addr.source);
	strcat(buf, int_ntoa(addr.daddr));
	sprintf(buf + strlen(buf), ",%i", addr.dest);
	return buf;
}

/*
 * @brief
 *
 * 在上面的例子程序中, 函数tcp_callback打印 hlf->data缓冲区的数据到stderr上, 并且这些数据不再需要了.
 * 在tcp_callback返回后, 默认情况下Libnids释放这些数据占用的空间.
 * hlf->offset域将增加丢弃的字节数, 并且新的数据将存储到data缓冲区的开始.
 * 如果上面的操作不是我们所希望的, (例如，数据处理器需要至少N字节的输入来处理, 并且迄今为止Libnids接收到的count_new<N字节), 你需要在tcp_callback返回前,调用下面的函数:
 * void nids_discard(struct tcp_stream * a_tcp, int num_bytes);
 * 结果, 在 tcp_callback返回后, Libnids将丢弃data缓冲区中至多num_bytes字节的前面的内容(相应地更新offset域, 移动剩下的数据到data缓冲区的开始位置).
 * 如果nids_discard函数没有被调用(像这个例子程序)缓冲区 hlf->data就正好包含hlf->count_new字节的内容.
 * 一般情况下, 缓冲区 hlf->data中的字节数等于hlf->count-hlf->offset.
 * 多亏了nids_discard函数, 程序员不必把接收到的数据拷贝到一个独立的缓冲区中. hlf->data将一直包含尽可能多的数据.
 * 可是, 经常发生一个需求来维持每一个对(libnids_callback, tcp stream)的辅助数据结构.
 * 例如, 如果我们希望检测一个针对wu-ftpd的攻击(这个攻击包括在服务器上建立深层目录), 我们需要将Ftpd守护进程的当前目录存储到某一个地方.
 * 将通过Ftp客户端发送CWD指令来改变. 这就是tcp_callback的第二个参数的用途.
 * 它是每一个对(libnids_callback, tcp stream)的私有的数据的指针的指针.
 * 通常, 我们应该这样使用他:

 void tcp_callback_2(struct tcp_stream *a_tcp, struct conn_param **ptr) {
 if (NIDS_JUST_EST == a_tcp->nids_state) {
 struct conn_param *a_conn;
 if the connection is uninteresting, return;// 如果连接是我们不感兴趣的就返回
 a_conn = malloc of some data structure; // 分配内存
 init of a_conn; // 初始化
 // 这个值在将来的调用中将被传递给tcp_callback_2增加一些"collect"域
 *ptr = a_conn; // this value will be passed to tcp_callback_2 in future calls increase some of "collect" fields;
 return;
 }

 if (NIDS_DATA == a_tcp->nids_state) {
 struct conn_param *current_conn_param = *ptr;
 using current_conn_param and the newly received data from the net;
 we search for attack signatures, possibly modifying;
 current_conn_param;
 return;
 }
 }
 * 函数 nids_register_tcp 和 nids_register_ip* 可以被调用任意次数.
 * 2种不同的函数(类似tcp_callback)允许跟踪同一个TCP流(带有某个非默认的exception).
 *
 */
void tcp_callback(struct tcp_stream *a_tcp, void ** this_time_not_needed) {
	char buf[1024] = { 0 };
	strcpy(buf, adres(a_tcp->addr)); // we put conn params into buf
	if (NIDS_JUST_EST == a_tcp->nids_state) {
		// connection described by a_tcp is established 由a_tcp描述的连接已经建立
		// here we decide, if we wish to follow this stream 这里我们决定是否希望跟踪这个流
		// sample condition: if (a_tcp->addr.dest!=23) return; 例子条件: if (a_tcp->addr.dest!=23) return;
		// in this simple app we follow each stream, so.. 在本程序中, 我们跟踪所有的流, 所以...
		a_tcp->client.collect++; // we want data received by a client 我们需要客户端接收到的数据
		a_tcp->server.collect++; // and by a server, too 我们也需要服务器接收到的数据
		a_tcp->server.collect_urg++; // we want urgent data received by a server 我们需要服务器接收到的紧急数据

#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
		// 如果我们不增加这个值, 当紧急数据到达时我们不会被通知.
		a_tcp->client.collect_urg++;// if we don't increase this value,
									// we won't be notified of urgent data
									// arrival
#endif
		fprintf(stderr, "%s established\n", buf);
		return;
	}
	if (a_tcp->nids_state == NIDS_CLOSE) {
		// connection has been closed normally 连接已经正常结束
		fprintf(stderr, "%s closing\n", buf);
		return;
	}
	if (a_tcp->nids_state == NIDS_RESET) {
		// connection has been closed by RST 连接已经通过RST关闭
		fprintf(stderr, "%s reset\n", buf);
		return;
	}

	if (a_tcp->nids_state == NIDS_DATA) {
		// new data has arrived; gotta determine in what direction 新的数据已经到达, 必须判断其数据流向
		// and if it's urgent or not 判断其是否紧急数据

		struct half_stream *hlf;

		if (a_tcp->server.count_new_urg) {
			// new byte of urgent data has arrived 紧急数据的新字节已经到达
			strcat(buf, "(urgent->)");
			buf[strlen(buf) + 1] = 0;
			buf[strlen(buf)] = a_tcp->server.urgdata;
			write(1, buf, strlen(buf));
			return;
		}
		// We don't have to check if urgent data to client has arrived, 我们不必检查是否客户端的紧急数据已经到达
		// because we haven't increased a_tcp->client.collect_urg variable. 因为我们没有增加a_tcp->client.collect_urg的值
		// So, we have some normal data to take care of. 因此，我们还有一些正常的数据关心
		if (a_tcp->client.count_new) {
			// new data for client 客户端的新数据
			hlf = &a_tcp->client; // from now on, we will deal with hlf var, 现在我们将处理hlf变量
								  // which will point to client side of conn 这个变量指向客户端的一边的连接.
			strcat(buf, "(<-)"); // symbolic direction of data 数据的符号方向
		} else {
			hlf = &a_tcp->server; // analogical 类似的
			strcat(buf, "(->)");
		}
		// 我们打印连接参数(saddr, daddr, sport, dport)和数据流向(-> or <-)
		fprintf(stderr, "%s", buf); // we print the connection parameters
									// (saddr, daddr, sport, dport) accompanied
									// by data flow direction (-> or <-)

		write(2, hlf->data, hlf->count_new); // we print the newly arrived data 我们打印最新到达的数据到stderr

	}
	return;
}

int main(void) {
	// here we can alter libnids params, for instance:
	// nids_params.n_hosts=256;
	// 这里我们可以改变Libnids的params, 例如 nids_params.n_hosts=256;
	if (!nids_init()) {
		fprintf(stderr, "%s\n", nids_errbuf);
		exit(1);
	}
	nids_register_tcp(tcp_callback);
	nids_run();
	return 0;
}

