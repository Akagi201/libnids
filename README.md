aklibnids
=========

libnids是一个用于网络入侵检测开发的专业编程接口,它使用了libpcap, 所以, 它具有捕获数据包的功能. 同时, libnids提供了TCP数据流重组功能, 所以, 对于分析基于TCP协议的各种协议Libnids都能胜任. libnids还提供了对IP分片进行重组的功能, 以及端口扫描检测和异常数据包检测功能.

## What

* libnids是网络入侵检测系统(IDS)的E-component的一个实现(NIDS E-component library).
* 他模拟了linux 2.0.x的IP stack.
* libnids提供IP重组, TCP stream assembly和TCP端口扫描检测.
* libnids的最有价值的特性是可靠性.
* 许多测试表明libnids能尽可能地预测受保护的linux主机的行为.
* libnids是运行时高度可配置的, 并且提供一个方便的接口.
* 使用libnids可以方便的访问一个TCP流的数据, 无论攻击者多么巧妙的掩盖.
* libnids被Rafal Wojtczuk设计.

## Related project
* [fragrouter by Dug Song](http://www.monkey.org/~dugsong/fragroute/)

## Related paper
* [Eluding Network Intrusion Detection](http://insecure.org/stf/secnet_ids/secnet_ids.html)

## Refs
* <http://libnids.sourceforge.net/>
* [libnids API中文版](http://www.linuxnote.org/libnids-api-chinese-version.html)

