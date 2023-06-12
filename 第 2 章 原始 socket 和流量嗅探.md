---
title: 第 2 章 原始socket和流量嗅探
tags: 
- [python]
- [black_hat_python]
categories: 
- [python]
- [black_hat_python]
date: 2022-06-15
mathjax: true
comment: true
---

个人的知识笔记。

<!-- more -->

# 1. UDP Host Discovery Tool
## 1.1. Windows/Linux分组嗅探
UDP来探测端口与TCP不同，攻击者发送UDP数据报给目标主机的一个或多个端口，

- 如果目标主机不存在，那么就不会收到任何消息（废话）
- 如果目标主机存在，但是对应端口关闭，那么就会在一段时间之后收到 ICMP 消息，提示端口不可达
- 如果目标主机存在，对应端口也处于开放状态，也不会收到任何回应

```python
import os
import socket

# host to listen on
Host = '10.0.2.4'

def main():
    if os.name == 'nt': # windows
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((Host, 0)) # 端口随意
    # 在捕获的数据包中包含IP头
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # 在Windows平台上，需要设置IOCTL以启用混杂模式
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    # 读取单个数据包
    print(sniffer.recv(65535))
    # 在Windows平台上，关闭IOCTL的混杂模式
    if os.name == 'nt': 
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == '__main__':
    main()
```

不同平台的 `os.name` 是不同的：

1. Windows
   
   ![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220614195653.png)

2. Linux
   
   ![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220614195715.png)


Windows的IOCTL允许嗅探所有协议的分组，但Linux只能嗅探ICMP分组（根据socket对象创建的时候的参数决定）。


解释：

1. `sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)` 创建一个基于 socket_protocol 的raw socket
2. `sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)` 设置为 IPPROTO_IP 即接收所有IP分组；并且必须设置 IP_HDRINCL。

运行结果：（需要使用 root 权限运行！！！）

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220614222003.png)

仅仅只是接收了分组，并没有对分组进行解码。

上面是ping的情况，如果不是ICMP的协议就不会嗅探：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220614223214.png)

如果是在Windows平台，则所有分组都能捕捉

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220614223244.png)

（我都还没有ping就已经捕捉了）

## 1.2. 解析IP头部
根据上一小节的分析，现在已经可以捕捉任何协议的IP分组了，但是捕捉到的分组是二进制的，难以理解。因此，下一步的工作就是解析IP分组中的IP头部，提取出IP头部的字段信息。首先看一下IP协议的头部的样子：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220614223833.png)

我们需要做的就是提取协议类型、源IP和目标IP。这意味着我们需要直接在二进制中分离出各个字段。在python中，可以使用 `ctypes` 或者 `struct` 模块。前者它为基于 C 的语言提供了一座桥梁，使你能够使用与 C 兼容的数据类型并在共享库中调用函数。后者在 Python 值和以 Python 字节对象表示的 C 结构之间进行转换。换句话说，`ctypes` 模块除了处理二进制数据类型外，还提供了很多其他功能，而 `struct` 模块主要处理二进制数据。

编写如下用来解析IP头部的代码：
```python
import ipaddress
import os
import socket
import struct
import sys


# 构建IP头部
class IP: 
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.flags = header[4] & 0x7
        self.offset = header[4] >> 3
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # human readable IP address
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocl constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print("%s No protocol for %s" %(e, self.protocol_num))

def sniff(host):
    # create raw socket, bin to public interface
    if os.name == 'nt': # windows
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 1))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_packet = sniffer.recvfrom(65535)[0]
            ip_header = IP(raw_packet[:20])
            print('Protocol %s, src: %s -> dst: %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
    except KeyboardInterrupt:
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '10.0.2.4'
    sniff(host)
```

1. 首先利用 `struct` 模块创建IP head 类。
2. 在类中，调用 `ipaddress.ip_address` 将二进制的IP地址转化为字符串
3. 在类中，还将得到的 protocol_num 做匹配，得到对应的 protocol 名
4. 与前一个代码不同的是，这里使用了无限循环，可以一直捕捉分组

在Windows上的运行结果：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220615141248.png)

在Linux上的运行结果：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220615141201.png)


## 1.3. 解析ICMP头部
>ICMP处于网络层，但在IP之上。因此ICMP数据包是在IP head之后

ICMP分组的头部：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220614232223.png)

其中，ICMP目标不可达报文格式如下：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220615141722.png)

```python
import struct  
import ipaddress  
import sys  
import socket  
import os  
  
class IP:  
    def __init__(self, buff=None):  
        header = struct.unpack('<BBHHHBBH4s4s', buff)  
        self.ver = header[0] >> 4  
        self.ihl = header[0] & 0xF  
  
        self.tos = header[1]  
        self.len = header[2]  
        self.id = header[3]  
        self.flags = header[4] & 0x7  
        self.offset = header[4] >> 3  
        self.ttl = header[5]  
        self.protocol_num = header[6]  
        self.sum = header[7]  
        self.src = header[8]  
        self.dst = header[9]  
  
        # human readabl IP address  
        self.src_address = ipaddress.ip_address(self.src)  
        self.dst_address = ipaddress.ip_address(self.dst)  
  
        # map protocl constants to their names  
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}  
        try:  
            self.protocol = self.protocol_map[self.protocol_num]  
        except Exception as e:  
            print("%s No protocol for %s" %(e, self.protocol_num))  

# 构建IMCP头部
class ICMP:  
    def __init__(self, buff=None):  
        header = struct.unpack('<BBHHH', buff)  
        self.type = header[0]  
        self.code = header[1]  
        self.head_checksum = header[2]  
        self.unused = header[3]  
        self.Next_hop_MTU = header[4]  
  
def sniff(host):  
    # create raw socket, bin to public interface  
    if os.name == 'nt': # windows  
        socket_protocol = socket.IPPROTO_IP  
    else:  
        socket_protocol = socket.IPPROTO_ICMP  
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)  
    sniffer.bind((host, 1))  
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  
    if os.name == 'nt':  
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  
  
    try:  
        while True:  
            raw_packet = sniffer.recvfrom(65535)[0]  
            ip_header = IP(raw_packet[:20])  
            if ip_header.protocol == 'ICMP':  
                print('Protocol %s, src: %s -> dst: %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))  
                print('Version: %s' % ip_header.ver)  
                print(f'Head Length: {ip_header.ihl}, TTL: {ip_header.ttl}')  
  
                # caculate where ICMP packet start, ihl=1 -> 1 line -> 32bits -> 4bits  
                offset = ip_header.ihl * 4  
                icmp_header = ICMP(raw_packet[offset: offset+8])  
                print('ICMP -> Type: %s, Code: %s' % (icmp_header.type, icmp_header.code))  
  
    except KeyboardInterrupt:  
        if os.name == 'nt':  
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  
        sys.exit(0)  
  
if __name__ == '__main__':  
    if len(sys.argv) == 2:  
        host = sys.argv[1]  
    else:  
        host = '10.0.2.4'  
    sniff(host)
```

- 从计算ICMP packet开始位置可以知道，IP head 之后才是ICMP packet
- IP head中的Head Length长度的单位是4byte。IP head一般为20byte，所以Head Length一般为5。（一种更简单的方法，看上面的IP头部的图中，一行就是4byte，可以理解为Head Length的单位是“1行”）

运行结果：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220615153907.png)

首先可以看到ping的响应被正确接收，其次可以看到 ping 响应的ICMP分组的 Type 和 Code 都为0，这表示这个ICMP为 ICMP Echo——回显应答。

## 1.4. 子网扫描
往上面的代码添加一些内容，使我们能够对整个子网进行扫描。

```python
import ipaddress, os, socket, struct, sys, threading, time  
  
SUBNET = '10.0.2.0/24'  
MESSAGE = 'PYTHONRULES!'  
  
class IP:  
    def __init__(self, buff=None):  
        header = struct.unpack('<BBHHHBBH4s4s', buff)  
        self.ver = header[0] >> 4  
        self.ihl = header[0] & 0xF  
  
        self.tos = header[1]  
        self.len = header[2]  
        self.id = header[3]  
        self.flags = header[4] & 0x7  
        self.offset = header[4] >> 3  
        self.ttl = header[5]  
        self.protocol_num = header[6]  
        self.sum = header[7]  
        self.src = header[8]  
        self.dst = header[9]  
  
        # human readabl IP address  
        self.src_address = ipaddress.ip_address(self.src)  
        self.dst_address = ipaddress.ip_address(self.dst)  
  
        # map protocl constants to their names  
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}  
        try:  
            self.protocol = self.protocol_map[self.protocol_num]  
        except Exception as e:  
            print("%s No protocol for %s" %(e, self.protocol_num))  
  
class ICMP:  
    def __init__(self, buff=None):  
        header = struct.unpack('<BBHHH', buff)  
        self.type = header[0]  
        self.code = header[1]  
        self.head_checksum = header[2]  
        self.unused = header[3]  
        self.Next_hop_MTU = header[4]  
  
class Scanner():  
    def __init__(self, host):  
        self.host = host  
        if os.name == 'nt':  
            socket_protocol = socket.IPPROTO_IP  
        else:  
            socket_protocol = socket.IPPROTO_ICMP  
  
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)  
        self.socket.bind((host, 0))  
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  
        if os.name == 'nt':  
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  
  
    def sniff(self):  
        hosts_up = []  
        hosts_up.append(self.host)  
  
        try:  
            while True:  
                raw_buffer = self.socket.recvfrom(65535)[0]  
                ip_header = IP(raw_buffer[: 20])  
                if ip_header.protocol == 'ICMP':  
                    offset = ip_header.ihl * 4  
                    icmp_header = ICMP(raw_buffer[offset: offset+8])  
                    if icmp_header.code == 3 and icmp_header.type == 3: # type=3 and code=3 indicate target's port unreachable  
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):  
                            if raw_buffer[len(raw_buffer) - len(MESSAGE): ] == bytes(MESSAGE, 'utf-8'):  
                                tgt = str(ip_header.src_address)  
                                if tgt != self.host and tgt not in hosts_up:  
                                    hosts_up.append(str(ip_header.src_address))  
                                    print(f'Host Up: {tgt}')  
        # handler CTRL-C  
        except KeyboardInterrupt:  
            if os.name == 'nt':  
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  
  
            print('\nUser interrupted.')  
            if hosts_up:  
                print(f'\n\nSummary: Hosts up op {SUBNET}')  
            for host in sorted(hosts_up):  
                print(f'{host}')  
            print('')  
            sys.exit()  
  
def udp_sender():  
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:  
        for ip in ipaddress.ip_network(SUBNET).hosts():  
            sender.sendto(bytes(MESSAGE, 'utf-8'), (str(ip), 65212))  
  
if __name__ == '__main__':  
    if len(sys.argv) == 2:  
        host = sys.argv[1]  
    else:  
        host = '10.0.2.4'  
  
    s = Scanner(host)  
    time.sleep(5)  
    t = threading.Thread(target=udp_sender)  
    t.start()  
    s.sniff()
```

想先重点说明一下 `if raw_buffer[len(raw_buffer) - len(MESSAGE): ] == bytes(MESSAGE, 'utf-8')`。我们发送的UDP分组是带有MESSAGE数据的，因此如果收到ICMP分组，那么ICMP分组中的 **最后** 就是发送的数据，即MESSAGE。因此，我们对收到的分组需要做以下验证工作：

1. 是否为ICMP？
2. ICMP分组中是否满足 `Type=3, Code=3`？
3. 发来ICMP分组的主机是否在子网内？
4. 这个ICMP分组是否带有数据MESSAGE？带有数据说明是对之前发的UDP的响应，不带有数据则说明不是UDP的响应，我们需要丢弃

上述代码的工作流程：

1. 先执行 `upd_sender()` 函数，向host所在子网广播udp，目标端口为 65212（随便选一个）
2. 然后执行 `s.sniff()` 方法：
	1. 捕捉到来的分组，提取IP头部
	2. 做上述4个验证工作
	3. 验证通过则将发来ICMP分组的host加入 `host_up` 列表中



运行结果：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220615211142.png)


