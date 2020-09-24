# DNS安全学习文档

## **1.** 安全篇（网络功能，DNS安全，DNS缓存）

### **1.1** 网络功能

#### **1.1.1** 流量牵引

（网络安全领域）就是将攻击流量和正常流量进行分离，由抗DDoS设备（defender）来专门抵抗DDoS攻击，保证正常流量尽可能的不受到攻击的干扰。

- 提出原因：为了防御大规模DDoS攻击和避免单点故障问题而提出的，即当单点故障出现时可以及时解决而保证其他流量正常运作。

- 应用场景：应用于IDC（互联网数据中心）单个设备故障；DDOS攻击防御

- 如何实现：server1遭受到了DDoS攻击，Probe监测到攻击行为后，目标为server1的流量将被转发到Defender。这些流量到达抗DDoS设备后，经过一系列的检测、甄别、过滤等算法，剩余的合法流量将继续被转发到R2。而此时其它的流量仍然保持原来的路线，即直接从R1转发到R2。（即分流）

#### **1.1.2** 流量回注

在不影响正常业务的前提下，将清洗（流量清洗服务是提供给租用IDC服务的政企客户，针对对其发起的DOS/[DDOS](https://baike.baidu.com/item/DDOS)攻击的监控、告警和防护的一种网络安全服务。）后的流量回注到原网络中的配置，有效满足客户对IDC运作连续性的要求

- 如何实现：流量回注通常与引流联系在一起

 ![image](https://github.com/Chengtao2020/mkdown_images/1.png)

- 应用场景：应用于抗DDOS的系统当中

### 1.2 DNS安全

#### 1.2.1异常报文攻击过滤

当维护人员配置错误或网络受到恶意攻击时，设备可能会收到非预期的STP（生成树协议）/RSTP（快速生成树协议）/MSTP（多生成树协议）报文，这种非预期的报文在网络中透传可能会影响生成树计算，引起网络震荡。为了防止以上情况的发生，可部署异常报文过滤功能。

- 提出原因：TCP报文头中存在六个标志位字段，代表不同的含义，标志位的值置为1，表示该标志位起作用。这六个标志位在TCP交互过程中各司其职，标志位置1与否必须严格遵循TCP协议规范。如果不遵循规范随意将标志位置0或置1，这类报文就称为TCP异常报文。接收方处理这些异常报文时会消耗系统资源，甚至可能会导致系统崩溃。攻击者也可以利用TCP异常报文来发起DDoS攻击，向被攻击目标发送大量的构造的TCP异常报文，导致被攻击目标系统资源耗尽、网络拥塞，无法正常提供服务。

- 可实现的功能：可以支持对进入系统的异常报文进行识别和防御，如IP异常包，TCP异常包，UDP异常包，DNS异常包。为系统面临的威胁提供依据

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps15.jpg) 

- 应用场景：对进入系统的每个报文进行合法检测能够更加完整的为系统的全局的安全审计和分析提供更全面的判断依据，可以发现可疑的客户端，异常软件的可疑行为。协助用户更好的管理网络，让客户的网络达到可控的目标。

- 如何实现：原SmartDDI的异常包过滤功能。

- 测试工具：mz

例如：银联DNS测试方案中的DNS异常过滤和UDP异常过滤

DNS异常测试步骤：

1、打开DNS异常包过滤功能；

2、在客户机上发送大量DNS异常包到被测DNS设备上，查看安全过滤流量情况；

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps16.jpg) 

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps17.jpg) 

 

#### 1.2.2 IP分片攻击过滤

如果IP层有数据包要传，而且数据包的长度超过了MTU（最大传输单元），那么IP层就要对数据包进行分片（fragmentation）操作，使每一片的长度都小于或等于MTU。如果有意发送总长度长于报文的碎片时， 老的内核回崩溃或者拒绝服务；如果分片偏移量精心构造，系统也会死机。

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps18.jpg) 

 

- 应用场景：阻挡诸如ping o’death，jolt2，teardrop 等碎片攻击的场景 

- 如何实现：可以使用iptables限制每秒通过碎片包的数目；目前分片攻击在Linux上已经不受影响，如果在Windows上需要部署最新的Service Pack

 

#### 1.2.2 DDOS攻击过滤

分布式[拒绝服务攻击](https://baike.baidu.com/item/拒绝服务攻击/421896)(英文意思是Distributed Denial of Service，简称DDoS)是指处于不同位置的多个攻击者同时向一个或数个目标发动攻击，或者一个攻击者控制了位于不同位置的多台机器并利用这些机器对受害者同时实施攻击。

##### 1.2.2.1 SYN Flood攻击过滤

攻击者首先伪造地址对服务器发起SYN请求（我可以建立连接吗？），服务器就会回应一个ACK+SYN（可以+请确认）。而真实的IP会认为，我没有发送请求，不作回应。服务器没有收到回应，会重试3-5次并且等待一个SYN Time（一般30秒-2分钟）后，丢弃这个连接。大量的请求会造成服务器的瘫痪



如何实现：

1. SYN Proxy功能，这种方法一般是定每秒通过指定对象（目标地址和端口、仅目标地址或仅源地址）的SYN片段数的阀值，当来自相同源地址或发往相同目标地址的SYN片段数达到这些阀值之一时，防火墙就开始截取连接请求和代理回复SYN/ACK片段，并将不完全的连接请求存储到连接队列中直到连接完成或请求超时。当防火墙中代理连接的队列被填满时，防火墙拒绝来自相同安全区域（zone）中所有地址的新SYN片段，避免网络主机遭受不完整的三次握手的攻击。

2. SYN Cookie：给每一个请求连接的IP地址分配一个Cookie，如果短时间	内连续受到某个IP的重复SYN报文，就认定是受到了攻击，以后从这个IP	地址来的包会被丢弃

 

##### 1.2.2.2 ACKFlood攻击过滤

通常与其他攻击混合使用，单独使用冲击力较小，原理同SYN Flood大致相似。

- 如何实现：对称型判断，就是收包异常大于发包，因为攻击者通常会采用大量ACK包，并且为了提高攻击速度，一般采用内容基本一致的小包发送

 

##### 1.2.2.3 UDPDDOS攻击过滤（较为困难）

UDP由于是无连接的，攻击者可发送大量伪造源IP地址的小UDP包，针对相关的服务进行攻击，UDP包双向流量会基本相等，而且大小和内容都是随机的，变化很大。

Ø 如何实现：判断包大小，如果是大包攻击则使用防止UDP碎片方法：根据攻击包大小设定包碎片重组大小，通常不小于1500。在极端情况下，可以考虑丢弃所有UDP碎片。
攻击端口为业务端口：根据该业务UDP最大包长设置UDP最大包大小以过滤异常流量。
攻击端口为非业务端口：一个是丢弃所有UDP包，可能会误伤正常业务；一个是建立UDP连接规则，要求所有去往该端口的UDP包，必须首先与TCP端口建立TCP连接。不过这种方法需要很专业的防火墙或其他防护设备支持。

 

##### 1.2.3 DNS的DDOS攻击过滤

 

***\*白名单：\****

IP白名单：IP白名单是用来调用API的服务器IP，设置后，只允许在IP白名单范围内的服务器IP过来调用API，非白名单IP无法调用API。

 

域名白名单：[CNNIC](https://baike.baidu.com/item/CNNIC)基于现行政策所推出的便民制度。CN、TOP等域名的注册者只要通过了CNNIC的审核进入“白名单”，就可以简化域名注册、过户、交易出售等操作

 

- 实现方式：通过在授权域里面创建根区来进行过滤，返回NXDOMAIN。

- 使用场景：金融行业内网存在垃圾域名需要进行过滤，则可以采用域白名单的方式进行过滤，对于授权和转发的直接配置在白名单，其他则被过滤。

 

***\*系统访问控制：\****

可以支持系统级别的访问控制，如针对报文的源IP，目的IP，源端口，目的端口，协议类型，IP协议段指定管理员预先定义的动作，如丢弃，单位时间内指定限速值限速通过，或不限速通过。

- 实现方式：原SmartDDI的高级访问控制；Linux自带的iptables防火墙策略。

使用场景：

- 用户在使用本产品时，需要对进入本设备的流量进行控制，如响应指定源IP段发起的ICMP包在单位时间内允许响应指定个数，超过个数的ICMP报文或者其他源IP段发起的ICMP报文将会丢弃

- 指定用户的管理网络段的用户可以访问本机的管理界面或者ssh登录界面，其他用户不允许访问。

- 限制应答某个终端对本机发送的报文，避免可能的攻击行为。

 

***\*DNS请求类型访问控制：\****

可以对向系统发起的DNS请求的报文的请求类型进行访问控制，如可支持对ANY、AAAA、TXT、NULL等类型的过滤（不应答），应答nodata，应答nxdomain。

 

- 如何实现：(1) 在ipv4到ipv6的过渡期间，可能存在各种各样ipv6到ipv4的网络切换的问题，有可能某些应用对应的域名已经配置了AAAA类型的解析结果，但是实际的应用还未在该ipv6地址上部署，需要用户选用A类型的ipv4地址。

-  (2) 由于DNS报文协议的特点，可能存在DNS的放大攻击，向ANY，TXT，NULL这种类型的应答中，应答包都比较大，如果用户通过抓包分析，发现有可疑终端发起此类攻击时，系统应当能够有一些策略，对此类攻击进行过滤和防护。

 

#### 1.2.4 DNS 的缓存投毒攻击防御

DNS缓存投毒攻击是指攻击者欺骗DNS服务器相信伪造的DNS响应的真实性。这种类型攻击的目的是将依赖于此DNS服务器的受害者重定向到其他的地址。

 

即利用控制DNS缓存服务器，把原本准备访问某网站的用户在不知不觉中带到黑客指向的其他网站上。其实现方式有多种，比如可以通过利用网民ISP端的DNS缓存服务器的漏洞进行攻击或控制，从而改变该ISP内的用户访问域名的响应结果;或者，黑客通过利用用户权威域名服务器上的漏洞，如当用户权威域名服务器同时可以被当作缓存服务器使用，黑客可以实现缓存投毒，将错误的域名纪录存入缓存中，从而使所有使用该缓存服务器的用户得到错误的DNS解析结果。

- 如何防御：原Smart DDI

 

#### 1.2.5 DNS 的 放大攻击防护

此DDoS攻击是基于反射的体积分布式拒绝服务（DDoS）攻击，其中攻击者利用开放式DNS解析器的功能，以便使用更大量的流量压倒目标服务器或网络，从而呈现服务器和它周围的基础设施无法进入。所有放大攻击都利用了攻击者和目标Web资源之间的带宽消耗差异

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps19.jpg) 

Ø 实现方式：原SmartDDI：对应答报文大小进行检查，对超过指定大小的报文进行限速通过。或者采用更合适的方式应对这种攻击。

Ø 测试案例，银联DNS

 

#### 1.2.6 DGA域名识别阻断

域名生成算法（DGA）通常会使用大量的伪随机算法（家族中有43个算法种子）来生成C&C域名来干扰正常域名的识别。

 

Ø 如何实现：通过大量数据集，通过选取大量的特征工程并加入分类算法进行提取，依据精确率precision和召回recall率来判断识别的程度。

Ø 应用场景：适用于对于恶意服务器攻击的相关应用

 

#### 1.2.7 恶意IDN域名识别阻断

因为DNS技术规格本身的限制，只能使用拉丁文字(ASCII)作为域名的组合，像是希里尔文、希腊文、中文或者是日文多国语言的文字原是无法使用在DNS上的。IDN满足了多语种域名发展的需求，如我国的[中文域名](https://www.ymw.cn/)，在IDN出现以前，全球六亿六千五百多万互联网用户必须输入英文字符的域名，才能浏览网络和发送电子邮件。英文域名不应该只是浏览互联网的唯一途径，但IDN (Internationalized domain name)的标准则突破了这种限制。

 

缺点：可以伪造与英文域名相似的名字形成钓鱼网站欺骗客户。

 

- 如何实现：基于黑名单的钓鱼识别技术, 基于URL的钓鱼识别技术,基于页面文本特征的钓鱼识别技术, 基于域名whois的钓鱼识别技术, 基于网站备案识别等等

 

#### 1.2.8 DNS隧道识别阻断

DNS的某些请求类型允许携带的内容为文本，没有太多的语法校验和长度，攻击者可以利用特定的请求类型承载这些数据。这些数据可以为伪装成DNS的客户端和DNS权威服务器的终端建立起隧道，并利用隧道传输机密信息或敏感信息。

 

- 如何实现：原SmartDDI的TCP服务开关。

  

## **2.** 工具篇（流量工具，分析工具）

 

### 2.1流量工具

***\*Mz（C语言开发）：\****

功能：产生大量的流量包

 

-  流量产生器（比如高压的多点传送网络）

-  防火墙和IDS的穿透测试

-  网络中的DoS攻击

-  在网络软件或工具中发现bug

-  用大量的ping和端口扫描搜索攻击

-  测试网络行为在奇怪的环境下（如压力测试，畸形包）

-  实验室里教学工具

  

在centos7下安装成功

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps20.jpg) 

 

其中主要参数为：

-A,-B：分别代表源地址和目标地址

-t：表示发送的包的类型，目前支持arp, bpdu, cdp, ip, icmp, udp, tcp,dns, rtp, syslog, lldp

-p：表示指定未加工的帧指定长度（随机字节数）

...

 

安装时遇到的问题：

1.安装libcli-devel时出现No package available

原因：CentOS是RedHat企业版编译过来的，去掉了所有关于版权问题的东西。安装EPEL后可以很好的解决这个问题。EPEL(Extra Packages for Enterprise Linux )即企业版Linux的扩展包，提供了很多可共Centos使用的组件，安装完这个以后基本常用的rpm都可以找到。

解决：sudo yum install epel-release



2.安装时cannot find a valid baseurl for repobase7x86_64

 

原因：网络配置network-scripts

 

***\*KPUMP：\****

 

KPUMP是一个工作在内核中，夹在协议栈与设备驱动之前的DNS发包工具。KPUMP不依赖协议栈或应用程序，只要网卡能被正确驱动就可以高效的发送DNS包。

 

安装kernal命令：rpm -ivh +包名

 

安装时遇到的问题：

1. Error: 10 Device is not exist or not attached pktgen thread

 

原因：配置脚本时候的网卡设置错误

 

解决：修改为自己的网卡名

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps21.jpg) 

 

2. 虚拟机网络配置始终失效且无法连接到SecureCRT上

 

原因：使用nat配置错误

 

解决：使用桥接，网络设置为静态路由，增加ip地址，子网掩码以及网关，最后ping成功。

 

***\*Queryperf：\****

 

Bind自带的压力测试软件，使用这款软件可以对DNS服务器作请求测试，可以使用queryperf测试多次，取一个平均值来评估DNS服务器的性能。

 

安装：bind自带测试软件

 

queryperf使用格式：

Queryperf [-d datafile]  [-s server_addr]  [-p port] [-q num_queries]


-d: 后面接上一个文件，文件的内容是用户对DNS的请求，一行为一条请求，所以为了测试，我们可以在里面写上几千几万条。
-s: DNS服务器地址
-p: DNS服务器端口
-q: 指定查询的输出的最大数量

 

 

***\*Dnsperf：\****

 

开源的DNS压力测试软件，输出样例如下：

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps22.jpg) 

queies sent是指本次探测发送的总请求数，queries completed是指本次探测收到响应的请求数，complete percentage是指本次探测的成功率(queies_completed/queries_sent)，elapsed time是指本次探测的时间，queries per second是指本次探测的QPS。

 

### 2.2分析工具

***\*Dnstop：\****

 

用来监控dns的服务器状态，可以对DNS的查询做一个系统的统计

参数如下：

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps23.jpg) 

dnstop -l 3 eth0 输出如下，表示支持三级域名的查看（用法dns + 网口）

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps24.jpg) 

 

***\*Iptables：\****

 

iptables组成Linux平台下的包过滤防火墙，与大多数的Linux软件一样，这个包过滤防火墙是免费的。

 

iptables实现防火墙功能的原理是：在数据包经过内核的过程中有五处关键地方，分别是PREROUTING、INPUT、OUTPUT、FORWARD、POSTROUTING，称为钩子函数，iptables这款用户空间的软件可以在这5处地方写规则，对经过的数据包进行处理，规则一般的定义为“如果数据包头符合这样的条件，就这样处理数据包”。

 

iptables具有Filter（过滤）, NAT（网络地址转换）, Mangle（包修改）, Raw（实现数据跟踪）四种内建表（tables由chains构成，chains由rules构成）

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps25.jpg) 

Iptables使用方法及参数如下：

![img](file:///C:\Users\xx.su\AppData\Local\Temp\ksohtml10940\wps26.jpg) 

选项参数

 

-t<表>：指定要操纵的表；

-A：向规则链中添加条目；

-D：从规则链中删除条目；

-i：向规则链中插入条目；

-R：替换规则链中的条目；

-L：显示规则链中已有的条目；

-F：清楚规则链中已有的条目；

-Z：清空规则链中的数据包计算器和字节计数器；

-N：创建新的用户自定义规则链；

-P：定义规则链中的默认目标；

-h：显示帮助信息；

-p：指定要匹配的数据包协议类型；

-s：指定要匹配的数据包源[ip](http://man.linuxde.net/ip)地址；

-j<目标>：指定要跳转的目标；

-i<网络接口>：指定数据包进入本机的网络接口；

-o<网络接口>：指定数据包要离开本机所使用的网络接口。

 

 

 

 

 

 

 

## **3.** 参考文档

 

https://blog.csdn.net/fly_yr/article/details/50858621 

DDOS攻击TCP UDP ICMP 

 

https://blog.csdn.net/bodybo/article/details/90782449

CentOS中yum安装软件时报错：No package XXX available（转载）

 

http://blog.sina.com.cn/s/blog_4882a26b01000atj.html

IP分片攻击

 

https://www.cnblogs.com/sparkdev/p/7777871.html

Dig命令解析

 

https://blog.csdn.net/yonggeit/article/details/88175022

DNS缓存

 

https://blog.csdn.net/zhu_tianwei/article/details/45202899

Queryperf压力测试

 

https://www.cnblogs.com/Booker808-java/p/7822763.html

虚拟机网络nat和桥接的区别

 

https://blog.csdn.net/s_ddwqwd/article/details/82866188

Dnstop监控dns服务器的状态

 

https://blog.csdn.net/u011537073/article/details/82685586

Iptables 基础知识详解