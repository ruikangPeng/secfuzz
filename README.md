I. 它做什么
------------------
IKE 模糊测试仪的目的是评估 IKE 实现中的漏洞。
模糊测试仪向被测实现（IUT）发送消息，然后使用动态分析工具对其进行低级别漏洞（例如内存错误）测试。
发送到 IUT 的消息序列是使用下面描述的模糊运算符之一随机变异的。


II. 模糊算子
------------------
模糊运算符随机变异一系列消息，这些消息是 IUT 的输入。
协议执行由一系列消息组成，消息由有效载荷列表组成，有效载荷由一组字段组成。

1. Fuzzing a message
   - 发送一个随机消息：这个操作符在一个有效的消息序列中插入一个格式良好的消息。
2. Fuzzing a payload
   - 移除有效载荷：消息中的有效载荷被移除
   - 插入有效载荷：在有效载荷列表中的随机位置插入一个随机形成的有效载荷
   - 重复有效载荷：随机有效载荷在有效载荷列表中重复
3. Fuzzing a field
   Fuzzing numerical fields:
   - 设置为 0
   - 设置为随机数模糊字节字段
   - 附加一个随机字节序列
   - 设置为空
   - 修改随机字节
   - 在随机位置插入字符串终止
   

III. 它是如何工作的
---------------------
下图说明了使用模糊测试仪的实验设置。
Openswan 是一个成熟的 IPsec 实现，用于生成有效的 IKE 消息序列。 

```
    +--------+                         +--------+
    |Opponent|<------------------------|  SUT   |
    +--------+\                      ->+--------+
         |     \                    /
write to |      \                  /
         \/      --->+---------+---
   log file -------->| SecFuzz |
             read    +---------+
```

IUT 的行为可以使用动态分析工具进行监测，例如内存错误检测器，如 Valgrind 的 Memcheck。


IV. 如何使用模糊测试仪
------------------------------
模糊测试仪是一个 python 脚本，可以如下启动：
```
$python ike_fuzzer.py [options]
```
- -i <ip>                 指定本地计算机的 IP 地址
- -o <opposite ip>        指定 IUT 的 IP 地址
- -f                      在 fuzzing 模式下运行 fuzztester，如果没有设置该标志，则 fuzzer 只转发所有 Openswan 消息
- -l <log file>           指定要记录信息的文件，如果未指定文件，则所有输出都将发送到标准输出
- -e <iface>              指定用于向 IUT 发送消息的以太网接口的名称(例如 eth0)
- -p <pluto log file>     设置 Openswan 日志文件的路径 


除 -f 和 -l 之外的所有选项都是必需的。模糊测试人员需要 root 权限。

当模糊测试仪启动时，Openswan 发送的所有消息都会被拦截并转发到 IUT 侦听 IKE 消息的端口。
Openswan 必须配置为输出所有调试信息，以便模糊测试人员能够从日志文件中找到必要的加密信息。
这可以通过在 ipsec.conf 中设置 pludebug＝all 来完成。ipsec_confs 目录包含许多 ipsec.conf 配置。


V. 软件依赖
------------------------
要使用模糊测试仪，您需要以下软件：
- Python 2.6+
- Scapy (http://www.secdev.org/projects/scapy/) - Scapy 是一个强大的 python 交互式数据包操作库。
- Openswan 2.6.37 (http://openswan.org/) - Openswan 是 Linux 的 IPsec 实现。您需要配置 Openswan 和 IUT 相互认证的方式。
- tcpdump (http://www.tcpdump.org/)


VI. 重要文件
-------------------
- fuzzer.py - 这是一个模糊测试程序，用于侦听 Openswan 消息并应用模糊运算符
- README - 这个文件
- ipsec_confs/ - 该目录包含不同的 Openswan 配置文件。Openswan 可以使用不同的配置文件启动，以便生成不同的消息序列。


VII. 已知问题
-------------------
- Scapy-python 库拒绝发送一些模糊消息，并使模糊测试程序崩溃。


VIII. 版本历史记录
---------------------
- v0.1 (November 14th, 2011)
  首次公开发布


IX. 联系方式
-----------------------
有关如何使用 IKE 模糊测试仪的更多信息：

Petar Tsankov
Email: petar.tsankov@gmail.com
