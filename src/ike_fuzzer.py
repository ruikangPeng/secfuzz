#! /usr/bin/env python

import fcntl
import os
import threading
import thread
import signal
import sys
import getopt
import datetime
import time
import random
from Crypto.Cipher import *
from Crypto.Hash import *
from scapy.all import *

#------------------------------------------------------------
# 此类枚举不同的负载类型
#------------------------------------------------------------
class PD_TYPE:
   SA = 1
   Transform = 3
   KE = 4
   ID = 5
   CERT = 6
   CR = 7
   Hash = 8
   SIG = 9
   Proposal = 10
   PD = 11
   VendorID = 13
   Header = -1

#------------------------------------------------------------
# 此类保存有关当前 IKE 会话的信息
#------------------------------------------------------------
class Fuzz_session:
  fuzz = None
  enc_algo = None
  hash_algo = None
  enc_key = None
  iv = None
  init_cookie = None
  resp_cookie = None
  pkts_received = 0
  pkt_to_fuzz = 0


#------------------------------------------------------------
# 全局变量
#------------------------------------------------------------
prob_list = [('payload', 0.1), ('field', 0.8), ('packet', 0.1)]   ## 指定应用不同模糊类别的概率
fuzz_session = Fuzz_session()                                     ## 保留有关当前 IKE 会话的信息
ip = None                                                         ## 本地计算机的 IP
opp_ip = None                                                     ## 远程机器的 IP(SUT)
log_file = None                                                   ## 存储 log 模糊信息
log_dir = None                                                    ## 存储 log 文件的路径
iface = None                                                      ## 本地机器的接口(例如 eth0)
fuzz_mode = False                                                 ## boolean类型，指定数据包是否模糊
pluto_log_file= "/home/adminuser/fuzzing/pluto.log"               ## pluto 日志文件的路径
pluto_log_fd = None                                               ## pluto 日志文件的文件描述符
running = True                                                    ## 模糊器是否在运行
ike_port = 500                                                    ## ike 端口(默认情况下将数据包发送到该端口)
dest_port = 501                                                   ## 远程机器正在侦听的 ike 端口
lock1 = threading.Semaphore(0)                                    ## 用于同步线程窥探数据包(tcpdump)和发送数据包的主模糊线程的信号量
lock2 = threading.Semaphore(1)                                    ## 用于同步线程窥探数据包(tcpdump)和发送数据包的主模糊线程的信号量


#------------------------------------------------------------
# 此函数将所有输出记录到一个文件中，如果未指定文件，则打印到标准输出
#------------------------------------------------------------
def log(msg):
   log_msg = '[' + str(datetime.datetime.now()) + '] ' + msg
   if log_file is not None and msg is not None:
      log_file.write(log_msg + '\n')
      log_file.flush()
   else:
      print log_msg


#------------------------------------------------------------
# 此函数用于清理临时文件并在 Ctrl+c 事件时停止模糊器
#------------------------------------------------------------
def signal_handler(signal, frame):
   running = False
   log('Cleaning up temporary pcap files')
   os.system('sudo rm -rf ' + log_dir + 'pkt*')
   log('Stopping')
   sys.exit(0)


#------------------------------------------------------------
# 此函数应在单独的线程中运行。它运行 tcpdump 将数据包捕获为 pcap 格式。
# 它与模糊器同步，以便只有在 tcpdump 侦听下一个数据包之后才发送数据包。
#------------------------------------------------------------
def start_tcpdump():
   log('Tcpdump running')
   pkt_count = 1
   while running:
      # 等待模糊器发送刚刚捕获的数据包
      lock2.acquire()
      pcap_file = log_dir + 'pkt_' + str(pkt_count) + '.pcap'
      os.system('tcpdump -i ' + iface + ' dst ' + opp_ip + ' and dst port ' + str(ike_port) + ' -c 1 -w ' + pcap_file + ' &')
      if pkt_count > 1:
         # 忙于等待 tcpdump 启动并运行
         while int(os.popen('sudo ps x | grep "tcpdump -i ' + iface + '" | wc -l').read().rstrip()) < 1:
            pass
         # tcpdump 正在侦听，可以安全地发送数据包
         lock1.release()
      pkt_count += 1


#------------------------------------------------------------
# 此函数返回一个格式良好的随机数据包(该数据包是从协议的以前会话中捕获的)
#------------------------------------------------------------
def get_random_pkt():
   num_pcap_pkts = int(os.popen('ls *.pcap | wc -l').read().rstrip())
   if num_pcap_pkts < 1:
      return None
   pcap_file = log_dir + 'pkt_'+str(random.randint(1,num_pcap_pkts-1))+'.pcap'
   rand_pkt = read_pcap(pcap_file)
   return rand_pkt
   

#------------------------------------------------------------
# 此函数读取一个 pcap 文件并返回一个数据包对象。
#------------------------------------------------------------
def read_pcap(pcap_file):
   while not( os.path.isfile(pcap_file) and os.path.getsize(pcap_file) > 0 ):
      pass
   pkts=rdpcap(pcap_file)
   if len(pkts) > 0:
      return pkts[0]
   else:
      return None


#------------------------------------------------------------
# 此函数将数据包端口重写为 dest 端口，并删除 IP 和 UDP 校验和，
# 如果校验和不匹配，操作系统可能(也应该)忽略数据包。
#------------------------------------------------------------
def rewrite_port(pkt):
   pkt[UDP].dport = dest_port
   del pkt[IP].chksum
   del pkt[UDP].chksum


#------------------------------------------------------------
# 从定义为的列表中选择一个：
# [(item_1,prob_1), (item_2,prob_2),... ,(item_n,prob_n)]
# 其中 prob_i 是选择 item_i 的概率
#------------------------------------------------------------
def weighted_choice(items):
   weight_total = sum((item[1] for item in items))
   n = random.uniform(0, weight_total)
   for item, weight in items:
      if n < weight:
         return item
      n = n - weight
   return item


#------------------------------------------------------------
# 当检测到一个新的 IKE 会话时，模糊器还会启动一个新会话，即在该会话期间模糊消息/负载
#------------------------------------------------------------
def init_new_session(pkt):
   global fuzz_session
   log('Starting a new session')
   fuzz_session = Fuzz_session()
   fuzz_session.fuzz = weighted_choice(prob_list) 
   # 选择一个随机数据包进行模糊处理
   fuzz_session.pkt_to_fuzz = random.randint(1,5)
   if fuzz_session.fuzz == 'payload':
      log('Prepare to fuzz a payload in packet ' + str(fuzz_session.pkt_to_fuzz))
   elif fuzz_session.fuzz == 'field':
      log('Prepare to fuzz a field in packet ' + str(fuzz_session.pkt_to_fuzz))
   elif fuzz_session.fuzz == 'packet':
      log('Prepare to insert random packet after packet ' + str(fuzz_session.pkt_to_fuzz))

   fuzz_session.init_cookie = pkt[ISAKMP].init_cookie


#------------------------------------------------------------
# 此函数对数据包进行加密
#------------------------------------------------------------
def encrypt(pkt):
   log('Encrypting a packet')
   key = get_key()
   try:
      pkt[ISAKMP].payload = Raw(key.encrypt( str(pkt[ISAKMP].payload) + '\x00'* ( (16 - len(pkt[ISAKMP].payload)%16 )%16 ) ) )
   except ValueError:
      if fuzz_session.fuzz == 'payload':
         log('Encryption failed, probably fuzzing a payload and length is unknown..')
         encrypt(pkt)
   log('Encrypted packet:\n' + pkt.command())



#------------------------------------------------------------
# 此函数读取 pluto 日志文件并返回当前加密密钥
#------------------------------------------------------------
def get_key():
   pluto_log_reader()
   log('Creating ' + str(fuzz_session.enc_algo) + ' key with enc key ' + fuzz_session.enc_key + ' and IV ' + fuzz_session.iv)
   if fuzz_session.enc_algo == AES:
     return AES.new(fuzz_session.enc_key[:32].decode('hex'), AES.MODE_CBC, fuzz_session.iv[:32].decode('hex'))
   elif fuzz_session.enc_algo == DES3:
     return DES3.new(fuzz_session.enc_key[:48].decode('hex'), AES.MODE_CBC, fuzz_session.iv[:16].decode('hex'))
   else:
     log('Not supported encryption algorithm')
     sys.exit(0)


#------------------------------------------------------------
# 此函数用于解密数据包
#------------------------------------------------------------

   SA = 1
   Transform = 3
   KE = 4
   ID = 5
   CERT = 6
   CR = 7
   Hash = 8
   SIG = 9
   Proposal = 10
   PD = 11
   VendorID = 13

def decrypt(pkt):
   log('Decrypting a packet')
   key = get_key()
   if pkt[ISAKMP].next_payload == PD_TYPE.ID:
      pkt[ISAKMP].payload = ISAKMP_payload_ID(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.KE:
      pkt[ISAKMP].payload = ISAKMP_payload_KE(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.Proposal:
      pkt[ISAKMP].payload = ISAKMP_payload_Proposal(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.SA:
      pkt[ISAKMP].payload = ISAKMP_payload_SA(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.Transform:
      pkt[ISAKMP].payload = ISAKMP_payload_Transform(key.decrypt(pkt[ISAKMP].payload.load))
   elif pkt[ISAKMP].next_payload == PD_TYPE.VendorID:
      pkt[ISAKMP].payload = ISAKMP_payload_VendorID(key.decrypt(pkt[ISAKMP].payload.load))
   else:
      pkt[ISAKMP].payload = ISAKMP_payload_Hash(key.decrypt(pkt[ISAKMP].payload.load))
   log('Decrypted packet:\n' + pkt.command() )
   # 我们假设 res 字段没有被使用，并且被设置为 0，这允许我们检查解密是否成功
   if pkt[ISAKMP].payload.res != 0:
      log('Decryption failed, probably the key was incorrect, this can happen if pluto has not written the latest key in its log file')
      pkt[ISAKMP].payload = ISAKMP_payload(next_payload=0)
      pkt[ISAKMP].next_payload = 6


#------------------------------------------------------------
# 此函数监视 pluto.log 文件并捕获加密密钥何时更新，它还跟踪当前使用的加密方案、CBC 的 IV 等。
#------------------------------------------------------------
def pluto_log_reader():
  global fuzz_session
  # 等待以确保 pluto 已保存到 pluto.log
  time.sleep(0.1)

  line = pluto_log_fd.readline().rstrip()
  while line != '':
     if '! enc key:' in line:
        fuzz_session.enc_key = line[12:].replace(' ', '')
        line = pluto_log_fd.readline().rstrip()
        if '! enc key:' in line:
           fuzz_session.enc_key += line[12:].replace(' ', '')
        else:
           continue
     elif '! IV:  ' in line:
        fuzz_session.iv = line[7:].replace(' ','')
        line = pluto_log_fd.readline().rstrip()
        if '! IV:  ' in line:
           fuzz_session.iv += line[7:].replace(' ', '')
        else:
           continue
     elif '| IV:' in line:
        line = pluto_log_fd.readline().rstrip()
        fuzz_session.iv = line[4:].replace(' ','')
     elif 'OAKLEY_AES_CBC' in line:
        fuzz_session.enc_algo = AES
     elif 'OAKLEY_3DES_CBC' in line:
        fuzz_session.enc_algo = DES3
     elif 'OAKLEY_SHA1' in line:
        fuzz_session.hash_algo = SHA
     elif 'OAKLEY_MD5' in line:
        fuzz_session.hash_algo = MD5
     line = pluto_log_fd.readline().rstrip()


#------------------------------------------------------------
# 此函数重复数据包中的有效载荷
#------------------------------------------------------------
def payload_repeat(pkt):
   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)
   repeat_pd = random.randint(2,len(payloads) )
   cur_payload = pkt[ISAKMP]
   for i in range(1,repeat_pd):
      cur_payload = cur_payload.payload
   cur_payload.payload = eval(cur_payload.command())
   cur_payload.next_payload = cur_payload.underlayer.next_payload


#------------------------------------------------------------
# 此函数从数据包中删除有效负载
#------------------------------------------------------------
def payload_remove(pkt):
   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)
   remove_pd = random.randint(2,len(payloads) )
   cur_payload = pkt[ISAKMP]
   for i in range(1,remove_pd):
      cur_payload = cur_payload.payload
   cur_payload.underlayer.next_payload = cur_payload.next_payload
   if cur_payload.payload.command() == '':
     del cur_payload.underlayer.payload
   else:
     cur_payload.underlayer.payload = eval(cur_payload.payload.command())

#------------------------------------------------------------
# 此函数在数据包中插入随机有效载荷
#------------------------------------------------------------
def payload_insert(pkt):
   cur_payload = pkt[ISAKMP]
   payloads = []
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      cur_payload = cur_payload.payload
   payloads.append(cur_payload)
   remove_pd = random.randint(2,len(payloads) )
   cur_payload = pkt[ISAKMP]
   for i in range(1,remove_pd):
      cur_payload = cur_payload.payload
   print cur_payload.command()
   r = random.choice( [ (fuzz(ISAKMP_payload()), 6), (fuzz(ISAKMP_payload_Hash()), 8), (fuzz(ISAKMP_payload_ID()), 5), 
                             (fuzz(ISAKMP_payload_KE()), 4), (fuzz(ISAKMP_payload_Nonce()), 8), (fuzz(ISAKMP_payload_Proposal()), 10), 
                             (fuzz(ISAKMP_payload_SA()), 1), (fuzz(ISAKMP_payload_Transform()), 3), (fuzz(ISAKMP_payload_VendorID()), 13) ] )
   r[0].payload = eval(cur_payload.command() )
   r[0].next_payload = cur_payload.underlayer.next_payload
   cur_payload.underlayer.next_payload = r[1]
   cur_payload.underlayer.payload = r[0]


#------------------------------------------------------------
# 从有效载荷模糊类型到有效载荷模糊函数的映射
#------------------------------------------------------------
fuzz_payload_func = {}
fuzz_payload_func['repeat'] = payload_repeat
fuzz_payload_func['remove'] = payload_remove
fuzz_payload_func['insert'] = payload_insert



#------------------------------------------------------------
# 此函数模糊一个有效载荷
#------------------------------------------------------------
def fuzz_payload(pkt):
   fuzz_type = random.choice( ['repeat', 'remove', 'insert'] )
   log('Fuzzing a payload ' + fuzz_type)

   encrypt_pkt = False
   if pkt[ISAKMP].flags == 1L:
     decrypt(pkt)
     encrypt_pkt = True

   fuzz_payload_func[fuzz_type](pkt)
   log('Fuzzed packet:\n'+pkt.command())
   pkt = eval(pkt.command())

   if encrypt_pkt:
      encrypt(pkt)


#------------------------------------------------------------
# 此函数模糊一个字段
#------------------------------------------------------------
def fuzz_field(pkt):
   log('Fuzzig a field')
   # 检查数据包是否加密
   encrypt_pkt = False
   if pkt[ISAKMP].flags == 1L:
     decrypt(pkt)
     encrypt_pkt = True

   # 检查数据包中包含哪些有效载荷，并随机选择一个来模糊其中的字段
   cur_payload = pkt[ISAKMP]
   payloads = []
   payload_type = []
   payload_type.append(PD_TYPE.Header)
   while cur_payload.next_payload != 0:
      payloads.append(cur_payload)
      if cur_payload.next_payload != 0:
         payload_type.append(cur_payload.next_payload)
      cur_payload = cur_payload.payload
   if len(payloads) == 0:
      payloads.append(pkt[ISAKMP])
   pd_to_fuzz = random.randint(0,len(payloads)-1)
   fuzz_func[ payload_type[pd_to_fuzz] ](payloads[pd_to_fuzz]) 
   log('Fuzzed packet:\n'+pkt.command())

   if encrypt_pkt:
      encrypt(pkt)


#------------------------------------------------------------
# 此函数模糊一个数据包(发送随机数据包)
#------------------------------------------------------------
def fuzz_packet(pkt):
   log('Fuzzing packet')
   rand_pkt = get_random_pkt()
   if rand_pkt != None:
      log('Sending random packet: ' + rand_pkt.command())
      rewrite_port(rand_pkt)
      send(rand_pkt[IP])


#------------------------------------------------------------
# 模糊一个包
#------------------------------------------------------------
def fuzz_pkt(pkt):
   if fuzz_session.fuzz == 'payload':
      fuzz_payload(pkt)
   elif fuzz_session.fuzz == 'field':
      fuzz_field(pkt)
   elif fuzz_session.fuzz == 'packet':
      fuzz_packet(pkt)
   

#------------------------------------------------------------
# 这个函数处理每个新的数据包，并决定我们是否应该模糊它
#------------------------------------------------------------
def process_pkt(pkt):
   global fuzz_session
   fuzz_session.pkts_received += 1
   if fuzz_session.pkt_to_fuzz == fuzz_session.pkts_received:
      pkt = fuzz_pkt(pkt)


#------------------------------------------------------------
# 模糊器的主要函数
#------------------------------------------------------------
def start_fuzzer():
   global running, pluto_log_fd
   log('Initializing pluto log reader')
   pluto_log_fd = open(pluto_log_file, 'r')

   os.system('sudo rm -rf pkt*')
   thread.start_new_thread(start_tcpdump, () )
   log('Fuzzer started')
   pkt_count = 1
   while running:
      pcap_file = log_dir + 'pkt_' + str(pkt_count) + '.pcap'
      pkt = read_pcap(pcap_file)
      if pkt is None:
         continue
      pkt_count = pkt_count + 1
      log('Received packet:\n' + pkt.command() + '\n')
      # 检测数据包是否属于新的 IKE 会话
      if fuzz_mode and pkt[ISAKMP].resp_cookie == '\x00\x00\x00\x00\x00\x00\x00\x00' and pkt[ISAKMP].init_cookie != fuzz_session.init_cookie:
         init_new_session(pkt)
      if fuzz_mode:
         process_pkt(pkt)
      rewrite_port(pkt)
      lock2.release()
      lock1.acquire()
      log('Sending packet\n' + pkt.command())
      send(pkt[IP])


#------------------------------------------------------------
# 主函数，读取 fuzzer 参数并启动 fuzzer
#------------------------------------------------------------
def main():
   global ip, opp_ip, log_file, fuzz_mode, log_dir, iface, pluto_log_file, prob_list

   opts, args = getopt.getopt(sys.argv[1:], 'i:o:l:fe:p:t:')
   for o, a in opts:
      print o, a
      if o == '-i':
         ip = a
      if o == '-o':
         opp_ip = a
      if o == '-l':
         log_file = open(a, 'w')
      if o == '-f':
         fuzz_mode = True
      if o == '-e':
         iface = a
      if o == '-p':
         pluto_log_file = a
      if o == '-t':
         prob_list = [(a,1)]
         if a not in ['field', 'payload', 'packet']:
            prob_list = None

   if fuzz_mode:
      log('Running in fuzzing mode')
   else:
      log('Running in disabled fuzzing mode')

   log('Pluto file: ' + pluto_log_file)

   if log_dir is None:
      log_dir = os.getcwd()+'/'
   else:
      log_dir=os.path.abspath(fp)[:os.path.abspath(fp).rfind('/')]+'/'
          
   log('Log dir: ' + log_dir)

   if prob_list is None:
      log('Invalid fuzz type')
      sys.exit(0)
   
   if( ip is None or opp_ip is None or iface is None):
      print_usage()
      sys.exit(0)

   for item, weight in prob_list:
      log('Fuzzing ' + item + ' probability ' + str(weight))

   bind_layers(UDP, ISAKMP, sport=500)
   bind_layers(UDP, ISAKMP, dport=500)

   start_fuzzer()

def print_usage():
   print sys.argv[0], '-i <ip> -o <opposite ip> -f -l <log file> -e <eth interface> -p <pluto log file>'



#------------------------------------------------------------
# 模糊字段下面的函数
#------------------------------------------------------------

def rand_ByteEnumField():
   return random.randint(0,100)


def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)


def rand_ByteField():
   return os.urandom(random.randint(0,100))


def rand_IntEnumField():
   return random.randint(0,100)


def rand_StrLenField(data):
   bit = random.randint(0,3)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + '\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,1000))
   elif bit == 3:
      data = '\x00'
   else:
      log('Error')
   return data

def rand_ShortEnumField():
   return random.randint(0,100)


def rand_IntField():
   return random.randint(0,5000)

#------------------------------------------------------------
# 模糊有效载荷下面的函数
#------------------------------------------------------------

def fuzz_SA(payload):
   log('fuzz SA')
   pd = random.choice([ISAKMP_payload_SA, ISAKMP_payload_Proposal, ISAKMP_payload_Transform])
   length = len(payload)
   if pd == ISAKMP_payload_SA:
      field = random.choice(['next_payload', 'length', 'DOI', 'situation'])
      log('Fuzzing field: ' + field)
      if field == 'next_payload':
         payload.next_payload = rand_ByteEnumField()
      elif field == 'length':
         payload.length = rand_FieldLenField()
      elif field == 'DOI':
         payload.DOI = rand_IntEnumField()
      elif field == 'situation':
         payload.situation = rand_IntEnumField()
      else:
         log('Error')
      if field != 'length':
         payload.length += ( len(payload) - length )
   elif pd == ISAKMP_payload_Proposal:
      fuzz_Proposal(payload)
   elif pd == ISAKMP_payload_Transform:
      fuzz_Transform(payload)
   else:
      log('Error')
      sys.exit(0)

def fuzz_KE(payload):
   log('fuzz KE')
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_ID(payload):
   log('fuzz ID')
   field = weighted_choice([('next_payload', 0.1), ('length', 0.1), ('IDtype',0.1), ('ProtoID', 0.1), ('Port', 0.1), ('load',0.5)])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'IDtype':
      payload.IDtype = rand_ByteEnumField()
   elif field == 'ProtoID':
      payload.ProtoID = rand_ByteEnumField()
   elif field == 'Port':
      payload.Port = rand_ShortEnumField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Hash(payload):
   log('fuzz Hash')
   length = len(payload)
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_VendorID(payload):
   log('fuzz VendorID')
   field = random.choice(['next_payload', 'length', 'vendorID'])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'vendorID':
      payload.vendorID = rand_StrLenField(payload.vendorID)
   else:
      log('Error')
      sys.exit(0)

def fuzz_Header(payload):
   log('fuzz Header')
   field = random.choice(['init_cookie', 'resp_cookie', 'next_payload', 'exch_type', 'flags', 'id', 'length'])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'init_cookie':
      payload.init_cookie = os.urandom(8)
   elif field == 'resp_cookie':
      payload.resp_cookie = os.urandom(8)
   elif field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'exch_type':
      payload.exch_type = rand_ByteEnumField()
   elif field == 'flags':
      if payload.flags == 0L:
         payload.flags = 1L
      else:
         payload.flags = 0L
   elif field == 'id':
     payload.id = rand_IntField()
   elif field == 'length':
     payload.length = rand_FieldLenField()
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_CERT(payload):
   log('fuzz CERT')
   fuzz_Payload(payload)


def fuzz_CR(payload):
   log('fuzz CR')
   fuzz_Payload(payload)


def fuzz_SIG(payload):
   log('fuzz SIG')
   fuzz_Payload(payload)


def fuzz_Proposal(payload):
   log(payload.command())
   log('fuzz Proposal')
   field = random.choice(['next_payload', 'length', 'proposal', 'proto', 'SPIsize', 'trans_nb'])#, 'SPI'])
   log('Fuzzing field: ' + field)
   length = len(payload)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'proposal':
      payload.proposal = rand_ByteField()
   elif field == 'proto':
      payload.proto = rand_ByteEnumField()
   elif field == 'SPIsize':
      payload.SPIsize = rand_FieldLenField()
   elif field == 'trans_nb':
      payload.field = rand_ByteField()
   elif field == 'SPI':
      payload.SPI = rand_StrLenField(payload.SPI)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Payload(payload):
   log('fuzz Payload')
   length = len(payload)
   field = weighted_choice([('next_payload', 0.2), ('length', 0.2), ('load',0.6)])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'load':
      payload.load = rand_StrLenField(payload.load)
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )

def fuzz_Transform(payload):
   log('fuzz Transform')
   num_transforms = 0
   cur_payload = payload
   length = len(payload)
   while cur_payload.next_payload != 0:
      num_transforms
      cur_payload = cur_payload.payload
   fuzz_transform = cur_payload
   for i in range(0,num_transforms-1):
      fuzz_transform = fuzz_transform.payload
   field = random.choice(['next_payload', 'length', 'num', 'id'])
   log('Fuzzing field: ' + field)
   if field == 'next_payload':
      payload.next_payload = rand_ByteEnumField()
   elif field == 'length':
      payload.length = rand_FieldLenField()
   elif field == 'num':
      payload.num = rand_ByteField()
   elif field == 'id':
      payload.id = rand_ByteEnumField()
   else:
      log('Error')
      sys.exit(0)
   if field != 'length':
      payload.length += ( len(payload) - length )



#------------------------------------------------------------
# Map <payload id> <--> <function that fuzzes payload>
#------------------------------------------------------------
fuzz_func = {}
fuzz_func[1] = fuzz_SA
fuzz_func[4] = fuzz_KE
fuzz_func[5] = fuzz_ID
fuzz_func[6] = fuzz_CERT
fuzz_func[7] = fuzz_CR
fuzz_func[8] = fuzz_Hash
fuzz_func[9] = fuzz_SIG
fuzz_func[10] = fuzz_Proposal
fuzz_func[11] = fuzz_Payload
fuzz_func[13] = fuzz_VendorID
fuzz_func[-1] = fuzz_Header


if __name__ == '__main__':
   signal.signal(signal.SIGINT, signal_handler)
   main()
