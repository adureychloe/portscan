from scapy.all import *
from IPy import IP as IPY

'''
通过设置flags位为'*',根据不同的扫描方式修改‘*’的值
'''


# conf.L3socket=L3RawSocket

# SYN半连接扫描
def syn_scan(ip, port):
    syn_scan_resp = sr1(IP(dst=ip) / TCP(dport=int(port), flags="S"), timeout=10)
    print("---------- syn scan ---------")
    print(syn_scan_resp)
    if syn_scan_resp == None:
        print(ip, "port", port, "is filtered")
    elif (syn_scan_resp.haslayer(TCP)):
        if (syn_scan_resp.getlayer(TCP).flags == 0x12): # ACK/SYN
            send_rst = sr(IP(dst=ip) / TCP(dport=int(port), flags="R"), timeout=10)  # 连接 R==>RST
            syn_scan_resp.display()
            print(ip, "port", port, "is open")
        elif (syn_scan_resp.getlayer(TCP).flags == 0x14): # RST/ACK
            syn_scan_resp.display()
            print(ip, "port", port, "is closed")
    elif (syn_scan_resp.haslayer(ICMP)): # ICMP错误数据包
        if (int(syn_scan_resp.getlayer(ICMP).type) == 3 and int(syn_scan_resp.getlayer(ICMP).code) in [1, 2, 3,
                                                                                                               9, 10,
                                                                                                               13]):
            syn_scan_resp.display()
            print(ip, "port", port, "is filtered")

# ACK扫描
def ack_scan(ip, port):
    ack_flag_scan_resp = sr1(IP(dst=ip) / TCP(dport=int(port), flags="A"), timeout=10)
    print("---------- ack scan ---------")
    if ack_flag_scan_resp == None:
        print("Stateful firewall present(Filtered)")
    elif (ack_flag_scan_resp.haslayer(TCP)):
        if (ack_flag_scan_resp.getlayer(TCP).flags == 0x4): # RST
            ack_flag_scan_resp.display()
            print("No firewall(Unfiltered)")
    elif (ack_flag_scan_resp.haslayer(ICMP)): # ICMP错误数据包
        if (int(ack_flag_scan_resp.getlayer(ICMP).type) == 3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1, 2,
                                                                                                                 3, 9,
                                                                                                                 10,
                                                                                                                 13]):
            ack_flag_scan_resp.display()
            print("Stateful firewall present(Filtered)")


# FIN扫描
def fin_scan(ip, port):
    fin_scan_resp = sr1(IP(dst=ip) / TCP(dport=int(port), flags="F"), timeout=10)
    print("---------- fin scan ---------")
    if fin_scan_resp == None:
        print(ip, "port", port, "is open | filtered.")
    elif (fin_scan_resp.haslayer(TCP)):
        if (fin_scan_resp.getlayer(TCP).flags == 0x14): # RST/ACK
            fin_scan_resp.display()
            print(ip, "port", port, "is closed")
    elif (fin_scan_resp.haslayer(ICMP)): # ICMP错误数据包
        if (int(fin_scan_resp.getlayer(ICMP).type) == 3 and int(fin_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,
                                                                                                       13]):
            fin_scan_resp.display()
            print(ip, "port", port, "is filtered")

# Null扫描,设置flags位为空
def null_scan(ip, port):
    null_scan_resp = sr1(IP(dst=ip) / TCP(dport=int(port), flags=""), timeout=10)
    print("---------- null scan ---------")
    if null_scan_resp == None:
        print(ip, "port", port, "is open|filtered.")
    elif (null_scan_resp.haslayer(TCP)):
        if (null_scan_resp.getlayer(TCP).flags == 0x14): # RST/ACK
            null_scan_resp.display()
            print(ip, "port", port, "is closed")
    elif (null_scan_resp.haslayer(ICMP)): # ICMP错误数据包
        if (int(null_scan_resp.getlayer(ICMP).type) == 3 and int(null_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,
                                                                                                         13]):
            null_scan_resp.display()
            print(ip, "port", port, "is filtered")

# Xmas扫描,设置flags位为FPU,不回复则表示端口开启，回复并且回复的标志位为RA表示端口关闭

def xmas_scan(ip, port):
    xmas_scan_resp = sr1(IP(dst=ip) / TCP(dport=int(port), flags="FPU"), timeout=10)
    print("---------- Xmas scan ---------")
    if xmas_scan_resp == None:
        print(ip, "port", port, "is open | filtered.")
    elif (xmas_scan_resp.haslayer(TCP)):
        if (xmas_scan_resp.getlayer(TCP).flags == 0x14): # RST/ACK
            xmas_scan_resp.display()
            print(ip, "port", port, "is closed")
    elif (xmas_scan_resp.haslayer(ICMP)): # ICMP错误数据包
        if (int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,
                                                                                                         13]):
            xmas_scan_resp.display()
            print(ip, "port", port, "is filtered")

# Windows扫描
# 设置flags为ACK
def windowScan(ip, port):
    window_scan_resp = sr1(IP(dst=ip) / TCP(dport=int(port), flags="A"), timeout=10)
    print("---------- windows scan ---------")
    if window_scan_resp == None:
        print("No response")
    elif (window_scan_resp.haslayer(TCP)):
        if (window_scan_resp.getlayer(TCP).window == 0):
            window_scan_resp.display()
            print(ip, "port", port, "is closed")
        elif (window_scan_resp.getlayer(TCP).window > 0):
            window_scan_resp.display()
            print(ip, "port", port, "is open")

# 利用ICMP协议探测主机是否开启
def Ping(dest):
    ip_addr = IPY(dest)
    for ip in ip_addr:
        # print(ip)
        packet = IP(dst=str(ip)) / ICMP() / b'rootkit'  # 构造三层数据包，/b是发送数据
        ping = sr1(packet, timeout=1, verbose=1)
        if ping:
            print("\033[0;32;47m\t" + str(ip) + " is up!" + "\033[0m")  # 打印带颜色字符串
        else:
            print(str(ip) + " is down!")


# ...
# 根据你的环境需改IP地址和端口
# ...

if __name__ == '__main__':
    dest = input("please input the target ip: ")
    port = input("please input the target port: ")
    Ping(dest)
    print(
        "syn\r\n",
        "ack\r\n",
        "fin\r\n",
        "null\r\n",
        "xmas\r\n",
        "windows\r\n")
    flag = input("please select the scan way：")
    if flag == 'syn':
        syn_scan(dest, port)
    elif flag == 'ack':
        ack_scan(dest, port)
    elif flag == 'fin':
        fin_scan(dest, port)
    elif flag == 'null':
        null_scan(dest, port)
    elif flag == 'xmas':
        xmas_scan(dest, port)
    elif flag == 'windows':
        windowScan(dest, port)
    else:
        print("please input the right choice!")
