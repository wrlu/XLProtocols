import datetime
import threading
import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.filedialog import *
from tkinter.ttk import Treeview

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

# 用来暂停捕获线程的线程事件
pause_sniff = threading.Event()
# 用来终止捕获线程的线程事件
stop_sniff = threading.Event()
# 捕获总数
sniff_count = 0
# 所有捕获到的报文
sniff_array = []

# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()

# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    global sniff_count
    global sniff_array
    # 如果是停止状态再捕获，提示保存pcap文件
    if stop_sniff.is_set():
        save_captured_data_to_file()
        sniff_count = 0
        sniff_array = []
        packet_list_tree.delete(*packet_list_tree.get_children())
        packet_dissect_tree.delete(*packet_dissect_tree.get_children())
        stop_sniff.clear()
        pause_sniff.clear()
    else:
        sniff_count = 0
        sniff_array = []
    # 开一个线程用于连续发送数据报文
    sniffThread = threading.Thread(target=sniffPacket)
    sniffThread.setDaemon(True)
    sniffThread.start()
    
    start_button['state'] = 'disabled'
    pause_button['state'] = 'normal'
    stop_button['state'] = 'normal'
    save_button['state'] = 'disabled'
    open_button['state'] = 'disabled'

# 暂停按钮单击响应函数
def pause_capture():
    if pause_button['text'] == '暂停':
        pause_sniff.set()
        pause_button['text'] = '继续'
    elif pause_button['text'] == '继续':
        pause_sniff.clear()
        pause_button['text'] = '暂停'

# 停止按钮单击响应函数
def stop_capture():
    stop_sniff.set()
    start_button['state'] = 'normal'
    pause_button['state'] = 'disabled'
    pause_button['text'] = '暂停'
    stop_button['state'] = 'disabled'
    save_button['state'] = 'normal'
    open_button['state'] = 'normal'

def on_stop_sniff(packet):
    return stop_sniff.is_set()==True

# 将抓到的数据包保存为pcap格式的文件
def save_captured_data_to_file():
    filename = asksaveasfilename(defaultextension = '.pcap',filetypes = [('PCAP Files', '*.pcap')],title = "保存到pcap文件")
    if filename != '':
        wrpcap(filename, sniff_array)
    

# 退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据
def quit_program():
    if sniff_count != 0:
        save_captured_data_to_file()
    exit(0)

# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime

# 开始捕获数据报文
def sniffPacket():
    print(fitler_entry.get())
#    sniff(prn=lambda x: resolvePacket(x), filter=fitler_entry.get(), stop_filter=lambda x: on_stop_sniff(x))
    sniff(prn=lambda x: resolvePacket(x), filter=fitler_entry.get(), stop_filter=lambda x : stop_sniff.is_set())


def readPcap():
    filename = askopenfilename(filetypes = [('PCAP Files', '*.pcap')],title = "打开pcap文件")
    if filename != '':
        global sniff_count
        global sniff_array
        # 如果是停止状态再打开，提示保存pcap文件
        if sniff_count != 0:
            save_captured_data_to_file()
            sniff_count = 0
            sniff_array = []
            packet_list_tree.delete(*packet_list_tree.get_children())
            packet_dissect_tree.delete(*packet_dissect_tree.get_children())
            stop_sniff.clear()
            pause_sniff.clear()
        sniff(prn=lambda x: resolvePacket(x), filter=fitler_entry['text'], offline=filename)

# 在显示区显示数据报文
def resolvePacket(pkg):
    global sniff_count
    global sniff_array
    if not pause_sniff.is_set():
        sniff_count = sniff_count + 1
        sniff_array.append(pkg)
        pkg_time = timestamp2time(pkg.time)
        # 推导数据包的协议类型
        proto_names = ['TCP', 'UDP', 'ICMP', 'IPv6', 'IP', 'ARP', 'Ether', 'Unknown']
        proto = ''
        for pn in proto_names:
            if pn in pkg:
                proto = pn
                break
        if proto == 'ARP' or proto == 'Ether':
            src = pkg.src
            dst = pkg.dst
        else:
            if 'IPv6' in pkg:
                src = pkg[IPv6].src
                dst = pkg[IPv6].dst
            elif 'IP' in pkg:
                src = pkg[IP].src
                dst = pkg[IP].dst
        length = len(pkg)
        info = pkg.summary()
        packet_list_tree.insert("", 'end', sniff_count, text=sniff_count, values=(sniff_count, pkg_time, src, dst, proto, length, info))
        packet_list_tree.update_idletasks()

"""
数据包列表单击事件响应函数，在数据包列表单击某数据包时，在协议解析区解析此数据包，并在hexdump区显示此数据包的十六进制内容
:param event: TreeView单击事件
:return: None
"""
def on_click_packet_list_tree(event):
    global sniff_array
    # event.widget获取Treeview对象，调用selection获取选择对象名称
    selected_item = event.widget.selection()
    # 清空packet_dissect_tree上现有的内容
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    # 获得点击的数据包
    packet = sniff_array[int(selected_item[0])-1]
    # 任何数据包必然是一个以太网帧，计算正确的校验和
    packetCheckSum = Ether(raw(packet))
    # 校验和检查结果
    isIPChkSum = 'Error'
    isTCPChkSum = 'Error'
    isUDPChkSum = 'Error'
    # 检查数据包的校验和
    if 'IP' in packet:
        # 检查IP校验和
        if packetCheckSum[IP].chksum == packet[IP].chksum:
            isIPChkSum = 'OK'
        else:
            isIPChkSum = 'Error'
    elif 'IPv6' in packet:
        # 检查IPv6校验和
        if packetCheckSum[IPv6].chksum == packet[IPv6].chksum:
            isIPChkSum = 'OK'
        else:
            isIPChkSum = 'Error'
    if 'TCP' in packet:
        # 检查TCP校验和
        if packetCheckSum[TCP].chksum == packet[TCP].chksum:
            isTCPChkSum = 'OK'
        else:
            isTCPChkSum = 'Error'
    elif 'UDP' in packet:
        # 检查UDP校验和
        if packetCheckSum[UDP].chksum == packet[UDP].chksum:
            isUDPChkSum = 'OK'
        else:
            isUDPChkSum = 'Error'
    
    # 按照协议层次显示数据包
    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None
    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        # 根据新插入数据项的长度动态调整协议解析区的宽度
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)

    # 插入校验和显示区
    if 'IP' in packet or 'IPv6' in packet:
        last_tree_entry = packet_dissect_tree.insert('', 'end', text='校验和')
        packet_dissect_tree.insert(last_tree_entry, 'end', text='IP校验和:'+isIPChkSum)
    if 'TCP' in packet:
        packet_dissect_tree.insert(last_tree_entry, 'end', text='TCP校验和:'+isTCPChkSum)
    elif 'UDP' in packet:
        packet_dissect_tree.insert(last_tree_entry, 'end', text='UDP校验和:'+isUDPChkSum)
    

    # 在hexdump区显示此数据包的十六进制内容
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'


# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
open_button = Button(toolbar, width=8, text="打开pcap", command=readPcap)
save_button = Button(toolbar, width=8, text="保存到pcap", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
open_button['state'] = 'normal'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
open_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=open_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)

packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)
main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
tk.mainloop()
