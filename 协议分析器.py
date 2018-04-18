# coding=utf-8
import datetime
import threading
import tkinter
from tkinter import *
from tkinter import font, filedialog
from tkinter.constants import *
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview

from scapy.layers.inet import *
from scapy.layers.l2 import *


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


# 时间戳转为格式化的时间字符串
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


def on_click_packet_list_tree(event):
    """
    数据包列表单击事件响应函数，在数据包列表单击某数据包时，在协议解析区解析此数据包，并在hexdump区显示此数据包的十六进制内容
    :param event: TreeView单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    # 清空packet_dissect_tree上现有的内容
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    # !!!!!!!!!!!!!!!测试用的数据包!!!!!!!!!!!!!!要求换成你抓到的数据包!!!!!!!!!!!!!!!!!!!
    packet = IP()/TCP(dport=80)
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
    #!!!!!!!!!!!!!!!!此处没实现到抓到的数据包的校验和的检查!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    #!!!!!!!!!!!!!!!!要求在此处补充代码检查数据包校验包是否正确，包括TCP/UPD/IP包的校验和!!!!!!!!!!!
    # 在hexdump区显示此数据包的十六进制内容
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'


# 测试在界面中显示一个数据包的内容
def just_a_test():
        # !!!!!!!!!!!!!!!测试用的数据包!!!!!!!!!!!!!!要求换成你抓到的数据包!!!!!!!!!!!!!!!!!!!
        packet = IP()/TCP(dport=80)
        packet_time = timestamp2time(packet.time)
        src = packet[IP].src
        dst = packet[IP].dst
        proto = 'http'
        length = len(packet)
        info = packet.summary()
        # print(info)
        packet_list_tree.insert("", 'end', '1', text='1', values=('1', packet_time, src, dst, proto, length, info))
        packet_list_tree.update_idletasks()


# 将抓到的数据包保存为pcap格式的文件
def save_captured_data_to_file():
    pass


# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    pass


# 暂停按钮单击响应函数
def pause_capture():
    pass


# 停止按钮单击响应函数
def stop_capture():
    pass

# 退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据
def quit_program():
    pass


# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
# tk.resizable(0, 0)
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
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
just_a_test()
tk.mainloop()

