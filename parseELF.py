'''
proj :parseELF
start:2022 01 12
by   :zxz
'''

'''
1、elf文件存在两种解析视图，编译视图和链接视图。 
    当然，编译视图在编译时使用，以 section为单位进行数据组织；
    链接视图在加载链接时使用，以 segment为单位进行数据组织，一个segment可能包含多个section信息。
        

2、ELF基本格式
    ELF header
    Program header table
    .text
    .rodata
    ...
    .data
    Section heade table

3、解析ELF文件的顺序
    解析ELF header
    解析Program header table、Section header table

4、本次解析只适用于64bit ELF文件，32bit文件暂不处理。
    受到影响字段：
    ELF_header:
        e_entry 32bit占用4字节，64bit占用8字节
        e_phoff 32bit占用4字节，64bit占用8字节
        e_shoff 32bit占用4字节，64bit占用8字节
5、参考网站：
    https://cloud.tencent.com/developer/article/1710868
    https://www.cnblogs.com/jiqingwu/p/elf_format_research_01.html

'''

from asyncio.windows_events import NULL
from ctypes import RTLD_GLOBAL
from ctypes.wintypes import PINT
from io import RawIOBase, open_code
import mmap
from os import access, pipe, read, readlink
import struct
import sys
import binascii
import socket
from turtle import end_fill
from types import new_class

#用以表示elf_header中 e_ident数据的结构体
class struct_e_ident:
    file_identification =[4]    #ELF文件标志，一般为："7F 45 4C 46":".ELF"
    ei_class_2  =[1]            #文件种类，三种取值：0：非法数据；1：32bit文件；2：64bit文件
    ei_data =[1]                #数据编码，三种取值：0：非法数据；1：高位在前；2：低位在前
    ei_version =[1]             #文件版本，目前为 1
    ei_osabi =[1]               #目前为 0
    ei_abiversion =[1]
    ei_pad =[6]                 #目前为 0
    ei_nident_Size =[1]         #目前为 0
    
    def printInfo(self):
        print("file_identification  -->",self.file_identification)
        print("ei_class_2           -->",self.ei_class_2)
        print("ei_data              -->",self.ei_data)
        print("ei_version           -->",self.ei_version)
        print("ei_osabi             -->",self.ei_osabi)
        print("ei_abiversion        -->",self.ei_abiversion)
        print("ei_pad               -->",self.ei_pad)
        print("ei_nident_Size       -->",self.ei_nident_Size)


#用于表示elf_header中 e_type数据的类型
dict_elf32_hdr_e_tpye ={
    0:"ET_NONE(0)",         #无文件类型
    1:"ET_REL(1)",          #可重定位文件，一般以 .o结尾
    2:"ET_EXEC(2)",         #可执行文件
    3:"ET_DYN(3)",          #动态库文件，一般以 .so结构
    4:"ET_CORE(4)",         #core文件，一般是 core dump下来的，用于保存系统相关信息
    5:"ET_NUM(5)",          #表示已经定义了 5种文件类型
    6:"ET_LOPROC(6)",       #特定处理器文件
    7:"ET_HIPROC(7)",       #特定处理器文件
}

#用于表示elf_header中 e_machine数据的类型，这部分定义过多 只取少数。
#详细信息请参考http://aospxref.com/android-10.0.0_r47/xref/external/elfutils/libelf/elf.h
dict_elf32_hdr_e_machine ={
    0:"EM_NONE(0)",
    183:"EM_AARCH64(183)",  #
}

#用以表示elf_header的结构体
class struct_elf32_hdr:
    e_ident =struct_e_ident()	    #魔数和其他信息
    e_type =[2]			    #描述ELF文件类型，
    e_machine =[2]		    #ELF文件适用的处理器架构
    e_version =[4]		    #ELF文件的版本号，三种取值：0、1、2，目前为 1
    e_entry =[8]		    #执行入口点，如果没有设置入口点，此值为0
    e_phoff =[8]		    #program header table的offset，如果没有 此值为0
    e_shoff =[8]		    #section header table的offset，如果没有 此值为0
    e_flags =[4]		    #特定处理器设置的标志位，Intel架构未设置此值 此值为0
    e_ehsize =[2]		    #header size,32bit为52字节，64bit为64字节
    e_phentsize =[2]		#program header table入口的大小，
    e_phnum =[2]		    #如果没有program header table 此值为0，e_phunm *e_phentsize =program header table的大小
    e_shentsize =[2]		#section header table入口的大小
    e_shnum =[2]		    #如果没有 section header table此值为0，e_shentsize *e_shnum =section header table的大小
    e_shstrndx =[2]		    #section header string table index，包含 section header table中的 section name string tables，如果没有section name string tables 此值为"SHN_UNDEF"0

    def printInfo(self):
        print("---***---elf_header---***---")
        self.e_ident.printInfo()
        
        print("e_type       -->",self.e_type)




#全局变量



'''
函数功能：加载ELF文件
函数参数：
函数返回：
'''
def loadFile():
    try:
        elfFilePath =sys.argv[1]  #通过ssy来获取命令行参数，获取加载目标文件
    except IndexError:
        print("错误：请输入需要解析的dex文件路径")
        exit()
    
    global elfFileMmap
    elfFileMmap =open(elfFilePath,'rb')

    
    elfFileMmap.seek(0)
    elfMagic =elfFileMmap.read(5)
    
    if(elfMagic.hex() !="7f454c4602"):   #判断文件格式是否为64bit elf,"7f 45 4c 46 02"
        print("请输入正确的64bit ELF文件")
        exit()


'''
函数功能：解析elf header信息
函数参数：
函数返回：
'''
def parseElfHeader():
    '''
    ELF header位于文件开头，以 elf32_hdr结构来表示该数据。
    32bit elf文件此数据大小为52字节，64bit elf文件此数据大小为64字节，本次只考虑64bit
    '''
    elfFileMmap.seek(0)
    elfHeader =elfFileMmap.read(64)
    
    elf_Header =struct_elf32_hdr()
    e_ident_ =struct_e_ident()

    e_ident_.file_identification =elfHeader[0:4]
    e_ident_.ei_class_2 =elfHeader[4:5]
    e_ident_.ei_data =elfHeader[5:6]
    e_ident_.ei_version =elfHeader[6:7]
    e_ident_.ei_osabi =elfHeader[7:8]
    e_ident_.ei_abiversion =elfHeader[8:9]
    e_ident_.ei_pad =elfHeader[9:15]
    e_ident_.ei_nident_Size =elfHeader[15:16]

    elf_Header.e_ident =e_ident_
    elf_Header.e_type =elfHeader[16:18]
    elf_Header.e_machine =elfHeader[]

'''
函数功能：将内存中大尾的hex数据拼接，例如 0x11 +0x22 +0x33 +0x44 = 0x11223344
函数参数：内存中的hex数据
函数返回：小尾的hex数据
'''

def append_hex(*arg):
    if(len(arg) ==2):
        arg0 =arg[0]<<8
        result = arg0 +arg[1]
        return hex(result)
    elif(len(arg) ==4):
        arg0 =arg[0]<<24
        arg1 =arg[1]<<16
        arg2 =arg[2]<<8
        result = arg0 +arg1 +arg2 +arg[3]
        return hex(result)
    elif(len(arg) ==8):
        arg0 =arg[0]<<56
        arg1 =arg[1]<<48
        arg2 =arg[2]<<40
        arg3 =arg[3]<<32
        arg4 =arg[4]<<24
        arg5 =arg[5]<<16
        arg6 =arg[6]<<0
        result =arg0 +arg1 +arg2 +arg3 +arg4 +arg5 +arg6 +arg[7]
        return hex(result)



if __name__ == "__main__":
    loadFile()   
    parseElfHeader()
