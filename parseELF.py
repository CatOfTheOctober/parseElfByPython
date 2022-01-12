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
4、参考网站：
    https://cloud.tencent.com/developer/article/1710868
    https://www.cnblogs.com/jiqingwu/p/elf_format_research_01.html

'''

from ctypes import RTLD_GLOBAL
from io import RawIOBase, open_code
import mmap
from os import access, pipe, read, readlink
import struct
import sys
import binascii
import socket
from types import new_class

#用以表示elf_header的结构体
class elf32_hdr:
    e_ident =e_ident()	    #魔数和其他信息
	e_type =[2]			    #描述ELF文件类型，
	e_machine =[2]		    #ELF文件适用的处理器架构
	e_version =[4]		    #ELF文件的版本号，三种取值：0、1、2，目前为 1
	e_entry =[]		/* Entry point virtual address */
	Elf32_Off	e_phoff;		/* Program header table file offset */
	Elf32_Off	e_shoff;		/* Section header table file offset */
	Elf32_Word	e_flags;		               /* Processor-specific flags */
	Elf32_Half	e_ehsize;		/* ELF header size in bytes */
	Elf32_Half	e_phentsize;		/* Program header table entry size */
	Elf32_Half	e_phnum;		/* Program header table entry count */
	Elf32_Half	e_shentsize;		/* Section header table entry size */
	Elf32_Half	e_shnum;		/* Section header table entry count */
	Elf32_Half	e_shstrndx;		/* Section header string table index */

#用以表示elf_header中 e_ident数据的结构体
class e_ident:
    file_identification =[4]    #ELF文件标志，一般为："7F 45 4C 46":".ELF"
    ei_class_2  =[1]            #文件种类，三种取值：0：非法数据；1：32bit文件；2：64bit文件
    ei_data =[1]                #数据编码，三种取值：0：非法数据；1：高位在前；2：低位在前
    ei_version =[1]             #文件版本，目前为 1
    ei_osabi =[1]               #目前为 0
    ei_adbversion =[1]
    ei_pad =[6]                 #目前为 0
    ei_nident_Size =[1]         #目前为 0

#用于表示elf_header中 e_type数据的类型
elf32_hdr_e_tpye ={
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
elf32_hdr_e_machine ={
    0:"EM_NONE(0)",
    183:"EM_AARCH64(183)",  #

}



'''
函数功能：加载ELF文件
函数参数：
函数返回：
'''
def loadFile():
    try:
        dexFilePath =sys.argv[1]  #通过ssy来获取命令行参数，获取加载目标文件
    except IndexError:
        print("错误：请输入需要解析的dex文件路径")
        exit()
    
    global dexFileMmap
    dexFileMmap =open(dexFilePath,'rb')

    
    dexFileMmap.seek(0)
    dexMagic =dexFileMmap.read(5)
    if(dexMagic.hex() !="6465780a30"):   #判断文件格式是否为dex,"64 65 78 0A 30 33 35 00"
        print("请输入正确的dex文件")
        exit()



'''
函数功能：解析elf header信息
函数参数：
函数返回：
'''
def parseElf_header():
    '''
    ELF header位于文件开头，以 elf32_hdr结构来表示该数据。


    '''




if __name__ == "__main__":
    loadFile()   
    parseElf_header()
