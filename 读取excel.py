#coding=gbk
#第一行指定了编码格式
from asyncio.windows_events import NULL  #赋个NULL值
from openpyxl import load_workbook  #导入openpyxl库，方便读取excel文件
from pathlib import Path    #导入pathlib库，方便操作文件
import matplotlib.pyplot as plt #画图用
import numpy as np  #numpy库，方便数组操作
#开始主流程
fpath=Path(input("Input the file path:"))#e.g.:D:\药品含量1.xlsx
file_name=fpath.name    #获取文件名
#定义各种变量
tmp=0
variance=0
print("Please input the number of data in the longest column :")
n=int(input())
data1=[0]*(n)  #创建一个长度为n的列表,n为最长的那一列的长度,从最开始到末尾
data2=[0]*(n-1)   #保存数据，方便后续画图,不会保存列的名称
No=[0]*(n-1)
for i in range(0,n-1):
    No[i]=i+1
    if i==n-1:
        break
#开始读取excel文件
wb=load_workbook(file_name)  #读取excel文件
print(wb.sheetnames)    #获取excel文件中的sheet名称
sheet=wb.active    #获取当前活动的sheet
print("Please input the scope of the data you want to read:")
column_start=int(input("column start:"))  #列起始值（请以最先有数据的一列作为初始值）
column_stop=int(input("column stop:")) 
row_start=int(input("raw start:")) #行起始值
row_stop=int(input("raw stop:")) 
for i in range(column_start,column_stop+1): #获取每行每列的数据
    for j in range(row_start,row_stop+1):   #需要每一列的开头是列列名称，不会有表格没有列名称吧。此处代码不会将列名称加入后续数据处理
        cell1=sheet.cell(row=j,column=i)
        if j==1:
            num=NULL
            data1[j-1]=0
        else:
            num=cell1.value
            data1[j-1]=num
            data2[j-2]=data1[j-1]
            tmp+=num
        print(cell1.value)   #输出每个单元格的数据
    num=0
    average_data=tmp/(row_stop-row_start)   #计算平均值
    for k in range(row_start,row_stop+1):   #计算方差
        num=data1[k-1]
        if num==0:
            variance=0   
        else:    
            variance+=(num-average_data)**2
    variance=variance/(row_stop-row_start-1)    #计算标准方差
    print("The average data of this factory is:",'%.3f' %average_data)  #输出平均值
    print("The variance of this factory is:",variance)  #输出方差
    tmp=0
    #画一手图--“直方散点图”
    plt.figure(figsize=(10,8))
    plt.scatter(No,data2)
    plt.xlabel("No")
    plt.ylabel("data")
    plt.title("data & No")
    plt.show()
#结束
print("Over!")