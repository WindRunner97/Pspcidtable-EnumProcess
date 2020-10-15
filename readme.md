简单分析下mhyprot2.sys中,关于句柄表的内容  
1.sub\_140007338与sub\_1400070CC,确定系统版本号,并赋值一些不同版本下的偏移.  

![](https://github.com/WindRunner97/Pspcidtable-EnumProcess/blob/master/IMG/1.png)  
![](https://github.com/WindRunner97/Pspcidtable-EnumProcess/blob/master/IMG/2.png)  
 
比如qword\_14000A700=384,就是对应win7 x64下的EPROCESS+0x180 PID偏移.  
2.从ExEnumHandleTable来看,qword\_14000A6D0可能是PspcidTable地址.  
![](https://github.com/WindRunner97/Pspcidtable-EnumProcess/blob/master/IMG/3.png)   


3.地址在sub\_140005998中得到  
首先取PsLookupProcessByProcessId地址  
![](https://github.com/WindRunner97/Pspcidtable-EnumProcess/blob/master/IMG/4.png)  
 正常来说,递增地址,比对特征码就能找到PspcidTable的偏移了,但他这里可能是为了不明文暴露,利用编译器划分了一块连续的内存区域,将特征码不明显的藏在了里面.  
![](https://github.com/WindRunner97/Pspcidtable-EnumProcess/blob/master/IMG/5.png)   
 然后传入v40的地址,变化v9(v40)的地址,比对四次特征码即可  
![](https://github.com/WindRunner97/Pspcidtable-EnumProcess/blob/master/IMG/6.png)   
然后  
![](https://github.com/WindRunner97/Pspcidtable-EnumProcess/blob/master/IMG/7.png)  
大致可归纳为：    

    BOOLEAN GetPspCidTableAddress(PULONG64 PspCidTable)
    {

	UNICODE_STRING FuncName;
	RtlInitUnicodeString(&FuncName, L"PsLookupProcessByProcessId");
	ULONG64 FuncAddress = MmGetSystemRoutineAddress(&FuncName);
	if (!FuncAddress)
		return FALSE;

	for (int i = 0; i < 100; i++)
	{
		if (*(PUCHAR)(FuncAddress + i) == 0x48 &&
			*(PUCHAR)(FuncAddress + i + 1) == 0x8b &&
			*(PUCHAR)(FuncAddress + i + 2) == 0xd1)
		{
			int Offset = *(int*)(FuncAddress + i + 3 + 3);
			int CodeLength = 7;
			ULONG64 StartAddress= FuncAddress + i + 3;
			*PspCidTable = StartAddress + Offset + CodeLength;
			return TRUE;
		}
	}
	return FALSE;
    }  



注意,存放Object的地址在不同Windows版本加密方式是不同的,参考mhy的解密函数.  
![](https://github.com/WindRunner97/Pspcidtable-EnumProcess/blob/master/IMG/8.png)  
a1为Object地址.  
目前就看到这,可以猜测一下他获得了全局句柄表后,会做些什么.  
1.	遍历进程.  
2.	ExEnumHandleTable PspcidTable,可以在回调里做一些事.  
3.	对每个进程的句柄表再解析,看看是否有原神进程的句柄,拥有什么权限(或许可以结合ObregisterCallbacks降权).  
4.	对全局句柄表操作,隐藏进程,不过这个不可能,太不稳定了也没必要.  
