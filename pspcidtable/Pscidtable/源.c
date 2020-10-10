#include<ntddk.h>
NTSTATUS
PsLookupProcessByProcessId(
__in HANDLE ProcessId,   //进程ID
__deref_out PEPROCESS *Process //返回的EPROCESS
);
NTSTATUS PsLookupThreadByThreadId(
	HANDLE   ThreadId,
	PETHREAD *Thread
	);
// 获取 PspCidTable
BOOLEAN get_PspCidTable(ULONG64* tableAddr) {

	// 获取 PsLookupProcessByProcessId 地址
	UNICODE_STRING uc_funcName;
	RtlInitUnicodeString(&uc_funcName, L"PsLookupProcessByProcessId");
	ULONG64 ul_funcAddr = MmGetSystemRoutineAddress(&uc_funcName);
	if (ul_funcAddr == NULL) {
		//DbgPrint("[LYSM] MmGetSystemRoutineAddress error.\n");
		return FALSE;
	}
	//DbgPrint("[LYSM] PsLookupProcessByProcessId:%p\n", ul_funcAddr);

	// 前 40 字节有 call（PspReferenceCidTableEntry）
	ULONG64 ul_entry = 0;
	for (INT i = 0; i < 40; i++) {
		if (*(PUCHAR)(ul_funcAddr + i) == 0xe8) {
			ul_entry = ul_funcAddr + i;
			break;
		}
	}
	if (ul_entry != 0) {
		// 解析 call 地址
		INT i_callCode = *(INT*)(ul_entry + 1);
		//DbgPrint("[LYSM] i_callCode:%X\n", i_callCode);
		ULONG64 ul_callJmp = ul_entry + i_callCode + 5;
		//DbgPrint("[LYSM] ul_callJmp:%p\n", ul_callJmp);
		// 来到 call（PspReferenceCidTableEntry） 内找 PspCidTable
		for (INT i = 0; i < 20; i++) {
			if (*(PUCHAR)(ul_callJmp + i) == 0x48 &&
				*(PUCHAR)(ul_callJmp + i + 1) == 0x8b &&
				*(PUCHAR)(ul_callJmp + i + 2) == 0x05) {
				// 解析 mov 地址
				INT i_movCode = *(INT*)(ul_callJmp + i + 3);
				DbgPrint("[LYSM] i_movCode:%X\n", i_movCode);
				ULONG64 ul_movJmp = ul_callJmp + i + i_movCode + 7;
				DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);
				// 得到 PspCidTable
				*tableAddr = ul_movJmp;
				DbgPrint("*tableAddr:%x\n", *(tableAddr));
				return TRUE;
			}
		}
	}

	// 前 40字节没有 call
	else {
		// 直接在 PsLookupProcessByProcessId 找 PspCidTable
		for (INT i = 0; i < 70; i++) {
			if (*(PUCHAR)(ul_funcAddr + i) == 0x49 &&
				*(PUCHAR)(ul_funcAddr + i + 1) == 0x8b &&
				*(PUCHAR)(ul_funcAddr + i + 2) == 0xdc &&
				*(PUCHAR)(ul_funcAddr + i + 3) == 0x48 &&
				*(PUCHAR)(ul_funcAddr + i + 4) == 0x8b &&
				*(PUCHAR)(ul_funcAddr + i + 5) == 0xd1 &&
				*(PUCHAR)(ul_funcAddr + i + 6) == 0x48 &&
				*(PUCHAR)(ul_funcAddr + i + 7) == 0x8b){							//48 8B d1					
				// 解析 mov 地址													//mov rdx,rcx 				
				DbgPrint("ul_funcAddr:%p\n", ul_funcAddr);//FFFFF8000 419A2DC		 //48 8B 0D F1 E0 ED FF
				INT i_movCode = *(INT*)(ul_funcAddr + i + 6 + 3);					//mov rcx,cs:PspCidTable
				DbgPrint("[LYSM] i_movCode:%X\n", i_movCode);//movCode=FFEDE0F1    u1_funcAddr+i+6 是mov 起始地址
				ULONG64 ul_movJmp = ul_funcAddr + i + 6 + i_movCode + 7;
				DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);//FFFFF8000 4078408
				// 得到 PspCidTable
				*tableAddr = ul_movJmp;
				DbgPrint("11111111\n");
				DbgPrint("*tableAddr:%p\n", *(tableAddr));
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* 解析一级表
BaseAddr：一级表的基地址
index1：第几个一级表
index2：第几个二级表
*/
VOID parse_table_1(ULONG64 BaseAddr, INT index1, INT index2) {

	//DbgPrint("[LYSM] BaseAddr 1:%p\n", BaseAddr);

	// 获取系统版本
	RTL_OSVERSIONINFOEXW OSVersion = { 0 };
	OSVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&OSVersion);

	// 遍历一级表（每个表项大小 16 ），表大小 4k，所以遍历 4096/16 = 526 次
	PEPROCESS p_eprocess = NULL;
	PETHREAD p_ethread = NULL;
	INT i_id = 0;
	for (INT i = 0; i < 256; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 16))) {
			//DbgPrint("[LYSM] 非法地址:%p\n", BaseAddr + i * 16);
			continue;
		}
		// win10
		if (OSVersion.dwMajorVersion == 10 && OSVersion.dwMinorVersion == 0) {
			ULONG64 ul_recode = *(PULONG64)(BaseAddr + i * 16);
			// 解密
			ULONG64 ul_decode = (LONG64)ul_recode >> 0x10;
			ul_decode &= 0xfffffffffffffff0;
			// 判断是进程还是线程
			i_id = i * 4 + 1024 * index1 + 512 * index2 * 1024;
			if (PsLookupProcessByProcessId(i_id, &p_eprocess) == STATUS_SUCCESS) {
				DbgPrint("[LYSM] PID:%d , i:%d , addr:%p , object:%p\n", i_id, i, BaseAddr + i * 0x10, ul_decode);
			}
			else if (PsLookupThreadByThreadId(i_id, &p_ethread) == STATUS_SUCCESS) {
				//DbgPrint("[LYSM] TID:%d , i:%d , addr:%p , object:%p\n", i_id, i, BaseAddr + i * 0x10, ul_decode);
			}

		}
		// win7
		if (OSVersion.dwMajorVersion == 6 && OSVersion.dwMinorVersion == 1) 
		{
			ULONG64 ul_recode = *(PULONG64)(BaseAddr + i * 16);
			// 解密
			ULONG64 ul_decode = ul_recode & 0xfffffffffffffff0;
			// 判断是进程还是线程
			i_id = i * 4 + 1024 * index1 + 512 * index2 * 1024;
			if (PsLookupProcessByProcessId(i_id, &p_eprocess) == STATUS_SUCCESS)
			{
				DbgPrint("[LYSM] PID:%d , i:%d , addr:%p , object:%p\n", i_id, i, BaseAddr + i * 0x10, ul_decode);
			}
			else if (PsLookupThreadByThreadId(i_id, &p_ethread) == STATUS_SUCCESS) 
			{
				//DbgPrint("[LYSM] TID:%d , i:%d , addr:%p , object:%p\n", i_id, i, BaseAddr + i * 0x10, ul_decode);
			}
			else 
			{ 
				
				continue; 
			}
		}
	}
}

/* 解析二级表
BaseAddr：二级表基地址
index2：第几个二级表
*/
VOID parse_table_2(ULONG64 BaseAddr, INT index2) {

	DbgPrint("[LYSM] BaseAddr 2:%p\n", BaseAddr);

	// 遍历二级表（每个表项大小 8）,表大小 4k，所以遍历 4096/8 = 512 次
	ULONG64 ul_baseAddr_1 = 0;
	for (INT i = 0; i < 512; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 8))) {
			//DbgPrint("[LYSM] 非法二级表指针（1）:%p\n", BaseAddr + i * 8);
			continue;
		}
		if (!MmIsAddressValid((PVOID64)*(PULONG64)(BaseAddr + i * 8))) {
			//DbgPrint("[LYSM] 非法二级表指针（2）:%p\n", BaseAddr + i * 8);
			continue;
		}
		ul_baseAddr_1 = *(PULONG64)(BaseAddr + i * 8);
		parse_table_1(ul_baseAddr_1, i, index2);
	}
}

/* 解析三级表
BaseAddr：三级表基地址
*/
VOID parse_table_3(ULONG64 BaseAddr) {

	//DbgPrint("[LYSM] BaseAddr 3:%p\n", BaseAddr);

	// 遍历三级表（每个表项大小 8）,表大小 4k，所以遍历 4096/8 = 512 次
	ULONG64 ul_baseAddr_2 = 0;
	for (INT i = 0; i < 512; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 8))) { continue; }
		if (!MmIsAddressValid((PVOID64)* (PULONG64)(BaseAddr + i * 8))) { continue; }
		ul_baseAddr_2 = *(PULONG64)(BaseAddr + i * 8);
		parse_table_2(ul_baseAddr_2, i);
	}
}

/* 遍历进程和线程
cidTableAddr：PspCidTable 地址
*/
BOOLEAN enum_PspCidTable(ULONG64 cidTableAddr) {

	DbgPrint("cidTableAddr:%p\n", cidTableAddr);

	DbgPrint("123:%p\n", (((ULONG64)*(PULONG64)cidTableAddr) + 8));//?+8? 是的 源代码有坑 把下面那个+8去掉
	// 获取 _HANDLE_TABLE 的 TableCode								//ULONG64 ul_tableCode = ...+8 
	ULONG64 ul_tableCode = *(PULONG64)(((ULONG64)*(PULONG64)cidTableAddr) );

	DbgPrint("[LYSM] ul_tableCode:%p\n", ul_tableCode);

	// 取低 2位（二级制11 = 3）
	INT i_low2 = ul_tableCode & 3;
	//DbgPrint("[LYSM] i_low2:%X\n", i_low2);

	// 一级表
	if (i_low2 == 0) {
		// TableCode 低 2位抹零（二级制11 = 3）
		parse_table_1(ul_tableCode & (~3), 0, 0);
	}
	// 二级表
	else if (i_low2 == 1) {
		// TableCode 低 2位抹零（二级制11 = 3）
		parse_table_2(ul_tableCode & (~3), 0);
	}
	// 三级表
	else if (i_low2 == 2) {
		// TableCode 低 2位抹零（二级制11 = 3）
		parse_table_3(ul_tableCode & (~3));
	}
	else {
		DbgPrint("[LYSM] i_low2 非法！\n");
		return FALSE;
	}

	return TRUE;
}
VOID Unload(IN PDRIVER_OBJECT pDriverObject) {
	DbgPrint("Driver UnLoad!");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	// 初始化省略...
	// ...
	// ...


	// 测试
	ULONG64 tableAddr = 0;
	if (get_PspCidTable(&tableAddr) == FALSE) {
		DbgPrint("[LYSM] get_PspCidTable error.\n");
	}
	else {
		DbgPrint("%x\n", tableAddr);
		enum_PspCidTable(tableAddr);
	}

	pDriverObj->DriverUnload = Unload;
	return STATUS_SUCCESS;
}