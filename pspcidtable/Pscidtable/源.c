#include<ntddk.h>
NTSTATUS
PsLookupProcessByProcessId(
__in HANDLE ProcessId,   //����ID
__deref_out PEPROCESS *Process //���ص�EPROCESS
);
NTSTATUS PsLookupThreadByThreadId(
	HANDLE   ThreadId,
	PETHREAD *Thread
	);
// ��ȡ PspCidTable
BOOLEAN get_PspCidTable(ULONG64* tableAddr) {

	// ��ȡ PsLookupProcessByProcessId ��ַ
	UNICODE_STRING uc_funcName;
	RtlInitUnicodeString(&uc_funcName, L"PsLookupProcessByProcessId");
	ULONG64 ul_funcAddr = MmGetSystemRoutineAddress(&uc_funcName);
	if (ul_funcAddr == NULL) {
		//DbgPrint("[LYSM] MmGetSystemRoutineAddress error.\n");
		return FALSE;
	}
	//DbgPrint("[LYSM] PsLookupProcessByProcessId:%p\n", ul_funcAddr);

	// ǰ 40 �ֽ��� call��PspReferenceCidTableEntry��
	ULONG64 ul_entry = 0;
	for (INT i = 0; i < 40; i++) {
		if (*(PUCHAR)(ul_funcAddr + i) == 0xe8) {
			ul_entry = ul_funcAddr + i;
			break;
		}
	}
	if (ul_entry != 0) {
		// ���� call ��ַ
		INT i_callCode = *(INT*)(ul_entry + 1);
		//DbgPrint("[LYSM] i_callCode:%X\n", i_callCode);
		ULONG64 ul_callJmp = ul_entry + i_callCode + 5;
		//DbgPrint("[LYSM] ul_callJmp:%p\n", ul_callJmp);
		// ���� call��PspReferenceCidTableEntry�� ���� PspCidTable
		for (INT i = 0; i < 20; i++) {
			if (*(PUCHAR)(ul_callJmp + i) == 0x48 &&
				*(PUCHAR)(ul_callJmp + i + 1) == 0x8b &&
				*(PUCHAR)(ul_callJmp + i + 2) == 0x05) {
				// ���� mov ��ַ
				INT i_movCode = *(INT*)(ul_callJmp + i + 3);
				DbgPrint("[LYSM] i_movCode:%X\n", i_movCode);
				ULONG64 ul_movJmp = ul_callJmp + i + i_movCode + 7;
				DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);
				// �õ� PspCidTable
				*tableAddr = ul_movJmp;
				DbgPrint("*tableAddr:%x\n", *(tableAddr));
				return TRUE;
			}
		}
	}

	// ǰ 40�ֽ�û�� call
	else {
		// ֱ���� PsLookupProcessByProcessId �� PspCidTable
		for (INT i = 0; i < 70; i++) {
			if (*(PUCHAR)(ul_funcAddr + i) == 0x49 &&
				*(PUCHAR)(ul_funcAddr + i + 1) == 0x8b &&
				*(PUCHAR)(ul_funcAddr + i + 2) == 0xdc &&
				*(PUCHAR)(ul_funcAddr + i + 3) == 0x48 &&
				*(PUCHAR)(ul_funcAddr + i + 4) == 0x8b &&
				*(PUCHAR)(ul_funcAddr + i + 5) == 0xd1 &&
				*(PUCHAR)(ul_funcAddr + i + 6) == 0x48 &&
				*(PUCHAR)(ul_funcAddr + i + 7) == 0x8b){							//48 8B d1					
				// ���� mov ��ַ													//mov rdx,rcx 				
				DbgPrint("ul_funcAddr:%p\n", ul_funcAddr);//FFFFF8000 419A2DC		 //48 8B 0D F1 E0 ED FF
				INT i_movCode = *(INT*)(ul_funcAddr + i + 6 + 3);					//mov rcx,cs:PspCidTable
				DbgPrint("[LYSM] i_movCode:%X\n", i_movCode);//movCode=FFEDE0F1    u1_funcAddr+i+6 ��mov ��ʼ��ַ
				ULONG64 ul_movJmp = ul_funcAddr + i + 6 + i_movCode + 7;
				DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);//FFFFF8000 4078408
				// �õ� PspCidTable
				*tableAddr = ul_movJmp;
				DbgPrint("11111111\n");
				DbgPrint("*tableAddr:%p\n", *(tableAddr));
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* ����һ����
BaseAddr��һ����Ļ���ַ
index1���ڼ���һ����
index2���ڼ���������
*/
VOID parse_table_1(ULONG64 BaseAddr, INT index1, INT index2) {

	//DbgPrint("[LYSM] BaseAddr 1:%p\n", BaseAddr);

	// ��ȡϵͳ�汾
	RTL_OSVERSIONINFOEXW OSVersion = { 0 };
	OSVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	RtlGetVersion((PRTL_OSVERSIONINFOW)&OSVersion);

	// ����һ����ÿ�������С 16 �������С 4k�����Ա��� 4096/16 = 526 ��
	PEPROCESS p_eprocess = NULL;
	PETHREAD p_ethread = NULL;
	INT i_id = 0;
	for (INT i = 0; i < 256; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 16))) {
			//DbgPrint("[LYSM] �Ƿ���ַ:%p\n", BaseAddr + i * 16);
			continue;
		}
		// win10
		if (OSVersion.dwMajorVersion == 10 && OSVersion.dwMinorVersion == 0) {
			ULONG64 ul_recode = *(PULONG64)(BaseAddr + i * 16);
			// ����
			ULONG64 ul_decode = (LONG64)ul_recode >> 0x10;
			ul_decode &= 0xfffffffffffffff0;
			// �ж��ǽ��̻����߳�
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
			// ����
			ULONG64 ul_decode = ul_recode & 0xfffffffffffffff0;
			// �ж��ǽ��̻����߳�
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

/* ����������
BaseAddr�����������ַ
index2���ڼ���������
*/
VOID parse_table_2(ULONG64 BaseAddr, INT index2) {

	DbgPrint("[LYSM] BaseAddr 2:%p\n", BaseAddr);

	// ����������ÿ�������С 8��,���С 4k�����Ա��� 4096/8 = 512 ��
	ULONG64 ul_baseAddr_1 = 0;
	for (INT i = 0; i < 512; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 8))) {
			//DbgPrint("[LYSM] �Ƿ�������ָ�루1��:%p\n", BaseAddr + i * 8);
			continue;
		}
		if (!MmIsAddressValid((PVOID64)*(PULONG64)(BaseAddr + i * 8))) {
			//DbgPrint("[LYSM] �Ƿ�������ָ�루2��:%p\n", BaseAddr + i * 8);
			continue;
		}
		ul_baseAddr_1 = *(PULONG64)(BaseAddr + i * 8);
		parse_table_1(ul_baseAddr_1, i, index2);
	}
}

/* ����������
BaseAddr�����������ַ
*/
VOID parse_table_3(ULONG64 BaseAddr) {

	//DbgPrint("[LYSM] BaseAddr 3:%p\n", BaseAddr);

	// ����������ÿ�������С 8��,���С 4k�����Ա��� 4096/8 = 512 ��
	ULONG64 ul_baseAddr_2 = 0;
	for (INT i = 0; i < 512; i++) {
		if (!MmIsAddressValid((PVOID64)(BaseAddr + i * 8))) { continue; }
		if (!MmIsAddressValid((PVOID64)* (PULONG64)(BaseAddr + i * 8))) { continue; }
		ul_baseAddr_2 = *(PULONG64)(BaseAddr + i * 8);
		parse_table_2(ul_baseAddr_2, i);
	}
}

/* �������̺��߳�
cidTableAddr��PspCidTable ��ַ
*/
BOOLEAN enum_PspCidTable(ULONG64 cidTableAddr) {

	DbgPrint("cidTableAddr:%p\n", cidTableAddr);

	DbgPrint("123:%p\n", (((ULONG64)*(PULONG64)cidTableAddr) + 8));//?+8? �ǵ� Դ�����п� �������Ǹ�+8ȥ��
	// ��ȡ _HANDLE_TABLE �� TableCode								//ULONG64 ul_tableCode = ...+8 
	ULONG64 ul_tableCode = *(PULONG64)(((ULONG64)*(PULONG64)cidTableAddr) );

	DbgPrint("[LYSM] ul_tableCode:%p\n", ul_tableCode);

	// ȡ�� 2λ��������11 = 3��
	INT i_low2 = ul_tableCode & 3;
	//DbgPrint("[LYSM] i_low2:%X\n", i_low2);

	// һ����
	if (i_low2 == 0) {
		// TableCode �� 2λĨ�㣨������11 = 3��
		parse_table_1(ul_tableCode & (~3), 0, 0);
	}
	// ������
	else if (i_low2 == 1) {
		// TableCode �� 2λĨ�㣨������11 = 3��
		parse_table_2(ul_tableCode & (~3), 0);
	}
	// ������
	else if (i_low2 == 2) {
		// TableCode �� 2λĨ�㣨������11 = 3��
		parse_table_3(ul_tableCode & (~3));
	}
	else {
		DbgPrint("[LYSM] i_low2 �Ƿ���\n");
		return FALSE;
	}

	return TRUE;
}
VOID Unload(IN PDRIVER_OBJECT pDriverObject) {
	DbgPrint("Driver UnLoad!");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	// ��ʼ��ʡ��...
	// ...
	// ...


	// ����
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