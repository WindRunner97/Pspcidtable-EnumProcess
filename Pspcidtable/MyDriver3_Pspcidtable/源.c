#include<ntddk.h>
NTSTATUS PsLookupProcessByProcessId(
__in HANDLE ProcessId,   
__deref_out PEPROCESS *Process 
);


VOID Unload(IN PDRIVER_OBJECT pDriverObject) {
	DbgPrint("Driver UnLoad!");
}

typedef struct _OBJECT_HEADER
{
	LONG PointerCount;
	union
	{
		LONG HandleCount;
		PVOID NextToFree;
	};
	LONG64 lock;
	UCHAR TypeIndex;
	//...
} OBJECT_HEADER, *POBJECT_HEADER;


VOID EnumFirstTable(ULONG64 TableCode,int j)
{
	
	//���256�����   x64 win7 handle table entry��С��16
	for (int i = 0; i < 4096 / 16; i++)
	{
		if (MmIsAddressValid((PVOID)(TableCode + i * 16)))
		{
			ULONG64 ObjectAddress = *(PULONG64)(TableCode + i * 16);
			//ȥ��3λ
			ObjectAddress = ObjectAddress&(~7);
			if (MmIsAddressValid(ObjectAddress))
			{
				//header=body-0x30
				POBJECT_HEADER ObjectHeader = (ObjectAddress - 0x30);	
				//process--->7   thread---->8 ɸѡ������
				if (ObjectHeader->TypeIndex == 7)
				{
					//ObjectAddress--->Eprocess
					//DbgPrint("%p\n", ObjectAddress);
					//PID��ʵ���Ǿ������
					DbgPrint("PID:%d  ", j * 256 * 4 + i * 4);
					DbgPrint("NAME:%s\n", ObjectAddress + 0x2e0);//����15�ֽ�����,���������������ȫ,�ڿ�����иĽ�
				}

			}
			
		}
	}
}
VOID EnumSecondTable(ULONG64 TableCode)
{
	//512��ָ�� ���������Ϊ512x256
	for (int i = 0; i < 4096 / 8; i++)
	{
		
		if (MmIsAddressValid((PVOID)(TableCode + i * 8)) && (*(PULONG64)(TableCode + i * 8) != 0)) //&& (*(PULONG64)(TableCode + i * 8) != 0)
		{
			ULONG64 SecondTableCode = *(PULONG64)(TableCode + i * 8);
			//DbgPrint("SecondTableCode:%p\n", SecondTableCode);
			SecondTableCode = SecondTableCode&(~3);
			EnumFirstTable(SecondTableCode,i);
		}
	}
}
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
BOOLEAN EnumPspCidTable(ULONG64 PspCidTable)
{
	ULONG64 HandleTable = *(PULONG64)PspCidTable;
	ULONG64 TableCode = *(PULONG64)HandleTable;
	
	//ȡ��2λ�жϼ�����
	int level = TableCode & 3;
	TableCode = TableCode&(~3);

	//DbgPrint("TableCode:%p\n", TableCode);
	if (level == 0)
	{
		//DbgPrint("first table\n");
		EnumFirstTable(TableCode,0);
	}
	else if (level == 1)
	{
		//DbgPrint("second table\n");
		EnumSecondTable(TableCode);
	}
	else if (level == 2)
	{
		//NULL ���������������
	}

	
	return TRUE;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	ULONG64 PspCidTable = 0;
	
	if (GetPspCidTableAddress(&PspCidTable))
	{
		//DbgPrint("PspCidTable:%p\n", PspCidTable);
		if (!EnumPspCidTable(PspCidTable))
			DbgPrint("enum pspcidtable error\n");
	}
	else
		DbgPrint("get pspcidtable error\n");
	
	
	pDriverObj->DriverUnload = Unload;
	return STATUS_SUCCESS;
}