#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


DWORD RvaToOffset(DWORD dwRva, char* buffer);	//计算数据目录表起始位置到文件头的偏移(RVAtoRAW)
void ImportTable(char* buffer);	//解析导入表函数
void ExportTable(char* buffer);	//解析导出表函数
void TlsTable(char* buffer);	//解析TLS表的函数

int main()
{
    int nFileLength = 0;
    FILE* pFile = NULL;
    char path[100];
    char *buffer;

    printf("Please input the path of the file you want to look by my parser of PE:\n");
    gets(path);
    fopen_s(&pFile,path, "rb");
	if(pFile == NULL)
	{
		printf("Open file failed,maybe it's doesn't exist?\n");
		return 0;
	}
    fseek(pFile, 0, SEEK_END);	//允许文件读写位置移动到文件尾，返回文件长度
    nFileLength = ftell(pFile);	//获取文件长度
	if(nFileLength == 0)
	{
		printf("The file is empty!\n");
		return 0;
	}
    rewind(pFile);	//将文件指针重新指向文件开头
    
	//接下来为文件分配空间
    int ImageBase = nFileLength * sizeof(char) + 1;
    buffer = (char*)malloc(ImageBase);
    memset(buffer, 0, nFileLength * sizeof(char) + 1);
	//读取文件内容
    fread(buffer, 1, ImageBase, pFile);
    //至此，文件读取操作完成

    PIMAGE_DOS_HEADER P_DosHeader;	//定义指向_IMAGE_DOS_HEADER结构体的指针
    P_DosHeader = (PIMAGE_DOS_HEADER)buffer;
    printf("Basic Info is as follow:\n");
    printf("The Flag bit of this file is %X\n", P_DosHeader->e_magic);
    printf("The offset of the DOS header is:%X\n", P_DosHeader->e_lfanew);
	printf("------------------------Thats's basic info of DosHeaderStruct----------------------------\n");
    printf("\n");
    if(P_DosHeader->e_magic != IMAGE_DOS_SIGNATURE)//判断是否为PE文件
    {
        printf("This file is not a PE file!\n");
        return 0;
    }
    //解析PE文件头
    //解析FILE_HEADER
    PIMAGE_NT_HEADERS32 P_NtHeader;	//定义指向_IMAGE_NT_HEADERS32结构体的指针
    P_NtHeader = (PIMAGE_NT_HEADERS32)(buffer + P_DosHeader->e_lfanew);
    printf("The follow is the info of PE file header:\n");
    printf("The Flag bit of this file is %X\n", P_NtHeader->Signature);
    printf("Machine: %X\n", P_NtHeader->FileHeader.Machine);
    printf("Number of Sections: %d\n", P_NtHeader->FileHeader.NumberOfSections);
    printf("Characteristics: %X\n", P_NtHeader->FileHeader.Characteristics);
    /*printf("TimeDateStamp: %X\n", P_NtHeader->FileHeader.TimeDateStamp);//这项可以告诉我们编译器创建文件的时间，注释掉吧，感觉没用过*/
    printf("------------------------Thats's basic info of FILE_HEADER----------------------------\n");
    printf("\n");
    //解析OPTIONAL_HEADER
    printf("The follow is the info of PE file optional header:\n");
    printf("Magic: %X\n", P_NtHeader->OptionalHeader.Magic); //这个值是0x10B，表示PE32,0x20B表示PE32+(64位)
    printf("AddressOfEntryPoint: %X\n", P_NtHeader->OptionalHeader.AddressOfEntryPoint);//这项可以告诉我们程序的入口地址
    printf("ImageBase: %X\n", P_NtHeader->OptionalHeader.ImageBase);//这个值是文件的起始地址，也就是我们要解析的文件的起始地址
    printf("SectionAlignment: %X\n", P_NtHeader->OptionalHeader.SectionAlignment);//节区对齐值
    printf("FileAlignment: %X\n", P_NtHeader->OptionalHeader.FileAlignment);//文件对齐值
    printf("SizeOfImage: %X\n", P_NtHeader->OptionalHeader.SizeOfImage);//文件大小
    printf("SizeOfHeaders: %X\n", P_NtHeader->OptionalHeader.SizeOfHeaders);//头部大小
    printf("CheckSum: %X\n", P_NtHeader->OptionalHeader.CheckSum);//映像校验和,用处就是用来检验文件是否被修改过。
    printf("Subsystem: %X\n", P_NtHeader->OptionalHeader.Subsystem);//子系统
    printf("NumberOfRvaAndSizes: %X\n", P_NtHeader->OptionalHeader.NumberOfRvaAndSizes);//RVA和Sizes的数量
    printf("Number Of Data Directories: %X\n", P_NtHeader->OptionalHeader.NumberOfRvaAndSizes);//数据目录的数量
    printf("------------------------Thats's basic info of OPTIONAL_HEADER----------------------------\n");
    printf("\n");
    printf("------------------------Next are some tables----------------------------\n");
    printf("\n");
    //解析DATA_DIRECTORY
    printf("The follow is the info of PE file data directory:\n");
    printf("Address of Export Table: %X\n", P_NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
    printf("Size of Export Table: %X\n", P_NtHeader->OptionalHeader.DataDirectory[0].Size);
    printf("Address of Import Table: %X\n", P_NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress);
    printf("Size of Import Table: %X\n", P_NtHeader->OptionalHeader.DataDirectory[1].Size);
    printf("Address of Resource Table: %X\n", P_NtHeader->OptionalHeader.DataDirectory[2].VirtualAddress);
    printf("Size of Resource Table: %X\n", P_NtHeader->OptionalHeader.DataDirectory[2].Size);
    printf("Address of TLS Table: %X\n", P_NtHeader->OptionalHeader.DataDirectory[9].VirtualAddress);
    printf("Size of TLS Table: %X\n", P_NtHeader->OptionalHeader.DataDirectory[9].Size);
    printf("Address of IAT: %X\n", P_NtHeader->OptionalHeader.DataDirectory[12].VirtualAddress);
    printf("Size of IAT: %X\n", P_NtHeader->OptionalHeader.DataDirectory[12].Size);
    printf("------------------------Thats's basic info of DATA_DIRECTORY----------------------------\n");
    printf("\n");
    //解析SECTION_HEADER
    printf("The follow is the info of PE file section header:\n");
    PIMAGE_SECTION_HEADER P_SectionHeader;
    P_SectionHeader = (PIMAGE_SECTION_HEADER)(buffer + P_DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    for(int i = 0; i < P_NtHeader->FileHeader.NumberOfSections; i++)
    {
        printf("Section Name: %s\n", P_SectionHeader->Name);
        printf("Virtual Address: %X\n", P_SectionHeader->VirtualAddress);
        printf("Size of Raw Data: %X\n", P_SectionHeader->SizeOfRawData);
        printf("Pointer to Raw Data: %X\n", P_SectionHeader->PointerToRawData);
        printf("Pointer to Relocations: %X\n", P_SectionHeader->PointerToRelocations);
        printf("Pointer to Linenumbers: %X\n", P_SectionHeader->PointerToLinenumbers);
        printf("Number of Relocations: %X\n", P_SectionHeader->NumberOfRelocations);
        printf("Number of Linenumbers: %X\n", P_SectionHeader->NumberOfLinenumbers);
        printf("Characteristics: %X\n", P_SectionHeader->Characteristics);
        printf("------------------------Thats's basic info of SECTION----------------------------\n");
        printf("\n");
        P_SectionHeader++;
    }
    printf("Please input which information you want to look :\n");
    printf("1.Export Table\n");
    printf("2.Import Table\n");
    printf("3.TLS Table\n");
    printf("4.exit\n");
    int choice;
    while(1)
	{
		printf("Input a number: ");
		scanf("%d", &choice);
		if (choice == 1)
			ExportTable(buffer);
		else if (choice == 2)
			ImportTable(buffer);
		else if (choice == 3)
			TlsTable(buffer);
		else if (choice == 4)
            return 0;
        else
            printf("Please input again and make sur that's valid\n");
	}
    system("pause");
    free(buffer);//走之前别忘了清空缓存区
	return 0;
}

DWORD RvaToOffset(DWORD dwRva, char* buffer)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;//Dos头
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);//PE头
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);//区段表
	//判断是否落在头部当中
	if (dwRva < pSection[0].VirtualAddress)
	{
		return dwRva;
	}
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		if (dwRva >= pSection[i].VirtualAddress && dwRva <= pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize)
		{
            //dwRva-pSection[i].VirtualAddress是数据目录表到区段起始地址的偏移（OFFSET）
			// pSection[i].PointerToRawData区段到文件头的偏移（OFFSET）
			return dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;//返回虚拟地址对应的文件偏移地址（RAW）,这个公式一定得掌握
		}
	}
}
void ImportTable(char* buffer)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT);//
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToOffset(pDataDirectory->VirtualAddress, buffer) + buffer);//指向导入表的第一个描述符
	//遍历导入表
	while(pImportDescriptor->Name)
    {
        char * szDllname = (char*)(RvaToOffset(pImportDescriptor->Name, buffer) + buffer);//指向DLL名字 
        printf("DLL Name: %s\n", szDllname);
        PIMAGE_THUNK_DATA32 PIAT = (PIMAGE_THUNK_DATA32)(RvaToOffset(pImportDescriptor->FirstThunk, buffer) + buffer);//指向IAT
        PIMAGE_THUNK_DATA32 PINT = (PIMAGE_THUNK_DATA32)(RvaToOffset(pImportDescriptor->OriginalFirstThunk, buffer) + buffer);//指向INT
        //解析IAT，IAT是一个结构体数组，其结尾为0
        while(PIAT->u1.Ordinal)
        {
            if(PIAT->u1.Ordinal & 0x80000000)//如果是序号
            {
                printf("Ordinal: %2d\n", PIAT->u1.Ordinal & 0xFFFF);
                printf("\n");
            }
            else//如果是函数名
            {
                PIMAGE_IMPORT_BY_NAME szFuncName = (PIMAGE_IMPORT_BY_NAME)(RvaToOffset(PIAT->u1.AddressOfData, buffer) + buffer);
                printf("Function Name: %s\n", szFuncName->Name);
                printf("Hint: %X\n", szFuncName->Hint);
                printf("\n");
            }
            PIAT++;
        }
        pImportDescriptor++;
    }
}
void ExportTable(char* buffer)
{
	//Dos头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	//PE
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	//定位数据目录表中的导出表
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
	//填充导出表结构
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(RvaToOffset(pExportDir->VirtualAddress, buffer) + buffer);
	char* szName = (char*)(RvaToOffset(pExport->Name, buffer) + buffer);
	if (pExport->AddressOfFunctions == 0)
	{
		printf("Without EXPORT_TABLE!\n");
		return;
	}
	printf("Name:%s\n", szName);
	printf("Number of Functions:%08X\n", pExport->NumberOfFunctions);
	printf("Number of Names:%08X\n", pExport->NumberOfNames);
	printf("Func_addr:%08X\n", pExport->AddressOfFunctions);
	printf("\n");
	//获取函数数量
	DWORD dwNumOfFUN = pExport->NumberOfFunctions;
	//函数名数量
	DWORD dwNumOfNames = pExport->NumberOfNames;
	//基
	DWORD dwBase = pExport->Base;
	//导出地址表
	PDWORD pEat32 = (PDWORD)(RvaToOffset(pExport->AddressOfFunctions, buffer) + buffer);
	//导出名称表
	PDWORD pEnt32 = (PDWORD)(RvaToOffset(pExport->AddressOfNames, buffer) + buffer);
	//导出序号表
	PWORD pId = (PWORD)(RvaToOffset(pExport->AddressOfNameOrdinals, buffer) + buffer);
	for (int i = 0; i < dwNumOfFUN; i++)
	{
		if (pEat32[i] == 0)
			continue;
		DWORD Id = 0;
		for (; Id < dwNumOfNames; Id++)
		{ 
			if (pId[Id] == i)
				break;
		}
		if (Id == dwNumOfNames)
		{
			printf("Name:%X Address:0x%08X Name[NuLL]\n", i + dwBase, pEat32[i]);
            printf("\n");
		}
		else
		{
			char* szFunName = (char*)(RvaToOffset(pEnt32[Id], buffer) + buffer);
			printf("Name:%X Address:0x%08X Name[%s]\n", i + dwBase, pEat32[i],szFunName);
            printf("\n");
		}
		printf("-------------------------------------\n");
	}
	printf("----------------------------------------------------------\n");
}
void TlsTable(char* buffer)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + buffer);
	PIMAGE_DATA_DIRECTORY pTLSDir = (pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_TLS);//定位数据目录表中的TLS表
	PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)(RvaToOffset(pTLSDir->VirtualAddress, buffer) + buffer);//填充TLS结构
    printf("StartAddressOfRawData: %08X\n", pTLS->StartAddressOfRawData);
    printf("EndAddressOfRawData: %08X\n", pTLS->EndAddressOfRawData);
    printf("TLS_Callback: %08X\n", pTLS->AddressOfCallBacks);//tls回调函数
    printf("TLS_Size: %08X\n", pTLS->SizeOfZeroFill);
    printf("TLS_Characteristics: %08X\n", pTLS->Characteristics);
}
