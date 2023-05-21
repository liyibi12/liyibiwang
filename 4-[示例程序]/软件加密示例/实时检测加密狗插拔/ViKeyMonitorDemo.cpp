// ViKeyMonitorDemo.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "windows.h"
#include "ViKeyMonitor.h"

#ifdef _M_X64
#pragma comment(lib, "./ViKeyMonitor/X64/ViKeyMonitor.lib")
#else
#pragma comment(lib, "./ViKeyMonitor/X86/ViKeyMonitor.lib")
#endif



void CALLBACK ViKeyMonitorCallBack(int nCount)
{
	if(nCount == 0)
	{
		printf("检测到加密狗已拔出!\n");
	}
	else
	{
		printf("检测到有加密狗插入，加密狗数量：%d个\n", nCount);
	}
	
}

int _tmain(int argc, _TCHAR* argv[])
{

	InitializeViKeyMonitor(ViKeyMonitorCallBack);
	while(1);
	return 0;
}

