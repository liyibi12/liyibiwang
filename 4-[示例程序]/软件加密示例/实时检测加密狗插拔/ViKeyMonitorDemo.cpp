// ViKeyMonitorDemo.cpp : �������̨Ӧ�ó������ڵ㡣
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
		printf("��⵽���ܹ��Ѱγ�!\n");
	}
	else
	{
		printf("��⵽�м��ܹ����룬���ܹ�������%d��\n", nCount);
	}
	
}

int _tmain(int argc, _TCHAR* argv[])
{

	InitializeViKeyMonitor(ViKeyMonitorCallBack);
	while(1);
	return 0;
}

