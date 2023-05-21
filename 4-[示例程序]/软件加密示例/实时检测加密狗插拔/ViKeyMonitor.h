#pragma once

typedef void (CALLBACK *PViKeyMonitorCallBack)(int nCount);

extern "C" __declspec(dllexport) int InitializeViKeyMonitor(PViKeyMonitorCallBack pfnCallBack);