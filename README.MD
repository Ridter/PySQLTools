# PySQLTools

[SharpSQLTools](https://github.com/uknowsec/SharpSQLTools) Python版本，方便在没windows机器或代理场景下使用。

>对于Link相关操作没做相关测试。有问题可以提Issue。

## 使用
支持Windows及密码认证 😊

Windows认证方式为：
```
python PySQLTools.py localhost/administrator:'password'@10.211.55.251 -windows-auth -debug
```

账号密码认证方式为：
```
python PySQLTools.py sa:'password'@10.211.55.251
```

如果碰到以下错误:
```
[-] [('SSL routines', '', 'unsafe legacy renegotiation disabled')]
```

可添加OPENSSL配置文件来加载，如：
```
OPENSSL_CONF=openssl.conf python PySQLTools.py sa:'password'@10.211.55.251
```

支持功能如下（直接扣来的没改，可以自己搞一个新的CLR来定制对应功能）:

```
enable_xp_cmdshell         - you know what it means
disable_xp_cmdshell        - you know what it means
xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
sp_oacreate {cmd}          - executes cmd using sp_oacreate
xp_dirtree {path}          - executes xp_dirtree on the path
sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
enable_ole                 - you know what it means
disable_ole                - you know what it means
upload {local} {remote}    - upload a local file to a remote path (OLE required)
download {remote} {local}  - download a remote file to a local path (OLE required)
enable_clr                 - you know what it means
disable_clr                - you know what it means
install_clr                - create assembly and procedure
uninstall_clr              - drop clr
clr_pwd                    - print current directory by clr
clr_ls {directory}         - list files by clr
clr_cd {directory}         - change directory by clr
clr_ps                     - list process by clr
clr_netstat                - netstat by clr
clr_ping {host}            - ping by clr
clr_cat {file}             - view file contents by clr
clr_rm {file}              - delete file by clr
clr_exec {cmd}             - for example: clr_exec whoami;clr_exec -p c:.exe;clr_exec -p c:\cmd.exe -a /c whoami
clr_efspotato {cmd}        - exec by EfsPotato like clr_exec
clr_badpotato {cmd}        - exec by BadPotato like clr_exec
clr_combine {remotefile}   - When the upload module cannot call CMD to perform copy to merge files
clr_dumplsass {path}       - dumplsass by clr
clr_rdp                    - check RDP port and Enable RDP
clr_getav                  - get anti-virus software on this machin by clr
clr_adduser {user} {pass}  - add user by clr
clr_download {url} {path}  - download file from url by clr
clr_scloader {code} {key}  - Encrypt Shellcode by Encrypt.py (only supports x64 shellcode.bin)
clr_scloader1 {file} {key} - Encrypt Shellcode by Encrypt.py and Upload Payload.txt
clr_scloader2 {remotefile} - Upload Payload.bin to target before Shellcode Loader
use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
enum_db                    - enum databases
enum_links                 - enum linked servers
enum_impersonate           - check logins that can be impersonate
enum_logins                - enum login users
enum_users                 - enum current db users
enum_owner                 - enum db owner
exec_as_user {user}        - impersonate with execute as user
exec_as_login {login}      - impersonate with execute as login
! {cmd}                    - executes a local shell cmd
show_query                 - show query
mask_query                 - mask query
```



## 参考：

```
1、https://github.com/uknowsec/SharpSQLTools
2、https://github.com/ShutdownRepo/impacket/blob/getST/examples/mssqlclient.py
```