using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.Threading;

public class program
{
    public static string run()
    {
        string result;
        try 
		{		
            result = findTokens();
        }
		catch (Exception e)
		{
			result = e.Message + "\n";
		} 
        return result;        
    }

	public const int NO_ERROR = 0;
	public const int ERROR_INSUFFICIENT_BUFFER = 122;
	public const int HANDLE_FLAG_INHERIT = 0x00000001;
	public const int SE_PRIVILEGE_ENABLED = 0x00000002;
	public const int TOKEN_QUERY = 0x00000008;
	public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
	public const string IMPERSONATE = "SeImpersonatePrivilege";
	public const string ASSIGN_PRIMARY_TOKEN = "SeAssignPrimaryTokenPrivilege";
	public const string INCREASE_QUOTA = "SeIncreaseQuotaPrivilege";
	public const long SECURITY_MANDATORY_HIGH_RID =(0x00003000L);

	public enum SID_NAME_USE
	{
	    SidTypeUser = 1,
	    SidTypeGroup,
	    SidTypeDomain,
	    SidTypeAlias,
	    SidTypeWellKnownGroup,
	    SidTypeDeletedAccount,
	    SidTypeInvalid,
	    SidTypeUnknown,
	    SidTypeComputer
	}

	public enum TOKEN_INFORMATION_CLASS
	{
	    TokenUser = 1,
	    TokenGroups,
	    TokenPrivileges,
	    TokenOwner,
	    TokenPrimaryGroup,
	    TokenDefaultDacl,
	    TokenSource,
	    TokenType,
	    TokenImpersonationLevel,
	    TokenStatistics,
	    TokenRestrictedSids,
	    TokenSessionId,
	    TokenGroupsAndPrivileges,
	    TokenSessionReference,
	    TokenSandBoxInert,
	    TokenAuditPolicy,
	    TokenOrigin,
	    TokenElevationType,
	    TokenLinkedToken,
	    TokenElevation,
	    TokenHasRestrictions,
	    TokenAccessInformation,
	    TokenVirtualizationAllowed,
	    TokenVirtualizationEnabled,
	    TokenIntegrityLevel,
	    TokenUIAccess,
	    TokenMandatoryPolicy,
	    TokenLogonSid,
	    MaxTokenInfoClass
	}

	public struct TOKEN_USER
	{
	    public SID_AND_ATTRIBUTES User;
	}

	public struct TOKEN_ORIGIN
	{
	    public ulong tokenorigin;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct TOKEN_MANDATORY_LABEL
	{
	    public SID_AND_ATTRIBUTES Label;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct SID_AND_ATTRIBUTES
	{
	    public IntPtr Sid;
	    public int Attributes;
	}

	public enum OBJECT_INFORMATION_CLASS : int
	{
	    ObjectBasicInformation = 0,
	    ObjectNameInformation = 1,
	    ObjectTypeInformation = 2,
	    ObjectAllTypesInformation = 3,
	    ObjectHandleInformation = 4
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct OBJECT_TYPE_INFORMATION
	{ // Information Class 1
	    public UNICODE_STRING Name;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct UNICODE_STRING
	{
	    public ushort Length;
	    public ushort MaximumLength;
	    public IntPtr Buffer;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
	   public IntPtr hProcess;
	   public IntPtr hThread;
	   public int dwProcessId;
	   public int dwThreadId;
	}

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
	     public Int32 cb;
	     public string lpReserved;
	     public string lpDesktop;
	     public string lpTitle;
	     public Int32 dwX;
	     public Int32 dwY;
	     public Int32 dwXSize;
	     public Int32 dwYSize;
	     public Int32 dwXCountChars;
	     public Int32 dwYCountChars;
	     public Int32 dwFillAttribute;
	     public Int32 dwFlags;
	     public Int16 wShowWindow;
	     public Int16 cbReserved2;
	     public IntPtr lpReserved2;
	     public IntPtr hStdInput;
	     public IntPtr hStdOutput;
	     public IntPtr hStdError;
	}
	public enum LogonFlags
	{
	     WithProfile = 1,
	     NetCredentialsOnly
	}

	public enum CreationFlags
	{
	    NoConsole = 0x08000000
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
	    public int nLength;
	    public IntPtr lpSecurityDescriptor;
	    public int bInheritHandle;
	}

	public enum TOKEN_TYPE
	{
	    TokenPrimary = 1,
	    TokenImpersonation
	}

	public enum SECURITY_IMPERSONATION_LEVEL
	{
	    SecurityAnonymous,
	    SecurityIdentification,
	    SecurityImpersonation,
	    SecurityDelegation
	}

	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct TokPriv1Luid
	{
	    public int Count;
	    public long Luid;
	    public int Attr;
	}

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool GetTokenInformation(
	    IntPtr TokenHandle,
	    TOKEN_INFORMATION_CLASS TokenInformationClass,
	    IntPtr TokenInformation,
	    int TokenInformationLength,
	    out int ReturnLength);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern IntPtr GetSidSubAuthority(IntPtr pSid, int nSubAuthority);

	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);
	
	[DllImport("ntdll.dll")]
	public static extern int NtQueryObject(IntPtr ObjectHandle, int ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength, ref int returnLength);

	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	public static extern bool LookupAccountSid(
	    [MarshalAs(UnmanagedType.LPTStr)] string strSystemName,
	    IntPtr pSid,
	    System.Text.StringBuilder pName,
	    ref uint cchName,
	    System.Text.StringBuilder pReferencedDomainName,
	    ref uint cchReferencedDomainName,
	    out SID_NAME_USE peUse);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int GetCurrentThreadId();

	protected static string findTokens()
	{
	    List<string> users = GetAllUsernames();
		var os = GetCurrentThreadId();
		var th  = Thread.CurrentThread;
        return String.Join(" || ", users);
	}

	public static List<string> GetAllUsernames()
	{
	    int nLength = 0, status = 0;
		List<string> users = new List<string>();
		List<string> tokens = new List<string>();
		
	    try
	    {
	        for (int index = 1; index < 100000; index++)
	        {
	            IntPtr handle = new IntPtr(index);
	            IntPtr hObjectName = IntPtr.Zero;
	            try
	            {
	                nLength = 0;
	                hObjectName = Marshal.AllocHGlobal(256 * 1024);
	                status = NtQueryObject(handle, (int)OBJECT_INFORMATION_CLASS.ObjectTypeInformation, hObjectName, nLength, ref nLength);

	                if (string.Format("{0:X}", status) == "C0000008") // STATUS_INVALID_HANDLE
	                    continue;
	                
	                while (status != 0)
	                {
	                    Marshal.FreeHGlobal(hObjectName);
	                    if (nLength == 0)
	                        continue;

	                    hObjectName = Marshal.AllocHGlobal(nLength);
	                    status = NtQueryObject(handle, (int)OBJECT_INFORMATION_CLASS.ObjectTypeInformation, hObjectName, nLength, ref nLength);
	                }

					OBJECT_TYPE_INFORMATION objObjectName = (OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(hObjectName, typeof(OBJECT_TYPE_INFORMATION));

	                if (objObjectName.Name.Buffer != IntPtr.Zero)
	                {
	                    string strObjectName = "" + Marshal.PtrToStringUni(objObjectName.Name.Buffer);

	                    if (strObjectName.ToLower() == "token")
	                    {
	                        int tokenInfLen = 0;
	                        bool result;

	                        // first call gets length of TokenInformation
	                        result = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfLen, out tokenInfLen);
	                        IntPtr TokenInformation = Marshal.AllocHGlobal(tokenInfLen);
	                        result = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenUser, TokenInformation, tokenInfLen, out tokenInfLen);

	                        if (result)
	                        {

	                            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));

	                            IntPtr pstr = IntPtr.Zero;
	                            StringBuilder name = new StringBuilder();
	                            uint cchName = (uint)name.Capacity;
	                            StringBuilder referencedDomainName = new StringBuilder();
	                            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
	                            SID_NAME_USE sidUse;

	                            int err = NO_ERROR;
	                            if (!LookupAccountSid(null, TokenUser.User.Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
	                            {
	                                err = Marshal.GetLastWin32Error();
	                                if (err == ERROR_INSUFFICIENT_BUFFER)
	                                {
	                                    name.EnsureCapacity((int)cchName);
	                                    referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
	                                    err = NO_ERROR;
	                                    if (!LookupAccountSid(null, TokenUser.User.Sid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out sidUse))
	                                        err = Marshal.GetLastWin32Error();
	                                }
	                            }

	                            if (err == NO_ERROR)
	                            {
	                                string userName = referencedDomainName.ToString().ToLower() + "\\" + name.ToString().ToLower();
	                                IntPtr tokenInformation = Marshal.AllocHGlobal(8);
	                                result = GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenOrigin, tokenInformation, 8, out tokenInfLen);
	                                if (result)
	                                {
	                                    TOKEN_ORIGIN tokenOrigin = (TOKEN_ORIGIN)Marshal.PtrToStructure(tokenInformation, typeof(TOKEN_ORIGIN));
	                                    if (tokenOrigin.tokenorigin != 0)
	                                            userName += "*";
	                                }

	                                // From https://www.pinvoke.net/default.aspx/Constants/SECURITY_MANDATORY.html
	                                IntPtr pb = Marshal.AllocCoTaskMem(1000);
	                                try 
	                                {
	                                    int cb = 1000;
	                                    if (GetTokenInformation(handle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, out cb)) 
	                                    {
	                                        IntPtr pSid = Marshal.ReadIntPtr(pb);

	                                        int dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (int)(Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));

	                                        if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) 
	                                            userName += " (+)";
	                                    }
	                                }
	                                finally 
	                                {
	                                    Marshal.FreeCoTaskMem(pb);
	                                }
                                    
	                                if (!users.Contains(userName))
									{
	                                    SetHandleInformation(
	                                        handle,
	                                        0x00000002, // HANDLE_FLAG_PROTECT_FROM_CLOSE
	                                        0x00000002
	                                        );
	                                    users.Add(userName);
										tokens.Add(userName + " -> " + handle.ToInt32().ToString());
	                                }
	                            }
	                        }
	                        Marshal.FreeHGlobal(TokenInformation);
	                    }
	                }
	            }
	            catch (Exception) { }
	            finally
	            {
	                Marshal.FreeHGlobal(hObjectName);
	            }
	            
	        }
			return tokens;
	    }
	    catch (Exception) { }   

	    return users;
    }
}
