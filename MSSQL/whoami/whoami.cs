using System;

public class program
{
    public static string run()
    {
	    return System.Security.Principal.WindowsIdentity.GetCurrent().Name;
	}
}