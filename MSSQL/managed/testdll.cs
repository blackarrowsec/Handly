using System;
using System.IO;

public static class program
{
	public static string Do()
	{
		return "";
	}
	
    public static string run()
    {
		string res = "\n[+] Accessing C:\\ from loaded assembly!\n";
		try
		{
            foreach (string d in Directory.GetDirectories(@"C:\"))
            {
			    res += d + "\n";
		    }	
		}
		catch (Exception e)
		{
			res += e.Message + "\n";
		}
		return res;
    }
}
