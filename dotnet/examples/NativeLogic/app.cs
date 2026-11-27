using System;
using System.Runtime.InteropServices;

public static class Program
{
    [DllImport("obsor_native", EntryPoint = "secret_transform")]
    private static extern long SecretTransform(long x);

    public static void Main()
    {
        Console.WriteLine("computed token: " + SecretTransform(7));
    }
}
