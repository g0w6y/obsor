using System;

public static class Program
{
    public static void Main()
    {
        var seq = Fibonacci(8);
        Console.WriteLine("FIB [" + string.Join(",", seq) + "]");
    }

    public static int[] Fibonacci(int n)
    {
        var seq = new int[n];
        seq[0] = 0; seq[1] = 1;
        for (int i = 2; i < n; i++) seq[i] = seq[i - 1] + seq[i - 2];
        return seq;
    }
}
