using System;
public class Greeter {
    private static string secretGreeting = "classified greeting text";
    private static string Format(string s) => "[" + s + "]";
    public static void Run() => Console.WriteLine(Format(secretGreeting));
}
public static class Program { public static void Main() => Greeter.Run(); }
