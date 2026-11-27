namespace ObsorRuntime;

/// <summary>
/// Shipped alongside every obsor-classic-protected assembly. Decrypts the
/// XOR'd string literals Obsor.Classic embeds at the call sites that used to
/// hold <c>ldstr "literal"</c> directly.
///
/// HONEST SCOPE: the XOR key is a plain IL operand sitting right next to the
/// call to this method -- see Obsor.Classic/README (root dotnet/README.md)
/// "What classic does NOT protect against" for a measured, working static
/// recovery of every string in a protected assembly with no execution at
/// all. This method's job is to exist as the call target, not to be a
/// security boundary.
/// </summary>
public static class StrDec
{
    public static string Decrypt(string s, byte key)
    {
        var arr = s.ToCharArray();
        for (int i = 0; i < arr.Length; i++) arr[i] = (char)(arr[i] ^ key);
        return new string(arr);
    }
}
