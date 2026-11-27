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
        // The encoder (Obsor.Classic/Program.cs) UTF8-encodes the original
        // string to bytes, XORs each byte, then stores each encrypted byte
        // as one char (0-255) in the ldstr operand. Reversing the XOR alone
        // and returning that char array directly only happens to work for
        // pure ASCII, where a UTF-8 byte equals its own code point: any
        // non-ASCII literal (accents, CJK, emoji) is multi-byte in UTF-8, so
        // skipping the final UTF-8 decode corrupted it into mojibake. We
        // must XOR back to the original UTF-8 bytes, then decode them.
        var bytes = new byte[s.Length];
        for (int i = 0; i < s.Length; i++) bytes[i] = (byte)(s[i] ^ key);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }
}
