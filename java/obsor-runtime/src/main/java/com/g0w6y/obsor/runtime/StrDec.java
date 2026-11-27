package com.g0w6y.obsor.runtime;

import java.nio.charset.StandardCharsets;

/**
 * Shipped alongside every obsor-classic-protected .class/.jar. Decrypts the
 * XOR'd string constants Obsor.Classic embeds at the call sites that used to
 * hold an {@code ldc "literal"} instruction directly.
 *
 * <p>HONEST SCOPE: the XOR key is a plain bytecode operand (a {@code bipush}
 * right next to the call to this method) -- see the Java port's README
 * "What classic does NOT protect against" for a measured, working static
 * recovery of every string in a protected class with no execution at all
 * (the same ASM-based attack the .NET port documents against its own
 * Obsor.Classic). This method's job is to exist as the call target, not to
 * be a security boundary.
 *
 * <p>Implementation note: the encoder UTF-8-encodes the original string to
 * bytes, then XORs each byte and stores it as one char (0-255) in the
 * constant. Decrypting therefore XORs back to the raw UTF-8 bytes FIRST,
 * then decodes those bytes as UTF-8 -- skipping that final decode step (and
 * just returning the XOR'd char array as a String) corrupts any non-ASCII
 * literal, exactly the mojibake bug the .NET port's StrDec.cs had and fixed.
 */
public final class StrDec {
    private StrDec() {}

    public static String decrypt(String s, int key) {
        byte[] bytes = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            bytes[i] = (byte) (s.charAt(i) ^ key);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
