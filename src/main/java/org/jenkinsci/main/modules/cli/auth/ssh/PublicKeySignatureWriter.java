/*
 * The MIT License
 *
 * Copyright (c) 2013 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.main.modules.cli.auth.ssh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.PublicKey;
import java.util.Objects;


public class PublicKeySignatureWriter {

    public String asString(PublicKey key) {
        if (key instanceof RSAPublicKey) return asString((RSAPublicKey) key);
        if (key instanceof DSAPublicKey) return asString((DSAPublicKey) key);
        throw new IllegalArgumentException("Unknown key type: " + key);
    }

    /*
     * copied from https://github.com/apache/mina-sshd/blob/master/sshd-common/src/main/java/org/apache/sshd/common/config/keys/impl/DSSPublicKeyEntryDecoder.java
     */
    public String asString(DSAPublicKey key) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            DSAParams keyParams = Objects.requireNonNull(key.getParams(), "No DSA params available");
            encodeString(output, "ssh-dss", StandardCharsets.UTF_8);
            encodeBigInt(output, keyParams.getP());
            encodeBigInt(output, keyParams.getQ());
            encodeBigInt(output, keyParams.getG());
            encodeBigInt(output, key.getY());
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        } catch(IOException e) {
            throw new Error(e);
        }
    }

    /*
     * copied from https://github.com/apache/mina-sshd/blob/master/sshd-common/src/main/java/org/apache/sshd/common/config/keys/impl/RSAPublicKeyDecoder.java
     */
    public String asString(RSAPublicKey key) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            encodeString(output, "ssh-rsa", StandardCharsets.UTF_8);
            encodeBigInt(output, key.getPublicExponent());
            encodeBigInt(output, key.getModulus());
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        } catch(IOException e) {
            throw new Error(e);
        }
    }

    /*
     * copied from https://github.com/apache/mina-sshd/blob/master/sshd-common/src/main/java/org/apache/sshd/common/config/keys/KeyEntryResolver.java
     */
    private int encodeString(OutputStream s, String v, Charset cs) throws IOException {
        byte[] bytes = v.getBytes(cs);
        return writeRLEBytes(s, bytes, 0, bytes.length);
    }

    private int encodeBigInt(OutputStream s, BigInteger v) throws IOException {
        byte[] bytes = v.toByteArray();
        return writeRLEBytes(s, bytes, 0, bytes.length);
    }

    private int writeRLEBytes(OutputStream s, byte[] bytes, int off, int len) throws IOException {
        byte[] lenBytes = encodeInt(s, len);
        s.write(bytes, off, len);
        return lenBytes.length + len;
    }

    private byte[] encodeInt(OutputStream s, int v) throws IOException {
        byte[] bytes = {
                (byte) ((v >> 24) & 0xFF),
                (byte) ((v >> 16) & 0xFF),
                (byte) ((v >> 8) & 0xFF),
                (byte) (v & 0xFF)
        };
        s.write(bytes);
        return bytes;
    }
}
