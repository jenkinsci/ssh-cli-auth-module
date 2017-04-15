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

import hudson.remoting.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

public class PublicKeySignatureWriter {

    public String asString(PublicKey key) {
        if (key instanceof RSAPublicKey) return asString((RSAPublicKey) key);
        if (key instanceof DSAPublicKey) return asString((DSAPublicKey) key);
        throw new IllegalArgumentException("Unknown key type: " + key);
    }

    public String asString(DSAPublicKey key) {
        PemWriter tw = new PemWriter();
        tw.writeString("ssh-dss");
        DSAParams p = key.getParams();
        tw.writeBigInt(p.getP());
        tw.writeBigInt(p.getQ());
        tw.writeBigInt(p.getG());
        tw.writeBigInt(key.getY());
        return encode(tw);
    }

    public String asString(RSAPublicKey key) {
        PemWriter tw = new PemWriter();
        tw.writeString("ssh-rsa");
        tw.writeBigInt(key.getPublicExponent());
        tw.writeBigInt(key.getModulus());
        return encode(tw);
    }

    private String encode(PemWriter tw) {
        return Base64.encode(tw.getBytes());
    }

    private static class PemWriter {
        private final ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

        private byte[] getBytes() {
            return byteOutputStream.toByteArray();
        }

        private void writeString(String value) {
            byte[] bytes = value.getBytes(StandardCharsets.ISO_8859_1);
            writeBytes(bytes);
        }

        private void writeBigInt(BigInteger bigInteger) {
            byte bytes[] = bigInteger.toByteArray();

            if ((bytes.length == 1) && (bytes[0] == 0)) {
                writeUnsigned32BitInt(0);
            } else {
                writeBytes(bytes);
            }
        }

        private void writeUnsigned32BitInt(int value) {
            byteOutputStream.write((byte) (value >> 24));
            byteOutputStream.write((byte) (value >> 16));
            byteOutputStream.write((byte) (value >> 8));
            byteOutputStream.write((byte) value);
        }


        private void writeBytes(byte[] bytes) {
            writeUnsigned32BitInt(bytes.length);
            try {
                byteOutputStream.write(bytes);
            } catch (IOException e) {
                //impossible
                throw new Error(e);
            }
        }



    }
}
