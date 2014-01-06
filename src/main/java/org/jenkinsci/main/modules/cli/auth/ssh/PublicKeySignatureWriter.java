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

import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.packets.TypesWriter;

public class PublicKeySignatureWriter {

    public String asString(PublicKey key) {
        if (key instanceof RSAPublicKey) return asString((RSAPublicKey) key);
        if (key instanceof DSAPublicKey) return asString((DSAPublicKey) key);
        throw new IllegalArgumentException("Unknown key type: " + key);
    }

    public String asString(DSAPublicKey key) {
        TypesWriter tw = new TypesWriter();
        tw.writeString("ssh-dss");
        DSAParams p = key.getParams();
        tw.writeMPInt(p.getP());
        tw.writeMPInt(p.getQ());
        tw.writeMPInt(p.getG());
        tw.writeMPInt(key.getY());
        return encode(tw);
    }

    public String asString(RSAPublicKey key) {
        TypesWriter tw = new TypesWriter();
        tw.writeString("ssh-rsa");
        tw.writeMPInt(key.getPublicExponent());
        tw.writeMPInt(key.getModulus());
        return encode(tw);
    }

    private String encode(TypesWriter tw) {
        return new String(Base64.encode(tw.getBytes()));
    }
}
