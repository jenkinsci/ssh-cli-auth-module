package org.jenkinsci.main.modules.cli.auth.ssh;

import com.trilead.ssh2.crypto.Base64;
import com.trilead.ssh2.packets.TypesWriter;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Kohsuke Kawaguchi
 */
public class UserPropertyImpl extends UserProperty {
    public String authorizedKeys;

    @DataBoundConstructor
    public UserPropertyImpl(String authorizedKeys) {
        this.authorizedKeys = authorizedKeys;
    }

    public boolean isAuthorizedKey(String sig) {
        try {
            final BufferedReader r = new BufferedReader(new StringReader(authorizedKeys));
            String s;
            while ((s=r.readLine())!=null) {
                String[] tokens = s.split("\\s+");
                if (tokens.length>=2 && tokens[1].equals(sig))
                    return true;
            }
            return false;
        } catch (IOException e) {// impossible
            return false;
        }
    }

    @Extension
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        public String getDisplayName() {
            return "SSH Public Keys";
        }

        public UserProperty newInstance(User user) {
            return null;
        }
    }

    public static User findUser(PublicKey identity) {
        String sig = getPublicKeySignature(identity);
        for (User u : User.getAll()) {
            UserPropertyImpl p = u.getProperty(UserPropertyImpl.class);
            if (p!=null && p.isAuthorizedKey(sig))
                return u;
        }
        return null;
    }

    private static String getPublicKeySignature(PublicKey pk) {
        TypesWriter tw = new TypesWriter();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rpk = (RSAPublicKey) pk;
            tw.writeString("ssh-rsa");
            tw.writeMPInt(rpk.getPublicExponent());
            tw.writeMPInt(rpk.getModulus());
            return new String(Base64.encode(tw.getBytes()));
        }
        if (pk instanceof DSAPublicKey) {
            DSAPublicKey rpk = (DSAPublicKey) pk;
            tw.writeString("ssh-dss");
            DSAParams p = rpk.getParams();
            tw.writeMPInt(p.getP());
            tw.writeMPInt(p.getQ());
            tw.writeMPInt(p.getG());
            tw.writeMPInt(rpk.getY());
            return new String(Base64.encode(tw.getBytes()));
        }
        throw new IllegalArgumentException("Unknown key type: "+pk);
    }
}
