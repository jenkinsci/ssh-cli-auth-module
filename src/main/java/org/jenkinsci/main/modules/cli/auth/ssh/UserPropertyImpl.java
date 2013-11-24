package org.jenkinsci.main.modules.cli.auth.ssh;

import hudson.Extension;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.model.User;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.PublicKey;

import org.kohsuke.stapler.DataBoundConstructor;

/**
 * @author Kohsuke Kawaguchi
 */
public class UserPropertyImpl extends UserProperty {
    private static final PublicKeySignatureWriter signature = new PublicKeySignatureWriter();
    public String authorizedKeys;

    @DataBoundConstructor
    public UserPropertyImpl(String authorizedKeys) {
        this.authorizedKeys = authorizedKeys;
    }

    /**
     * Checks if this user has the given public key in his {@link #authorizedKeys}.
     */
    public boolean has(PublicKey pk) {
        return isAuthorizedKey(signature.asString(pk));
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
        String sig = signature.asString(identity);
        for (User u : User.getAll()) {
            UserPropertyImpl p = u.getProperty(UserPropertyImpl.class);
            if (p!=null && p.isAuthorizedKey(sig))
                return u;
        }
        return null;
    }
}
