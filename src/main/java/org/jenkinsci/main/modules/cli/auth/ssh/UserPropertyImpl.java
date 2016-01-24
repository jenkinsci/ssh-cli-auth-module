package org.jenkinsci.main.modules.cli.auth.ssh;

import hudson.Extension;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.model.User;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.PublicKey;

import hudson.util.FormValidation;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

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

        @SuppressWarnings("unused")
        public FormValidation doCheckAuthorizedKeys(@QueryParameter String authorizedKeys, @AncestorInPath User currentUser) {
            for (User user: User.getAll()) {
                UserPropertyImpl userPropertyImpl = user.getProperty(UserPropertyImpl.class);
                if (!authorizedKeys.isEmpty() && userPropertyImpl!=null && userPropertyImpl.authorizedKeys!=null && user!=currentUser && checkReapeatedAuthorizedKeys(authorizedKeys, userPropertyImpl)) {
                    return FormValidation.error("There is at least one user with the same SSH public Key");
                }
            }
            return FormValidation.ok();
        }

        private boolean checkReapeatedAuthorizedKeys(String userAuthorizedKeys, UserPropertyImpl userPropertyImpl) {
            String[] splittedUserAuthorizedKeys = userAuthorizedKeys.split("\\r?\\n");
            String[] splittedAuthorizedKeys = userPropertyImpl.authorizedKeys.split("\\r?\\n");
            for (String userAuthorizedKey : splittedUserAuthorizedKeys) {
                for (String authorizedKey : splittedAuthorizedKeys) {
                    if(userAuthorizedKey.equals(authorizedKey)) {
                        return true;
                    }
                }
            }
            return false;
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
