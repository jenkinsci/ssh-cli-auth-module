package org.jenkinsci.main.modules.cli.auth.ssh;

import hudson.Extension;
import hudson.cli.CLICommand;
import hudson.cli.CliTransportAuthenticator;
import hudson.cli.Connection;
import hudson.model.User;
import hudson.remoting.Channel;
import org.jenkinsci.main.modules.instance_identity.InstanceIdentity;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.logging.Logger;

import static java.util.logging.Level.*;

/**
 * 
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class SshCliAuthenticator extends CliTransportAuthenticator {
    @Override
    public boolean supportsProtocol(String protocol) {
        return protocol.equals("ssh");
    }

    @Override
    public void authenticate(String protocol, Channel channel, Connection c) {
        try {
            byte[] sharedSecret = c.diffieHellman(true).generateSecret();
            InstanceIdentity ii = InstanceIdentity.get();
            c.proveIdentity(sharedSecret,new KeyPair(ii.getPublic(),ii.getPrivate()));
            User u;
            do {
                PublicKey clientIdentity = c.verifyIdentity(sharedSecret);
                u = UserPropertyImpl.findUser(clientIdentity);
                if (u!=null) {
                    // remember the authentication token. make sure to do this before
                    // we respond to avoid race condition.
                    channel.setProperty(CLICommand.TRANSPORT_AUTHENTICATION,u.impersonate());
                }
                c.writeBoolean(u!=null);
            } while(u==null);
        } catch (GeneralSecurityException e) {
            LOGGER.log(WARNING, "CLI authentication failure", e);
        } catch (IOException e) {
            LOGGER.log(WARNING, "CLI authentication failure", e);
        } finally {
            try {
                c.close();
            } catch (IOException e) {
                LOGGER.log(WARNING, "Failed to terminate the CLI authentication connection", e);
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger(SshCliAuthenticator.class.getName());
}
