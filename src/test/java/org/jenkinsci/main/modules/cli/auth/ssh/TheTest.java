package org.jenkinsci.main.modules.cli.auth.ssh;

import hudson.cli.CLI;
import hudson.cli.CLICommand;
import hudson.model.User;
import hudson.remoting.Callable;

import java.util.Collections;

import org.jvnet.hudson.test.HudsonTestCase;
import org.jvnet.hudson.test.TestExtension;

/**
 * @author Kohsuke Kawaguchi
 */
public class TheTest extends HudsonTestCase {

    @TestExtension
    public static class TestCommand extends CLICommand {
        @Override
        public String getShortDescription() {
            return "test";
        }

        @Override
        protected int run() throws Exception {
            return User.current().getId().equals("foo")?0:1;
        }
    }

    public void testRsa() throws Exception {
        testRoundtrip(PRIVATE_RSA_KEY, PUBLIC_RSA_KEY);
    }

    public void testDsa() throws Exception {
        testRoundtrip(PRIVATE_DSA_KEY, PUBLIC_DSA_KEY);
    }

    private void testRoundtrip(String privateKey, String publicKey) throws Exception {
        User foo = User.get("foo");
        foo.addProperty(new UserPropertyImpl(publicKey));
        configRoundtrip(foo);
        assertEquals(publicKey, foo.getProperty(UserPropertyImpl.class).authorizedKeys);

        CLI cli = new CLI(getURL());
        try {
            cli.authenticate(Collections.singleton(CLI.loadKey(privateKey)));
            assertEquals(0, cli.execute("test"));

            // closures executed with this channel should automatically carry the credential
            // now that it's authenticated
            cli.upgrade();
            assertEquals("foo", cli.getChannel().call(new GetCurrentUser()));
        } finally {
            cli.close();
        }
    }

    private static final String PUBLIC_RSA_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr+ZaQ/SI8xIr5BtMCh7gizoH/cVzEi8tCxwvHOu5eELzxl1FBwUH5/pRzMI31w1+WlYXBCYQSvcWgpLlAZn7VaJYCxUE9K9gMxLPmk81fUec8sFr5hSj6cPL3hWdk4CgdJ0M2Q/GNJExvbDsiFMFb/p9jnrKhHQ47mhT4HpMLTE4fG5+AB3liJZhaUo9lbHfmhpmpps9o1tE1z7YcIO4ckvCklxF+04mVRjKur3lcezh2i4TXjMGmkDgU7pTrwf9OM9rDo5dSpsAK/dGWlBT01jhv69wOfUitcYENAK07Tgyoti3pEYD3b2ugxQ0fe0LqoxFa//O540PjMhxEbmuQQ== xxx@yyy";

    private static final String PRIVATE_RSA_KEY =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEogIBAAKCAQEAr+ZaQ/SI8xIr5BtMCh7gizoH/cVzEi8tCxwvHOu5eELzxl1F\n" +
            "BwUH5/pRzMI31w1+WlYXBCYQSvcWgpLlAZn7VaJYCxUE9K9gMxLPmk81fUec8sFr\n" +
            "5hSj6cPL3hWdk4CgdJ0M2Q/GNJExvbDsiFMFb/p9jnrKhHQ47mhT4HpMLTE4fG5+\n" +
            "AB3liJZhaUo9lbHfmhpmpps9o1tE1z7YcIO4ckvCklxF+04mVRjKur3lcezh2i4T\n" +
            "XjMGmkDgU7pTrwf9OM9rDo5dSpsAK/dGWlBT01jhv69wOfUitcYENAK07Tgyoti3\n" +
            "pEYD3b2ugxQ0fe0LqoxFa//O540PjMhxEbmuQQIBIwKCAQA8TvpgcRkC4ail+rr8\n" +
            "J9f1OHfEuLm9F30oYW89HZ6s48FLUy2cAbmRXSNcJVT5RnR2vm5KkLUhBEI7ZZBY\n" +
            "Ug0Hatxbki2VuHjBDcOFXPxld6OGbjOfV4in61vXHVqY+OaOYbtDG1nmIyb/NVhp\n" +
            "QQkttPfZFCgtaa0eiiti6BoeHu+RRycl5DOVyLyE85WDhnC8AT1bpJk3PFDQjW0G\n" +
            "Ht9qC67S+Tbh2W0bdcm58SbM8C+rHIeiq+8IbUt73nsyCLJEv2vN5zpPdCGwjV4r\n" +
            "1BPMzsgB0LOzniCRQmhHw6VmqPNhLCT/CHY3741iwxuOhIoXZaeC9EvCcWxZ5/PK\n" +
            "kpJLAoGBANVu1bcYskA9cy81hXcjMUjVlGt2ZO3vLrCTqrrS2DkXyzNo2UGv0uGp\n" +
            "FeVkqwz75/EDE3V/sMT3E2VIu9AC6k3irofLMnmZayyXuIw+SWuCyGfmYxKOjxk5\n" +
            "9u4JYXJgZTmqtPyfmF/c7K4oiSvbLX5Qr5FnRoEyDrDMOuAmLyG1AoGBANL7M+oO\n" +
            "PLmA7wxaqP0IOHigLQg6QOYoZ1M4okpL0XO6iSaXgXmOFnEb61j3vidK8xB5XLzu\n" +
            "t3Mf7rQ3CvGvhFINnT4qzs70HRv797zG3Fk7NV0pVlGKLip+zWYD+/V2u4hyDaRy\n" +
            "KkszAPlP0fhDEk/q9DYcG3C+XjgPqQnctGHdAoGBAJJaoS0YP7cFkM/qL6ImwrWZ\n" +
            "xNv5ace59CFPUIAbjPPzDv6uS9VFXWeJ4yD0koyPenlhMeorrGnN/qvaGmLAK6Mf\n" +
            "GJehRy7PmfKxLhcGI7dvn10wQ+93spT0jBDwfVW+cUwdSOe95NQFNJSuFOrfb6cS\n" +
            "wYhG0UKl+3HrIQ67GQErAoGAZnoDRcxmoz6f/q+xKnG1B2O+GfBoqk4jjtJddIs5\n" +
            "2SAWuvkhoXDmVDIh2sF5ng52D1Dj5r0XRovaV4hzB60FwXRTsHsxP/LpkT/eusb9\n" +
            "T+mO8rxOf2BfkPvC2cdrwF491I8rMp3aB0Sos5vMYqQ8GDBKuzI5NsLdTm4BpbRX\n" +
            "nT8CgYEAtY1KJQjGitOgMV8AiOgieUTRN8cR7z2bf9TUlZ3uHngP2NeR28g1EN1N\n" +
            "Qob9zCG3CPQmu7I3dWp1rDUu2ZickE7rISRfo2N9TXWlkJ7ZjhSmQ2gnYgPQ6YGU\n" +
            "LUNVNqTdfk2S8M+BM94pRqVgLSHHvwnqmMdoe7Ul3h2fk9CtNIw=\n" +
            "-----END RSA PRIVATE KEY-----";

    private static final String PUBLIC_DSA_KEY = "ssh-dss AAAAB3NzaC1kc3MAAACBANmOhJjtmkkhF+Z9TTz1Y1/7pta/ZzNdY0h71T5DsD2WJb2cDGD+11oPxKiejCpDh4kQ5lDBUIHAfIcCoaFFkr85G89H5wTfoBethwmVnmVIzxUwGDh4VKMDF+meNlNh26a0h/0e00lOodIJvUz/2u7U7KTVrSrgtSZkAOLIWxK7AAAAFQDlI+2Ug32bB3xWpKmF5DqW67F82QAAAIAR85ga/Cz2wlvJSPqIxqm3ZS9LY5jvubA0mYH1XwYRZEWfYcI0j5NAfUCdv2RncFdeyo6ZIcREtu1uLU8rTqIcucgcRjMdrgDreN+ImyQKDkwH160if+PbsulG7bCZnl01Pp5YegUuAQknEqtg6cJg3N6is6BlsHv3elNzZITTsAAAAIEAinzZ44EogFDIajB/SqZ2xaJRubePnJuMXxjDh0RypZHQMNYKsf8NdE6ocrKMHw2Etg9CSZyaATpAuBZ3oNipuS+uJCk+i9Oc5oom8umowTUE7aGZtDnIMRBlL/MyOUPwoBNohUhSWDkI+CCu9qUhz160Q3ErYztyyB3CVaFBNSk= xxx@yyy";

    private static final String PRIVATE_DSA_KEY =
            "-----BEGIN DSA PRIVATE KEY-----\n" +
            "MIIBvAIBAAKBgQDZjoSY7ZpJIRfmfU089WNf+6bWv2czXWNIe9U+Q7A9liW9nAxg\n" +
            "/tdaD8SonowqQ4eJEOZQwVCBwHyHAqGhRZK/ORvPR+cE36AXrYcJlZ5lSM8VMBg4\n" +
            "eFSjAxfpnjZTYdumtIf9HtNJTqHSCb1M/9ru1Oyk1a0q4LUmZADiyFsSuwIVAOUj\n" +
            "7ZSDfZsHfFakqYXkOpbrsXzZAoGAEfOYGvws9sJbyUj6iMapt2UvS2OY77mwNJmB\n" +
            "9V8GEWRFn2HCNI+TQH1Anb9kZ3BXXsqOmSHERLbtbi1PK06iHLnIHEYzHa4A63jf\n" +
            "iJskCg5MB9etIn/j27LpRu2wmZ5dNT6eWHoFLgEJJxKrYOnCYNzeorOgZbB793pT\n" +
            "c2SE07ACgYEAinzZ44EogFDIajB/SqZ2xaJRubePnJuMXxjDh0RypZHQMNYKsf8N\n" +
            "dE6ocrKMHw2Etg9CSZyaATpAuBZ3oNipuS+uJCk+i9Oc5oom8umowTUE7aGZtDnI\n" +
            "MRBlL/MyOUPwoBNohUhSWDkI+CCu9qUhz160Q3ErYztyyB3CVaFBNSkCFQDlBLXW\n" +
            "2eADfc6ZtDWcqfGCGbyvJg==\n" +
            "-----END DSA PRIVATE KEY-----";

    private static class GetCurrentUser implements Callable<String, Exception> {
        public String call() throws Exception {
            return User.current().getId();
        }
    }
}
