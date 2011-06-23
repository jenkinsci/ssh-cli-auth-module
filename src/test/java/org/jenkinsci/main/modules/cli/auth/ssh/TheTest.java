package org.jenkinsci.main.modules.cli.auth.ssh;

import hudson.cli.CLI;
import hudson.cli.CLICommand;
import hudson.model.User;
import org.jvnet.hudson.test.HudsonTestCase;
import org.jvnet.hudson.test.TestExtension;

import java.util.Collections;

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

    public void test1() throws Exception {
        User foo = User.get("foo");
        foo.addProperty(new UserPropertyImpl(PUBLIC_KEY));
        configRoundtrip(foo);
        assertEquals(PUBLIC_KEY, foo.getProperty(UserPropertyImpl.class).authorizedKeys);

        CLI cli = new CLI(getURL());
        cli.authenticate(Collections.singleton(CLI.loadKey(PRIVATE_KEY)));
        assertEquals(0,cli.execute("test"));
        cli.close();
    }

    private static final String PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAr+ZaQ/SI8xIr5BtMCh7gizoH/cVzEi8tCxwvHOu5eELzxl1FBwUH5/pRzMI31w1+WlYXBCYQSvcWgpLlAZn7VaJYCxUE9K9gMxLPmk81fUec8sFr5hSj6cPL3hWdk4CgdJ0M2Q/GNJExvbDsiFMFb/p9jnrKhHQ47mhT4HpMLTE4fG5+AB3liJZhaUo9lbHfmhpmpps9o1tE1z7YcIO4ckvCklxF+04mVRjKur3lcezh2i4TXjMGmkDgU7pTrwf9OM9rDo5dSpsAK/dGWlBT01jhv69wOfUitcYENAK07Tgyoti3pEYD3b2ugxQ0fe0LqoxFa//O540PjMhxEbmuQQ== xxx@yyy";

    private static final String PRIVATE_KEY =
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
}
