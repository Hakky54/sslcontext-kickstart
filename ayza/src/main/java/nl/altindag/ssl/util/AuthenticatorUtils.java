/*
 * Copyright 2019 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.util;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

/**
 * @author Hakan Altindag
 */
public final class AuthenticatorUtils {

    private AuthenticatorUtils() {

    }

    public static Authenticator create(String userName, char[] password) {
        return create(new PasswordAuthentication(userName, password));
    }

    public static Authenticator create(PasswordAuthentication passwordAuthentication) {
        return new FelixAuthenticator(passwordAuthentication);
    }

    private static class FelixAuthenticator extends Authenticator {

        private final PasswordAuthentication passwordAuthentication;

        private FelixAuthenticator(PasswordAuthentication passwordAuthentication) {
            this.passwordAuthentication = passwordAuthentication;
        }

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            return passwordAuthentication;
        }
    }

}
