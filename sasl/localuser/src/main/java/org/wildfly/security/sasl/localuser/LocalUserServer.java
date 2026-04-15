/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.sasl.localuser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.wildfly.common.Assert;
import org.wildfly.common.array.Arrays2;
import org.wildfly.common.iteration.CodePointIterator;
import org.wildfly.security.manager.action.ReadPropertyAction;
import org.wildfly.security.sasl.util.AbstractSaslServer;

import static org.wildfly.security.mechanism._private.ElytronMessages.saslLocal;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
final class LocalUserServer extends AbstractSaslServer implements SaslServer {

    // Should SecureRandom be used? Default to true
    public static final String LOCAL_USER_USE_SECURE_RANDOM = "wildfly.sasl.local-user.use-secure-random";
    public static final String LEGACY_LOCAL_USER_USE_SECURE_RANDOM = "jboss.sasl.local-user.use-secure-random";
    public static final String LOCAL_USER_CHALLENGE_PATH = "wildfly.sasl.local-user.challenge-path";
    public static final String LEGACY_LOCAL_USER_CHALLENGE_PATH = "jboss.sasl.local-user.challenge-path";
    public static final String LOCAL_USER_CHALLENGE_FILE_PERMISSIONS = "wildfly.sasl.local-user.challenge-file-permissions";
    public static final String LEGACY_LOCAL_USER_CHALLENGE_FILE_PERMISSIONS = "jboss.sasl.local-user.challenge-file-permissions";
    public static final String DEFAULT_USER = "wildfly.sasl.local-user.default-user";
    public static final String LEGACY_DEFAULT_USER = "jboss.sasl.local-user.default-user";

    private static final byte UTF8NUL = 0x00;

    private static final int INITIAL_CHALLENGE_STATE = 1;
    private static final int PROCESS_RESPONSE_STATE = 2;

    private volatile String authorizationId;
    private volatile File challengeFile;
    private volatile byte[] challengeBytes;
    private final File basePath;
    private final FileAttribute<?>[] challengeFileAttributes;
    private final String defaultUser;
    private final boolean useSecureRandom;

    LocalUserServer(final String protocol, final String serverName, Map<String, ?> props, final CallbackHandler callbackHandler) {
        super(LocalUserSaslFactory.JBOSS_LOCAL_USER, protocol, serverName, callbackHandler, saslLocal);
        if (props == null) props = Collections.emptyMap();
        String value;
        if (props.containsKey(LOCAL_USER_CHALLENGE_PATH)) {
            basePath = new File(props.get(LOCAL_USER_CHALLENGE_PATH).toString()).getAbsoluteFile();
        } else if (props.containsKey(LEGACY_LOCAL_USER_CHALLENGE_PATH)) {
            basePath = new File(props.get(LEGACY_LOCAL_USER_CHALLENGE_PATH).toString()).getAbsoluteFile();
        } else if ((value = getProperty(LOCAL_USER_CHALLENGE_PATH)) != null) {
            basePath = new File(value).getAbsoluteFile();
        } else if ((value = getProperty(LEGACY_LOCAL_USER_CHALLENGE_PATH)) != null) {
            basePath = new File(value).getAbsoluteFile();
        } else {
            basePath = new File(getProperty("java.io.tmpdir"));
        }
        challengeFileAttributes = getChallengeFileAttributes(props, basePath.toPath());

        Object useSecureRandomObj = null;
        if (props.containsKey(LOCAL_USER_USE_SECURE_RANDOM)) {
            useSecureRandomObj = props.get(LOCAL_USER_USE_SECURE_RANDOM);
        } else if (props.containsKey(LEGACY_LOCAL_USER_USE_SECURE_RANDOM)) {
            useSecureRandomObj = props.get(LEGACY_LOCAL_USER_USE_SECURE_RANDOM);
        } else {
            useSecureRandomObj = getProperty(LOCAL_USER_USE_SECURE_RANDOM);
            if (useSecureRandomObj == null) {
                useSecureRandomObj = getProperty(LEGACY_LOCAL_USER_USE_SECURE_RANDOM);
            }
        }

        if (useSecureRandomObj != null) {
            if (useSecureRandomObj instanceof Boolean) {
                useSecureRandom = ((Boolean) useSecureRandomObj).booleanValue();
            } else if (useSecureRandomObj instanceof String) {
                useSecureRandom = Boolean.parseBoolean((String) useSecureRandomObj);
            } else {
                useSecureRandom = true;
            }
        } else {
            useSecureRandom = true;
        }

        if (props.containsKey(DEFAULT_USER)) {
            defaultUser = (String) props.get(DEFAULT_USER);
        } else if (props.containsKey(LEGACY_DEFAULT_USER)) {
            defaultUser = (String) props.get(LEGACY_DEFAULT_USER);
        } else {
            defaultUser = null;
        }
    }

    private static String getProperty(final String name) {
        return doPrivileged(new ReadPropertyAction(name, null));
    }

    private static FileAttribute<?>[] getChallengeFileAttributes(final Map<String, ?> props, final Path basePath) {
        Object challengeFilePermissions = null;
        if (props.containsKey(LOCAL_USER_CHALLENGE_FILE_PERMISSIONS)) {
            challengeFilePermissions = props.get(LOCAL_USER_CHALLENGE_FILE_PERMISSIONS);
        } else if (props.containsKey(LEGACY_LOCAL_USER_CHALLENGE_FILE_PERMISSIONS)) {
            challengeFilePermissions = props.get(LEGACY_LOCAL_USER_CHALLENGE_FILE_PERMISSIONS);
        } else {
            challengeFilePermissions = getProperty(LOCAL_USER_CHALLENGE_FILE_PERMISSIONS);
            if (challengeFilePermissions == null) {
                challengeFilePermissions = getProperty(LEGACY_LOCAL_USER_CHALLENGE_FILE_PERMISSIONS);
            }
        }

        if (challengeFilePermissions == null) {
            return new FileAttribute<?>[0];
        }
        if (challengeFilePermissions instanceof String) {
            assertPosixViewSupported(basePath);
            return new FileAttribute<?>[] { toPosixPermissions((String) challengeFilePermissions) };
        }
        if (challengeFilePermissions instanceof Set) {
            assertPosixViewSupported(basePath);
            @SuppressWarnings("unchecked")
            final Set<PosixFilePermission> permissions = (Set<PosixFilePermission>) challengeFilePermissions;
            return new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(permissions) };
        }
        if (challengeFilePermissions instanceof FileAttribute) {
            return new FileAttribute<?>[] { (FileAttribute<?>) challengeFilePermissions };
        }
        if (challengeFilePermissions instanceof FileAttribute[]) {
            return ((FileAttribute<?>[]) challengeFilePermissions).clone();
        }
        throw new IllegalArgumentException("Invalid challenge file permissions value: " + challengeFilePermissions);
    }

    private static void assertPosixViewSupported(final Path basePath) {
        if (!basePath.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            throw new IllegalArgumentException("POSIX challenge file permissions require a filesystem with POSIX attribute support: " + basePath);
        }
    }

    private static FileAttribute<Set<PosixFilePermission>> toPosixPermissions(final String challengeFilePermissions) {
        try {
            return PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(challengeFilePermissions));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid challenge file permissions value: " + challengeFilePermissions, e);
        }
    }

    private static <T> T doPrivileged(final PrivilegedAction<T> action) {
        return System.getSecurityManager() != null ? AccessController.doPrivileged(action) : action.run();
    }

    private Random getRandom() {
        if (useSecureRandom) {
            return new SecureRandom();
        } else {
            return new Random();
        }
    }

    @Override
    public void init() {
        setNegotiationState(INITIAL_CHALLENGE_STATE);
    }

    @Override
    public String getAuthorizationID() {
        assertComplete();

        return authorizationId;
    }

    private void deleteChallenge() {
        if (challengeFile != null) {
            try {
                Files.deleteIfExists(challengeFile.toPath());
            } catch (IOException ignored) {
            }
            challengeFile = null;
        }
    }

    @Override
    public void dispose() throws SaslException {
        super.dispose();
        deleteChallenge();
    }

    @Override
    protected byte[] evaluateMessage(int state, final byte[] message) throws SaslException {
        switch (state) {
            case INITIAL_CHALLENGE_STATE:
                if (message.length == 0) {
                    // trigger initial response
                    return NO_BYTES;
                }

                // initial message
                if (message.length == 1 && message[0] == UTF8NUL) {
                    authorizationId = null;
                } else {
                    authorizationId = new String(message, StandardCharsets.UTF_8);
                }
                final Random random = getRandom();
                final byte[] bytes = new byte[8];
                random.nextBytes(bytes);
                Path challengePath = null;
                try {
                    challengePath = Files.createTempFile(basePath.toPath(), "local", ".challenge", challengeFileAttributes);
                    Files.write(challengePath, bytes);
                    challengeFile = challengePath.toFile();
                } catch (IOException | UnsupportedOperationException e) {
                    if (challengePath != null) try {
                        Files.deleteIfExists(challengePath);
                    } catch (IOException ignored) {
                    }
                    throw saslLocal.mechFailedToCreateChallengeFile(e).toSaslException();
                }
                challengeBytes = bytes;
                final String path = challengeFile.getAbsolutePath();
                final byte[] response = CodePointIterator.ofString(path).asUtf8(true).drain();
                setNegotiationState(PROCESS_RESPONSE_STATE);
                return response;
            case PROCESS_RESPONSE_STATE:
                deleteChallenge();
                final int length = message.length;
                if (length < 8) {
                    throw saslLocal.mechInvalidClientMessage().toSaslException();
                }
                if (!Arrays.equals(challengeBytes, Arrays.copyOf(message, 8))) {
                    throw saslLocal.mechAuthenticationRejectedInvalidProof().toSaslException();
                }
                String authenticationRealm;
                String authenticationId;
                final int firstMarker = Arrays2.indexOf(message, 0, 8);
                if (firstMarker > -1) {
                    authenticationId = new String(message, 8, firstMarker - 8, StandardCharsets.UTF_8);
                    final int secondMarker = Arrays2.indexOf(message, 0, firstMarker + 1);
                    if (secondMarker > -1) {
                        authenticationRealm = new String(message, firstMarker + 1, secondMarker - firstMarker - 1, StandardCharsets.UTF_8);
                    } else {
                        authenticationRealm = null;
                    }
                } else {
                    authenticationId = null;
                    authenticationRealm = null;
                }
                if (authenticationId == null || authenticationId.isEmpty()) {
                    authenticationId = defaultUser;
                }
                if (authenticationId == null || authenticationId.isEmpty()) {
                    throw saslLocal.mechAuthenticationNameIsEmpty().toSaslException();
                }
                if (authorizationId == null || authorizationId.isEmpty()) {
                    // If no authorization ID is specified default to authentication ID
                    authorizationId = authenticationId;
                }
                final NameCallback nameCallback = new NameCallback("User name", authenticationId);
                final AuthorizeCallback authorizeCallback = new AuthorizeCallback(authenticationId, authorizationId);
                if (authenticationRealm == null) {
                    handleCallbacks(nameCallback, authorizeCallback);
                } else {
                    final RealmCallback realmCallback = new RealmCallback("User realm", authenticationRealm);
                    handleCallbacks(realmCallback, nameCallback, authorizeCallback);
                }
                if (!authorizeCallback.isAuthorized()) {
                    throw saslLocal.mechAuthorizationFailed(authenticationId, authorizationId).toSaslException();
                }
                negotiationComplete();
                return null;
        }
        throw Assert.impossibleSwitchCase(state);
    }
}
