/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wildfly.security.http.oidc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.wildfly.security.realm.token.test.util.JwkTestUtil;
import org.wildfly.security.realm.token.test.util.RsaJwk;

public class JWKKeyLocatorTest {

    private static final String RESOURCE_NAME = "test-client";
    private static final int MIN_TIME_BETWEEN_REQUESTS = 60;
    private static final int PUBLIC_KEY_CACHE_TTL = 60;

    private MockWebServer server;
    private CloseableHttpClient httpClient;

    @Before
    public void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
        httpClient = HttpClients.createDefault();
    }

    @After
    public void tearDown() throws Exception {
        if (httpClient != null) {
            httpClient.close();
        }
        if (server != null) {
            server.shutdown();
        }
    }

    @Test
    public void testPublicKeyLocatorRetriesImmediatelyAfterFailedFetch() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RsaJwk jwk = JwkTestUtil.createRsaJwk(keyPair, "sig-1").setUse("sig");
        JWKPublicKeyLocator locator = new JWKPublicKeyLocator();
        TestOidcClientConfiguration configuration = createConfiguration();

        server.enqueue(new MockResponse().setResponseCode(500));
        server.enqueue(new MockResponse().setBody(JwkTestUtil.jwksToJson(jwk).toString()));

        assertNull(locator.getPublicKey("sig-1", configuration));
        assertRequestReceived();

        assertPublicKeyEquals(keyPair.getPublic(), locator.getPublicKey("sig-1", configuration));
        assertRequestReceived();
        assertNoAdditionalRequest();
    }

    @Test
    public void testPublicKeyLocatorResetFailureDoesNotSuppressNextFetch() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RsaJwk jwk = JwkTestUtil.createRsaJwk(keyPair, "sig-1").setUse("sig");
        JWKPublicKeyLocator locator = new JWKPublicKeyLocator();
        TestOidcClientConfiguration configuration = createConfiguration();

        server.enqueue(new MockResponse().setResponseCode(500));
        server.enqueue(new MockResponse().setBody(JwkTestUtil.jwksToJson(jwk).toString()));

        locator.reset(configuration);
        assertRequestReceived();

        assertPublicKeyEquals(keyPair.getPublic(), locator.getPublicKey("sig-1", configuration));
        assertRequestReceived();
        assertNoAdditionalRequest();
    }

    @Test
    public void testPublicKeyLocatorStillThrottlesAfterSuccessfulFetch() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RsaJwk jwk = JwkTestUtil.createRsaJwk(keyPair, "sig-1").setUse("sig");
        JWKPublicKeyLocator locator = new JWKPublicKeyLocator();
        TestOidcClientConfiguration configuration = createConfiguration();

        server.enqueue(new MockResponse().setBody(JwkTestUtil.jwksToJson(jwk).toString()));

        assertNull(locator.getPublicKey("missing", configuration));
        assertRequestReceived();

        assertNull(locator.getPublicKey("missing", configuration));
        assertNoAdditionalRequest();
    }

    @Test
    public void testEncryptionKeyLocatorRetriesImmediatelyAfterFailedFetch() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RsaJwk jwk = JwkTestUtil.createRsaJwk(keyPair, "enc-1").setUse("enc");
        JWKEncPublicKeyLocator locator = new JWKEncPublicKeyLocator();
        TestOidcClientConfiguration configuration = createConfiguration();

        server.enqueue(new MockResponse().setResponseCode(500));
        server.enqueue(new MockResponse().setBody(JwkTestUtil.jwksToJson(jwk).toString()));

        assertNull(locator.getPublicKey(null, configuration));
        assertRequestReceived();

        assertPublicKeyEquals(keyPair.getPublic(), locator.getPublicKey(null, configuration));
        assertRequestReceived();
        assertNoAdditionalRequest();
    }

    @Test
    public void testEncryptionKeyLocatorResetFailureDoesNotSuppressNextFetch() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RsaJwk jwk = JwkTestUtil.createRsaJwk(keyPair, "enc-1").setUse("enc");
        JWKEncPublicKeyLocator locator = new JWKEncPublicKeyLocator();
        TestOidcClientConfiguration configuration = createConfiguration();

        server.enqueue(new MockResponse().setResponseCode(500));
        server.enqueue(new MockResponse().setBody(JwkTestUtil.jwksToJson(jwk).toString()));

        locator.reset(configuration);
        assertRequestReceived();

        assertPublicKeyEquals(keyPair.getPublic(), locator.getPublicKey(null, configuration));
        assertRequestReceived();
        assertNoAdditionalRequest();
    }

    @Test
    public void testEncryptionKeyLocatorReturnsNullWhenNoEncryptionKeysAreReturned() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RsaJwk jwk = JwkTestUtil.createRsaJwk(keyPair, "sig-1").setUse("sig");
        JWKEncPublicKeyLocator locator = new JWKEncPublicKeyLocator();
        TestOidcClientConfiguration configuration = createConfiguration();

        server.enqueue(new MockResponse().setBody(JwkTestUtil.jwksToJson(jwk).toString()));

        assertNull(locator.getPublicKey(null, configuration));
        assertRequestReceived();
        assertNoAdditionalRequest();
    }

    @Test
    public void testEncryptionKeyLocatorSupportsConcurrentCachedReads() throws Exception {
        KeyPair keyPair = generateKeyPair();
        RsaJwk jwk = JwkTestUtil.createRsaJwk(keyPair, "enc-1").setUse("enc");
        JWKEncPublicKeyLocator locator = new JWKEncPublicKeyLocator();
        TestOidcClientConfiguration configuration = createConfiguration();

        server.enqueue(new MockResponse().setBody(JwkTestUtil.jwksToJson(jwk).toString()));

        assertPublicKeyEquals(keyPair.getPublic(), locator.getPublicKey(null, configuration));
        assertRequestReceived();

        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<PublicKey>> tasks = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                tasks.add(() -> locator.getPublicKey(null, configuration));
            }

            List<Future<PublicKey>> results = executor.invokeAll(tasks);
            for (Future<PublicKey> result : results) {
                assertPublicKeyEquals(keyPair.getPublic(), getFuture(result));
            }
        } finally {
            executor.shutdownNow();
        }

        assertNoAdditionalRequest();
    }

    private TestOidcClientConfiguration createConfiguration() {
        return new TestOidcClientConfiguration(
                httpClient,
                server.url("/jwks").toString(),
                RESOURCE_NAME,
                MIN_TIME_BETWEEN_REQUESTS,
                PUBLIC_KEY_CACHE_TTL);
    }

    private KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        return keyPairGenerator.generateKeyPair();
    }

    private void assertPublicKeyEquals(PublicKey expected, PublicKey actual) {
        assertNotNull(actual);
        assertArrayEquals(expected.getEncoded(), actual.getEncoded());
    }

    private void assertRequestReceived() throws InterruptedException {
        assertNotNull(server.takeRequest(1, TimeUnit.SECONDS));
    }

    private void assertNoAdditionalRequest() throws InterruptedException {
        assertNull(server.takeRequest(200, TimeUnit.MILLISECONDS));
    }

    private PublicKey getFuture(Future<PublicKey> future) throws InterruptedException, ExecutionException, TimeoutException {
        return future.get(1, TimeUnit.SECONDS);
    }

    private static final class TestOidcClientConfiguration extends OidcClientConfiguration {

        private final HttpClient client;
        private final String jwksUrl;
        private final String resourceName;
        private final int minTimeBetweenJwksRequests;
        private final int publicKeyCacheTtl;

        private TestOidcClientConfiguration(HttpClient client, String jwksUrl, String resourceName,
                int minTimeBetweenJwksRequests, int publicKeyCacheTtl) {
            this.client = client;
            this.jwksUrl = jwksUrl;
            this.resourceName = resourceName;
            this.minTimeBetweenJwksRequests = minTimeBetweenJwksRequests;
            this.publicKeyCacheTtl = publicKeyCacheTtl;
        }

        @Override
        public HttpClient getClient() {
            return client;
        }

        @Override
        public String getJwksUrl() {
            return jwksUrl;
        }

        @Override
        public String getResourceName() {
            return resourceName;
        }

        @Override
        public int getMinTimeBetweenJwksRequests() {
            return minTimeBetweenJwksRequests;
        }

        @Override
        public int getPublicKeyCacheTtl() {
            return publicKeyCacheTtl;
        }
    }
}
