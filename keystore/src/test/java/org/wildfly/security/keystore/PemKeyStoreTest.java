/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2026 Red Hat, Inc., and individual contributors
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
package org.wildfly.security.keystore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;
import org.wildfly.common.bytes.ByteStringBuilder;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.pem.Pem;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;

/**
 * Tests for the PEM {@link KeyStore} implementation.
 */
public class PemKeyStoreTest {

    private static final char[] EMPTY_PASSWORD = new char[0];
    private static final char[] PASSWORD = "secret".toCharArray();
    private static final String DEFAULT_ALIAS = "tls";

    private KeyPairGenerator keyPairGenerator;
    private Path workingDir;

    @Before
    public void beforeTest() throws Exception {
        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        workingDir = Paths.get("target", "pem-keystore-test");
        Files.createDirectories(workingDir);
    }

    @Test
    public void testProviderReturnsPemKeyStore() throws Exception {
        KeyStore keyStore = createPemKeyStore();

        Assert.assertEquals("PEM", keyStore.getType());
        Assert.assertEquals(WildFlyElytronKeyStoreProvider.getInstance(), keyStore.getProvider());
    }

    @Test
    public void testCombinedPemUsesCertificateSubjectAlias() throws Exception {
        TestMaterial material = createMaterial("Combined");
        KeyStore keyStore = createPemKeyStore();

        keyStore.load(new ByteArrayInputStream(createCombinedPem(material)), PASSWORD);

        assertKeyEntry(keyStore, material.subjectCertificate.getSubjectX500Principal().getName(), material, PASSWORD);
    }

    @Test
    public void testSeparateCertificateAndPrivateKeyFilesUseDefaultAlias() throws Exception {
        TestMaterial material = createMaterial("Separate");
        Path certificatePath = write("tls.crt", createCertificatePem(material));
        Path privateKeyPath = write("tls.key", createPrivateKeyPem(material));
        KeyStore keyStore = createPemKeyStore();

        keyStore.load(new PemKeyStoreLoadParameter(certificatePath, privateKeyPath, null,
                new KeyStore.PasswordProtection(PASSWORD)));

        assertKeyEntry(keyStore, DEFAULT_ALIAS, material, PASSWORD);
    }

    @Test
    public void testSeparateFilesUseExplicitAliasAndNullPassword() throws Exception {
        TestMaterial material = createMaterial("ExplicitAlias");
        Path certificatePath = write("explicit-alias.crt", createCertificatePem(material));
        Path privateKeyPath = write("explicit-alias.key", createPrivateKeyPem(material));
        KeyStore keyStore = createPemKeyStore();

        keyStore.load(new PemKeyStoreLoadParameter(certificatePath, privateKeyPath, "server",
                new KeyStore.PasswordProtection(null)));

        assertKeyEntry(keyStore, "server", material, EMPTY_PASSWORD);
    }

    @Test
    public void testNullStreamCreatesEmptyKeyStore() throws Exception {
        KeyStore keyStore = createPemKeyStore();

        keyStore.load(null, PASSWORD);

        Assert.assertEquals(0, keyStore.size());
        Assert.assertFalse(keyStore.aliases().hasMoreElements());
    }

    @Test
    public void testMismatchedCertificateAndPrivateKeyFilesFail() throws Exception {
        TestMaterial certificateMaterial = createMaterial("Certificate");
        TestMaterial keyMaterial = createMaterial("PrivateKey");
        Path certificatePath = write("mismatched-tls.crt", createCertificatePem(certificateMaterial));
        Path privateKeyPath = write("mismatched-tls.key", createPrivateKeyPem(keyMaterial));
        KeyStore keyStore = createPemKeyStore();

        CertificateException exception = Assert.assertThrows(CertificateException.class,
                () -> keyStore.load(new PemKeyStoreLoadParameter(certificatePath, privateKeyPath)));

        Assert.assertEquals("Private key does not match certificate public key", exception.getMessage());
    }

    @Test
    public void testMissingCertificateFails() throws Exception {
        TestMaterial material = createMaterial("MissingCertificate");
        Path certificatePath = write("missing-certificate.crt", createPrivateKeyPem(material));
        Path privateKeyPath = write("missing-certificate.key", createPrivateKeyPem(material));
        KeyStore keyStore = createPemKeyStore();

        CertificateException exception = Assert.assertThrows(CertificateException.class,
                () -> keyStore.load(new PemKeyStoreLoadParameter(certificatePath, privateKeyPath)));

        Assert.assertEquals("PEM certificate file does not contain an X.509 certificate", exception.getMessage());
    }

    @Test
    public void testMissingPrivateKeyFails() throws Exception {
        TestMaterial material = createMaterial("MissingPrivateKey");
        Path certificatePath = write("missing-key.crt", createCertificatePem(material));
        Path privateKeyPath = write("missing-key.key", createCertificatePem(material));
        KeyStore keyStore = createPemKeyStore();

        IOException exception = Assert.assertThrows(IOException.class,
                () -> keyStore.load(new PemKeyStoreLoadParameter(certificatePath, privateKeyPath)));

        Assert.assertEquals("PEM private key file does not contain a private key", exception.getMessage());
    }

    @Test
    public void testCombinedPrivateKeyWithoutCertificateFails() throws Exception {
        TestMaterial material = createMaterial("NoCertificate");
        KeyStore keyStore = createPemKeyStore();

        CertificateException exception = Assert.assertThrows(CertificateException.class,
                () -> keyStore.load(new ByteArrayInputStream(createPrivateKeyPem(material)), PASSWORD));

        Assert.assertEquals("PEM content does not contain an X.509 certificate", exception.getMessage());
    }

    @Test
    public void testMultiplePrivateKeysFail() throws Exception {
        TestMaterial first = createMaterial("FirstKey");
        TestMaterial second = createMaterial("SecondKey");
        ByteStringBuilder target = new ByteStringBuilder();
        Pem.generatePemContent(target, "PRIVATE KEY", ByteIterator.ofBytes(first.keyPair.getPrivate().getEncoded()));
        Pem.generatePemContent(target, "PRIVATE KEY", ByteIterator.ofBytes(second.keyPair.getPrivate().getEncoded()));
        Pem.generatePemX509Certificate(target, first.subjectCertificate);
        KeyStore keyStore = createPemKeyStore();

        IOException exception = Assert.assertThrows(IOException.class,
                () -> keyStore.load(new ByteArrayInputStream(target.toArray()), PASSWORD));

        Assert.assertEquals("PEM content contains more than one private key", exception.getMessage());
    }

    @Test
    public void testMalformedPemFails() throws Exception {
        byte[] malformedPem = "-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n"
                .getBytes(StandardCharsets.US_ASCII);
        KeyStore keyStore = createPemKeyStore();

        IOException exception = Assert.assertThrows(IOException.class,
                () -> keyStore.load(new ByteArrayInputStream(malformedPem), PASSWORD));

        Assert.assertEquals("Unable to parse PEM content", exception.getMessage());
        Assert.assertNotNull(exception.getCause());
    }

    @Test
    public void testUnsupportedProtectionParameterFails() throws Exception {
        TestMaterial material = createMaterial("UnsupportedProtection");
        Path certificatePath = write("unsupported-protection.crt", createCertificatePem(material));
        Path privateKeyPath = write("unsupported-protection.key", createPrivateKeyPem(material));
        KeyStore.ProtectionParameter unsupported = new KeyStore.ProtectionParameter() {
        };
        KeyStore keyStore = createPemKeyStore();

        IOException exception = Assert.assertThrows(IOException.class,
                () -> keyStore.load(new PemKeyStoreLoadParameter(certificatePath, privateKeyPath, null, unsupported)));

        Assert.assertEquals("PEM KeyStore only supports KeyStore.PasswordProtection", exception.getMessage());
    }

    @Test
    public void testLoadParameterRejectsNullPaths() {
        Path path = Paths.get("tls.pem");

        Assert.assertThrows(IllegalArgumentException.class, () -> new PemKeyStoreLoadParameter(null, path));
        Assert.assertThrows(IllegalArgumentException.class, () -> new PemKeyStoreLoadParameter(path, null));
    }

    @Test
    public void testReadBeforeLoadFails() throws Exception {
        KeyStore keyStore = createPemKeyStore();

        KeyStoreException exception = Assert.assertThrows(KeyStoreException.class, keyStore::size);

        Assert.assertTrue(exception.getMessage().toLowerCase().contains("uninitialized"));
    }

    @Test
    public void testMutationOperationsAreReadOnly() throws Exception {
        TestMaterial material = createMaterial("ReadOnly");
        KeyStore keyStore = createPemKeyStore();
        keyStore.load(new ByteArrayInputStream(createCombinedPem(material)), PASSWORD);
        Certificate[] chain = new Certificate[] { material.subjectCertificate, material.ca.getSelfSignedCertificate() };

        assertReadOnly(() -> keyStore.setKeyEntry("new", material.keyPair.getPrivate(), PASSWORD, chain));
        assertReadOnly(() -> keyStore.setKeyEntry("new", material.keyPair.getPrivate().getEncoded(), chain));
        assertReadOnly(() -> keyStore.setCertificateEntry("new", material.subjectCertificate));
        assertReadOnly(() -> keyStore.setEntry("new", new KeyStore.TrustedCertificateEntry(material.subjectCertificate), null));
        assertReadOnly(() -> keyStore.deleteEntry(material.subjectCertificate.getSubjectX500Principal().getName()));
    }

    @Test
    public void testStoreOperationsAreUnsupported() throws Exception {
        TestMaterial material = createMaterial("StoreUnsupported");
        KeyStore keyStore = createPemKeyStore();
        keyStore.load(new ByteArrayInputStream(createCombinedPem(material)), PASSWORD);

        assertStoreUnsupported(() -> keyStore.store(new ByteArrayOutputStream(), PASSWORD));
        assertStoreUnsupported(() -> keyStore.store((KeyStore.LoadStoreParameter) null));
    }

    private KeyStore createPemKeyStore() throws KeyStoreException {
        return KeyStore.getInstance("PEM", WildFlyElytronKeyStoreProvider.getInstance());
    }

    private void assertKeyEntry(KeyStore keyStore, String alias, TestMaterial material, char[] password) throws Exception {
        List<String> aliases = Collections.list(keyStore.aliases());

        Assert.assertEquals(1, keyStore.size());
        Assert.assertTrue(keyStore.containsAlias(alias));
        Assert.assertTrue(keyStore.isKeyEntry(alias));
        Assert.assertFalse(keyStore.isCertificateEntry(alias));
        Assert.assertEquals(1, aliases.size());
        Assert.assertTrue(alias.equalsIgnoreCase(aliases.get(0)));
        Assert.assertArrayEquals(material.keyPair.getPrivate().getEncoded(), keyStore.getKey(alias, password).getEncoded());
        Assert.assertEquals(material.subjectCertificate, keyStore.getCertificate(alias));
        Assert.assertTrue(alias.equalsIgnoreCase(keyStore.getCertificateAlias(material.subjectCertificate)));
        Assert.assertNotNull(keyStore.getCreationDate(alias));
        Assert.assertTrue(keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class));
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias,
                new KeyStore.PasswordProtection(password));
        Assert.assertArrayEquals(material.keyPair.getPrivate().getEncoded(), entry.getPrivateKey().getEncoded());
        Certificate[] chain = keyStore.getCertificateChain(alias);
        Assert.assertEquals(2, chain.length);
        Assert.assertEquals(material.subjectCertificate, chain[0]);
        Assert.assertEquals(material.ca.getSelfSignedCertificate(), chain[1]);
    }

    private void assertReadOnly(ThrowingRunnable operation) {
        KeyStoreException exception = Assert.assertThrows(KeyStoreException.class, operation);
        Assert.assertEquals("PEM KeyStore is read-only", exception.getMessage());
    }

    private void assertStoreUnsupported(ThrowingRunnable operation) {
        UnsupportedOperationException exception = Assert.assertThrows(UnsupportedOperationException.class, operation);
        Assert.assertEquals("PEM KeyStore does not support storing", exception.getMessage());
    }

    private TestMaterial createMaterial(String commonName) throws Exception {
        SelfSignedX509CertificateAndSigningKey ca = SelfSignedX509CertificateAndSigningKey.builder()
                .setDn(new X500Principal("O=Root Certificate Authority, EMAILADDRESS=elytron@wildfly.org, C=UK, ST=Elytron, CN=Elytron CA " + commonName))
                .setKeyAlgorithmName("RSA")
                .setSignatureAlgorithmName("SHA256withRSA")
                .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
                .build();
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509Certificate subjectCertificate = new X509CertificateBuilder()
                .setIssuerDn(ca.getSelfSignedCertificate().getIssuerX500Principal())
                .setSubjectDn(new X500Principal("O=Elytron, OU=Elytron, C=UK, ST=Elytron, CN=" + commonName))
                .setSignatureAlgorithmName("SHA256withRSA")
                .setSigningKey(ca.getSigningKey())
                .setPublicKey(keyPair.getPublic())
                .build();
        return new TestMaterial(ca, keyPair, subjectCertificate);
    }

    private byte[] createCombinedPem(TestMaterial material) {
        ByteStringBuilder target = new ByteStringBuilder();
        Pem.generatePemContent(target, "PRIVATE KEY", ByteIterator.ofBytes(material.keyPair.getPrivate().getEncoded()));
        Pem.generatePemX509Certificate(target, material.subjectCertificate);
        Pem.generatePemX509Certificate(target, material.ca.getSelfSignedCertificate());
        return target.toArray();
    }

    private byte[] createCertificatePem(TestMaterial material) {
        ByteStringBuilder target = new ByteStringBuilder();
        Pem.generatePemX509Certificate(target, material.subjectCertificate);
        Pem.generatePemX509Certificate(target, material.ca.getSelfSignedCertificate());
        return target.toArray();
    }

    private byte[] createPrivateKeyPem(TestMaterial material) {
        ByteStringBuilder target = new ByteStringBuilder();
        Pem.generatePemContent(target, "PRIVATE KEY", ByteIterator.ofBytes(material.keyPair.getPrivate().getEncoded()));
        return target.toArray();
    }

    private Path write(String fileName, byte[] contents) throws IOException {
        Path path = workingDir.resolve(fileName);
        Files.write(path, contents);
        return path;
    }

    private static final class TestMaterial {

        private final SelfSignedX509CertificateAndSigningKey ca;
        private final KeyPair keyPair;
        private final X509Certificate subjectCertificate;

        private TestMaterial(SelfSignedX509CertificateAndSigningKey ca, KeyPair keyPair,
                X509Certificate subjectCertificate) {
            this.ca = ca;
            this.keyPair = keyPair;
            this.subjectCertificate = subjectCertificate;
        }
    }
}
