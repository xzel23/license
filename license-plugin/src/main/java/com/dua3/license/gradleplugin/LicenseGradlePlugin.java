package com.dua3.license.gradleplugin;

import com.dua3.utility.crypt.CertificateUtil;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.lang.LangUtil;
import com.dua3.utility.text.TextUtil;

import org.gradle.api.Project;
import org.gradle.api.DefaultTask;
import org.gradle.api.Plugin;
import org.gradle.api.tasks.TaskAction;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Objects;

/**
 * The {@code LicenseGradlePlugin} class implements a Gradle plugin that provides
 * a custom task to generate a trial signing keystore. The plugin registers the task
 * {@code createTrialSigningKeystore} in the "build setup" group.
 * <p>
 * This plugin simplifies setup steps in a Gradle build process for systems
 * requiring signed trial licenses.
 */
public class LicenseGradlePlugin implements Plugin<Project> {
    @Override
    public void apply(Project project) {
        project.getTasks().register("createTrialSigningKeystore", CreateTrialSigningKeystoreTask.class, task -> {
            task.setGroup("build setup");
            task.setDescription("Generates a short-lived trial signing keystore");
        });
    }

    /**
     * Represents a task for generating a trial signing keystore. This task creates a
     * keystore with a short-lived trial signing certificate. It supports two modes of operation:
     * <p>
     * 1. CI mode, which uses developer keys and certificates from environment variables.
     * 2. Local mode, which uses a developer keystore file.
     * <p>
     * The generated trial keystore is stored as a Java Keystore (JKS) file and includes a
     * key pair, trial certificate, and credentials necessary for signing operations.
     * Additionally, the developer's public certificate is written as a PEM resource.
     * <p>
     * Environment Variables:
     * - DEV_PRIVATE_KEY: Base64-encoded private key for developer (CI mode).
     * - DEV_CERT: Base64-encoded developer certificate in X.509 format (CI mode).
     * - TRIAL_KEYSTORE_PASSWORD: Password for the trial keystore.
     * - TRIAL_KEY_ALIAS: Alias for the trial key entry in the keystore.
     * - TRIAL_KEYSTORE_VALID_DAYS: Validity period (in days) for the trial certificate.
     * <p>
     * Task Behavior:
     * - CI Mode:
     *   - Uses developer private key and certificate from environment variables.
     *   - Fails if required variables are not present or invalid.
     * - Local Mode:
     *   - Uses a developer keystore file to load the private key and certificate.
     *   - Requires project-level configuration properties:
     *     - developer_keystore_path: Path to the keystore file.
     *     - developer_keystore_password: Password for the keystore file.
     *     - developer_keystore_developer_key_alias: Alias for the developer key in the keystore.
     * <p>
     * Outputs:
     * - The developer's certificate is saved in PEM format to `src/main/resources/keys/developer-cert.pem`.
     * - The trial signing keystore is stored as `src/main/resources/keys/trial-signing.jks`.
     * <p>
     * Task Registration:
     * This task can be registered in a Gradle project and invoked to generate the necessary keystore
     * required for development or testing purposes.
     */
    public abstract static class CreateTrialSigningKeystoreTask extends DefaultTask {

        /**
         * Generates a keystore with a trial key and certificate signer. It retrieves and processes
         * security-related information, such as private keys, certificates, and passwords, from
         * environment variables or specified file-based keystores.
         *
         * @throws GeneralSecurityException if there are issues related to security operations, such as
         *                                  generating keys or certificates.
         * @throws IOException if an input/output error occurs during file or keystore operations.
         */
        @TaskAction
        public void generateKeystore() throws GeneralSecurityException, IOException {

            String privateKeyB64 = System.getenv("DEV_PRIVATE_KEY");
            String certB64 = System.getenv("DEV_CERT");
            String trialKeyStorePassword = System.getenv("TRIAL_KEYSTORE_PASSWORD");
            String trialKeyAlias = System.getenv("TRIAL_KEY_ALIAS");

            String trialKeystoreValidDaysStr = System.getenv("TRIAL_KEYSTORE_VALID_DAYS");
            LangUtil.check(trialKeystoreValidDaysStr != null, "missing trial keystore validity in environment variable TRIAL_KEYSTORE_VALID_DAYS");
            int validDays = Integer.parseInt(trialKeystoreValidDaysStr);

            PrivateKey developerPrivateKey;
            X509Certificate developerCertificate;
            if (privateKeyB64 != null) {
                getLogger().lifecycle("🔐 Using developer keys from environment (CI mode)");

                LangUtil.check(!privateKeyB64.isBlank(), "empty private key in environment variable DEV_PRIVATE_KEY");
                LangUtil.check(certB64 != null, "missing certificate in environment variable DEV_CERT");
                LangUtil.check(trialKeyStorePassword != null, "missing trial keystore password in environment variable TRIAL_KEYSTORE_PASSWORD");

                byte[] privateKeyBytes = TextUtil.base64Decode(privateKeyB64);
                byte[] certBytes = TextUtil.base64Decode(certB64);

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                developerPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                developerCertificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
            } else {
                getLogger().lifecycle("🔐 Using developer keystore (local mode)");

                String ksPath = getStringProperty(getProject(), "developerKeystorePath");
                String password = getStringProperty(getProject(), "developerKeystorePassword");
                String alias = getStringProperty(getProject(), "developerKeystoreDeveloperKeyAlias");

                KeyStore developerKeyStore = KeyStoreUtil.loadKeyStoreFromFile(Paths.get(ksPath), password.toCharArray());

                developerPrivateKey = (PrivateKey) developerKeyStore.getKey(alias, password.toCharArray());
                developerCertificate = (X509Certificate) developerKeyStore.getCertificate(alias);
            }

            // Write developer public certificate as a PEM resource for embedding
            Path keyFolderPath = Files.createDirectories(getProject().file("src/main/resources/keys").toPath());
            Path certOut = keyFolderPath.resolve("developer-cert.pem");
            try (Writer writer = Files.newBufferedWriter(certOut, StandardCharsets.UTF_8)) {
                writer.write("-----BEGIN CERTIFICATE-----\n");
                writer.write(TextUtil.base64Encode(developerCertificate.getEncoded()).replaceAll("(.{64})", "$1\n"));
                writer.write("\n-----END CERTIFICATE-----\n");
            }
            getLogger().lifecycle("📄 Developer certificate written to: " + certOut.toAbsolutePath());

            // Generate key pair for trial keystore
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair trialKeyPair = keyGen.generateKeyPair();

            X509Certificate[] trialCertificate = CertificateUtil.createX509Certificate(
                    trialKeyPair,
                    "CN=Trial License Issuer",
                    validDays,
                    developerCertificate,
                    developerPrivateKey
            );

            KeyStore trialKeystore = KeyStoreUtil.createKeyStore(trialKeyStorePassword.toCharArray());
            trialKeystore.setKeyEntry(
                    trialKeyAlias,
                    trialKeyPair.getPrivate(),
                    trialKeyStorePassword.toCharArray(),
                    trialCertificate
            );

            Path trialKeyStorePath = keyFolderPath.resolve("trial-signing.jks");
            try (OutputStream fos = Files.newOutputStream(trialKeyStorePath)) {
                trialKeystore.store(fos, trialKeyStorePassword.toCharArray());
            }

            getLogger().lifecycle("✅ Trial signing keystore created at: " + trialKeyStorePath.toAbsolutePath());
        }

        private static String getStringProperty(Project project, String name) {
            return Objects.requireNonNull(project.findProperty(name), "missing property " + name).toString();
        }
    }
}
