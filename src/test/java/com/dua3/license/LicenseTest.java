package com.dua3.license;

import com.dua3.utility.crypt.CertificateUtil;
import com.dua3.utility.lang.Version;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.dua3.license.License.*;
import static org.junit.jupiter.api.Assertions.*;

class LicenseTest {

    enum TestFields {
        LICENSE_ID,
        LICENSEE,
        ISSUE_DATE,
        EXPIRY_DATE,
        MIN_VERSION,
        MAX_VERSION,
        FEATURE
    }

    private record SigningContext(KeyPair keyPair, X509Certificate[] chain, Certificate[] trusted) {}

    private static SigningContext createSigningContext() throws Exception {
        KeyPair kp = com.dua3.utility.crypt.KeyUtil.generateRSAKeyPair();
        X509Certificate[] chain = CertificateUtil.createSelfSignedX509Certificate(kp, "CN=Test", 365, true);
        Certificate[] trusted = new Certificate[]{chain[chain.length - 1]};
        return new SigningContext(kp, chain, trusted);
    }

    private static Map<String, Object> baseLicenseData() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put(LICENSE_ID_LICENSE_FIELD, "LIC-123");
        data.put(LICENSEE_LICENSE_FIELD, "Acme Corp");
        data.put(ISSUE_DATE_LICENSE_FIELD, LocalDate.now());
        data.put(EXPIRY_DATE_LICENSE_FIELD, LocalDate.now().plusDays(30));
        data.put(MIN_VERSION_LICENSE_FIELD, Version.valueOf("1.0.0"));
        data.put(MAX_VERSION_LICENSE_FIELD, Version.valueOf("2.0.0"));
        data.put("FEATURE", "pro");
        return data;
    }

    private static java.util.function.Function<byte[], byte[]> signer(SigningContext ctx) {
        return bytes -> {
            try {
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(ctx.keyPair.getPrivate());
                sig.update(bytes);
                return sig.sign();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    @Test
    void testCreateLicense_enumOverload_andValidate_andRoundtrip() throws Exception {
        SigningContext sc = createSigningContext();
        Map<String, Object> data = baseLicenseData();

        License lic = License.createLicense(TestFields.class, data, signer(sc), sc.chain, sc.trusted);

        assertNotNull(lic);
        assertEquals("LIC-123", lic.getLicenseId());
        assertEquals("Acme Corp", lic.getLicenseData().licensee());
        assertArrayEquals(sc.chain, lic.getCertChain());
        assertTrue(lic.getSignatureBytes().length > 0);

        StringBuilder out = new StringBuilder();
        boolean ok = lic.validate(sc.trusted, Version.valueOf("1.5.0"), out);
        assertTrue(ok, () -> "Expected valid license, got: \n" + out);
        assertTrue(out.toString().contains("✓"));

        // save/load roundtrip
        Path tmp = Files.createTempFile("license", ".json");
        lic.save(tmp);
        License loaded = License.load(tmp, TestFields.class, sc.trusted);
        assertEquals(lic.getLicenseId(), loaded.getLicenseId());
        assertEquals(lic.getValidUntil(), loaded.getValidUntil());
        Files.deleteIfExists(tmp);
    }

    @Test
    void testCreateLicense_dynamicEnumOverload() throws Exception {
        SigningContext sc = createSigningContext();
        Map<String, Object> data = baseLicenseData();
        DynamicEnum dyn = DynamicEnum.ofNames("LICENSE_ID","LICENSEE","ISSUE_DATE","EXPIRY_DATE","MIN_VERSION","MAX_VERSION","FEATURE");

        License lic = License.createLicense(dyn, data, signer(sc), sc.chain, sc.trusted);
        assertEquals("LIC-123", lic.getLicenseId());
        assertEquals(LocalDate.now().plusDays(30), lic.getValidUntil());
    }

    @Test
    void testSaveLoadStreams_and_getters() throws Exception {
        SigningContext sc = createSigningContext();
        Map<String, Object> data = baseLicenseData();
        License lic = License.createLicense(TestFields.class, data, signer(sc), sc.chain, sc.trusted);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        lic.save(bos);

        Map<String,Object> map = new ObjectMapper().readValue(bos.toByteArray(), new TypeReference<>(){});
        StringBuilder out = new StringBuilder();
        assertTrue(License.validate(map, sc.trusted, Version.valueOf("1.1.0"), out));

        // Load via InputStream
        License lic2 = License.load(new java.io.ByteArrayInputStream(bos.toByteArray()), TestFields.class, sc.trusted);
        assertEquals(lic.getLicenseId(), lic2.getLicenseId());
        assertEquals(lic.getLicenseData().validUntil(), lic2.getLicenseData().validUntil());
    }

    @Test
    void testValidation_missingFields_and_malformedSignature() throws Exception {
        SigningContext sc = createSigningContext();
        Map<String, Object> bad = new LinkedHashMap<>();
        bad.put(LICENSE_ID_LICENSE_FIELD, "X");
        // missing other required fields
        bad.put(SIGNATURE_LICENSE_FIELD, "not-base64:also-bad");
        StringBuilder out = new StringBuilder();
        boolean ok = License.validate(bad, sc.trusted, Version.valueOf("1.0.0"), out);
        assertFalse(ok);
        assertTrue(out.toString().contains("Required field"));
        assertTrue(out.toString().contains("Invalid signature format"));
    }

    @Test
    void testValidation_tamperedData_signatureFails() throws Exception {
        SigningContext sc = createSigningContext();
        Map<String, Object> data = baseLicenseData();
        License lic = License.createLicense(TestFields.class, data, signer(sc), sc.chain, sc.trusted);

        // serialize and tamper
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        lic.save(bos);
        Map<String,Object> map = new ObjectMapper().readValue(bos.toByteArray(), new TypeReference<>(){});
        map.put(LICENSEE_LICENSE_FIELD, "Mallory"); // tamper

        StringBuilder out = new StringBuilder();
        boolean ok = License.validate(map, sc.trusted, Version.valueOf("1.5.0"), out);
        assertFalse(ok, () -> out.toString());
        assertTrue(out.toString().contains("Signature verification failed"));
    }

    @Test
    void testValidation_untrustedCertChain() throws Exception {
        SigningContext sc = createSigningContext();
        Map<String, Object> data = baseLicenseData();
        License lic = License.createLicense(TestFields.class, data, signer(sc), sc.chain, sc.trusted);

        // Use different trusted root (new self-signed cert)
        SigningContext other = createSigningContext();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        lic.save(bos);
        Map<String,Object> map = new ObjectMapper().readValue(bos.toByteArray(), new TypeReference<>(){});

        StringBuilder out = new StringBuilder();
        boolean ok = License.validate(map, other.trusted, Version.valueOf("1.1.0"), out);
        assertFalse(ok);
        assertTrue(out.toString().contains("Invalid or untrusted certificate chain"));
    }

    @Test
    void testVersionAndDateBoundaries_and_validDays() throws Exception {
        SigningContext sc = createSigningContext();
        Map<String, Object> data = baseLicenseData();
        // set strict range 1.2.0..1.2.9
        data.put(MIN_VERSION_LICENSE_FIELD, Version.valueOf("1.2.0"));
        data.put(MAX_VERSION_LICENSE_FIELD, Version.valueOf("1.2.9"));
        // dates
        data.put(ISSUE_DATE_LICENSE_FIELD, LocalDate.now());
        data.put(EXPIRY_DATE_LICENSE_FIELD, LocalDate.now().plusDays(10));

        License lic = License.createLicense(TestFields.class, data, signer(sc), sc.chain, sc.trusted);

        StringBuilder out = new StringBuilder();
        assertTrue(lic.validate(sc.trusted, Version.valueOf("1.2.5"), out), () -> out.toString());

        out.setLength(0);
        assertFalse(lic.validate(sc.trusted, Version.valueOf("1.1.9"), out));
        assertTrue(out.toString().contains("Version is not covered by this license"));

        out.setLength(0);
        assertFalse(lic.validate(sc.trusted, Version.valueOf("1.3.0"), out));
        assertTrue(out.toString().contains("Version is not covered by this license"));

        // future issue date
        Map<String,Object> futureIssue = baseLicenseData();
        futureIssue.put(ISSUE_DATE_LICENSE_FIELD, LocalDate.now().plusDays(2));
        assertThrows(LicenseException.class, () -> License.createLicense(TestFields.class, futureIssue, signer(sc), sc.chain, sc.trusted));

        // expired
        Map<String,Object> expired = baseLicenseData();
        expired.put(EXPIRY_DATE_LICENSE_FIELD, LocalDate.now().minusDays(1));
        assertThrows(LicenseException.class, () -> License.createLicense(TestFields.class, expired, signer(sc), sc.chain, sc.trusted));

        // validDays
        assertEquals(10, lic.validDays());
        assertEquals(LocalDate.now().plusDays(10), lic.getValidUntil());
    }

    @Test
    void testGetUnsignedLicenseData_and_prepareSigningDataConsistency() throws Exception {
        SigningContext sc = createSigningContext();
        Map<String, Object> data = baseLicenseData();
        License lic = License.createLicense(TestFields.class, data, signer(sc), sc.chain, sc.trusted);

        // Serialize to map
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        lic.save(bos);
        Map<String,Object> map = new ObjectMapper().readValue(bos.toByteArray(), new TypeReference<>(){});

        byte[] unsignedFromMap = License.getUnsignedLicenseData(map);
        map.remove(SIGNATURE_LICENSE_FIELD);
        byte[] prepared = License.prepareSigningData(map);
        assertArrayEquals(prepared, unsignedFromMap);
    }

    @Test
    void testReservedSignatureKeyInEnumCausesException() throws Exception {
        SigningContext sc = createSigningContext();
        // Define enum that illegally contains SIGNATURE name and includes all used fields
        enum BadFields { LICENSE_ID, LICENSEE, ISSUE_DATE, EXPIRY_DATE, MIN_VERSION, MAX_VERSION, FEATURE, SIGNATURE }
        Map<String, Object> data = baseLicenseData();
        var ex = assertThrows(LicenseException.class, () -> License.createLicense(BadFields.class, data, signer(sc), sc.chain, sc.trusted));
        assertTrue(ex.getMessage().toLowerCase().contains("reserved"));
    }
}
