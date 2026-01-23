package com.dua3.license;

import com.dua3.utility.application.LicenseData;
import com.dua3.utility.crypt.CertificateUtil;
import com.dua3.utility.lang.LangUtil;
import com.dua3.utility.lang.Version;
import com.dua3.utility.text.TextUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.SequencedMap;
import java.util.Set;
import java.util.function.Function;

/**
 * Represents a License with associated metadata and functionality for validation and processing.
 * The License class provides functionality to load, validate, and manage license data, supporting
 * cryptographic operations such as signing and signature verification.
 */
public final class License {
    private static final Logger LOG = LogManager.getLogger(License.class);
    /**
     * Represents the field name for the unique identifier of a license.
     * This constant is used as a key to access the license ID within a license object
     * or during license-related operations.
     */
    // required license fields
    public static final String LICENSE_ID_LICENSE_FIELD = "LICENSE_ID";
    /**
     * Represents the field name for the licensee name.
     * This constant is used as a key to access the licensee name within a license object
     * or during license-related operations.
     */
    public static final String LICENSEE_LICENSE_FIELD = "LICENSEE";
    /**
     * A constant representing the field name for the digital signature in the license data.
     * This field is used to reference the digital signature associated with the license.
     */
    public static final String SIGNATURE_LICENSE_FIELD = "SIGNATURE";
    /**
     * Represents the field key used to store or retrieve the issue date of the license
     * from a data structure or input.
     * This constant is used to reference the license issue date in the license.
     */
    public static final String ISSUE_DATE_LICENSE_FIELD = "ISSUE_DATE";
    /**
     * Represents the field name used to access the last date the license is valid.
     */
    public static final String EXPIRY_DATE_LICENSE_FIELD = "EXPIRY_DATE";

    /**
     * Define the list of fields that have to be present in every license.
     */
    public static final List<String> REQUIRED_LICENSE_FIELDS = List.of(
            LICENSE_ID_LICENSE_FIELD,
            LICENSEE_LICENSE_FIELD,
            ISSUE_DATE_LICENSE_FIELD,
            EXPIRY_DATE_LICENSE_FIELD,
            SIGNATURE_LICENSE_FIELD
    );
    /**
     * Represents the key for the minimum version required by the license.
     * This field is used to specify the earliest version of software or system
     * that the license is compatible with.
     */
    public static final String MIN_VERSION_LICENSE_FIELD = "MIN_VERSION";
    /**
     * Represents the key for the maximum version supported by the license.
     * This field is used to specify the last version of software or system
     * that the license is compatible with.
     */
    public static final String MAX_VERSION_LICENSE_FIELD = "MAX_VERSION";

    private final Object keyClass;
    private final Map<Object, Object> data;
    private final @Nullable String licenseText;
    private final byte[] signatureBytes;
    private final Certificate[] certChain;

    /**
     * Constructs a new instance of the License class. This constructor verifies the signature of the license
     * properties against the provided public key and initializes the license data.
     *
     * @param keyClass        the class defining the keys used in the license; this must be an enum class or a DynamicEnum
     * @param properties      a map of license properties, including the signature and other license data
     * @param trustedRoots    the certificates trusted by the application
     * @throws LicenseException if the key class is invalid, the license signature is invalid, or any other error occurs during processing
     */
    private License(Object keyClass, Map<String, Object> properties, Certificate[] trustedRoots) throws LicenseException {
        try {
            Set<Object> keys;
            Function<Object, String> enumName;
            switch (keyClass) {
                case Class<?> cls -> {
                    if (!cls.isEnum()) {
                        throw new IllegalArgumentException("not an enum class");
                    }
                    keys = Set.copyOf(Arrays.asList((Object[]) (cls.getMethod("values").invoke(null))));
                    enumName = v -> ((Enum<?>) v).name();
                }
                case DynamicEnum de -> {
                    keys = Set.copyOf(Arrays.asList(de.values()));
                    enumName = v -> ((DynamicEnum.EnumValue) v).name();
                }
                default -> throw new IllegalArgumentException("invalid keyClass");
            }

            if (keys.stream().map(enumName).anyMatch(SIGNATURE_LICENSE_FIELD::equalsIgnoreCase)) {
                throw new LicenseException("license data contains reserved key: " + SIGNATURE_LICENSE_FIELD);
            }

            this.keyClass = keyClass;

            // store signing details
            String[] signatureParts = properties.get(SIGNATURE_LICENSE_FIELD).toString().split(":");
            LangUtil.check(signatureParts.length == 2, "signature format error");

            this.signatureBytes = TextUtil.base64Decode(signatureParts[0]);
            this.certChain = CertificateUtil.parsePkiPathBytes(TextUtil.base64Decode(signatureParts[1]));

            // copy the signature data
            this.data = LinkedHashMap.newLinkedHashMap(keys.size());
            keys.forEach(key -> data.put(enumName.apply(key), properties.get(key.toString())));

            if (data.size() != properties.size() - 1) {
                throw new LicenseException("invalid license data", properties.toString());
            }

            ValidationResult validationResult = validate(properties, trustedRoots, null);
            if (!validationResult.isValid()) {
                LOG.warn("License validation failed:\n{}", validationResult.toString());
                throw new LicenseException("License validation failed: " + validationResult);
            }

            // set the license text
            this.licenseText = data.toString();
        } catch (InvocationTargetException | IllegalAccessException | NoSuchMethodException e) {
            throw new LicenseException("error in key class", e);
        } catch (CertificateException e) {
            throw new LicenseException("error in certificate chain", e);
        }
    }

    /**
     * Retrieves the byte array representing the signature.
     *
     * @return a byte array containing the signature data
     */
    public byte[] getSignatureBytes() {
        return signatureBytes;
    }

    /**
     * Retrieves the RSA public key used for the license.
     *
     * @return the RSA public key associated with signing operations
     */
    public Certificate[] getCertChain() {
        return Arrays.copyOf(certChain, certChain.length);
    }

    /**
     * Creates a license with the specified license fields and data, signs it with the provided key,
     * and writes it to the output stream.
     *
     * @param licenseFieldsEnum the enum class defining the license fields
     * @param licenseData       the license data
     * @param signer            the signing function
     * @param certChain     the certificate chain used for signing
     * @param trustedRoots      the root certificates trusted by the application
     * @return an unmodifiable sequenced map containing the signed license data
     * @throws LicenseException if an error occurs
     */
    public static License createLicense(
            Class<? extends Enum> licenseFieldsEnum,
            Map<String, Object> licenseData,
            Function<byte[], byte[]> signer,
            Certificate[] certChain,
            Certificate[] trustedRoots
    ) throws LicenseException {
        try {
            // Get enum values using reflection
            Object[] enumValues = (Object[]) licenseFieldsEnum.getMethod("values").invoke(null);
            List<String> licenseFields = Arrays.stream(enumValues)
                    .map(v -> ((Enum<?>) v).name())
                    .toList();

            return createLicense(
                    licenseFieldsEnum,
                    licenseFields,
                    licenseData,
                    signer,
                    certChain,
                    trustedRoots
            );
        } catch (InvocationTargetException | IllegalAccessException | NoSuchMethodException e) {
            throw new LicenseException("internal error during license creation", e);
        }
    }

    /**
     * Creates a license with the specified license fields and data, signs it with the provided key,
     * and writes it to the output stream.
     *
     * @param licenseFieldsEnum the dynamic enum defining the license fields
     * @param licenseData       the license data
     * @param signer            the signing function
     * @param certChain     the certificate chain used for signing
     * @param trustedRoots  the root certificates trusted by the application
     * @return an unmodifiable sequenced map containing the signed license data
     * @throws LicenseException if the license could not be created
     */
    public static License createLicense(
            DynamicEnum licenseFieldsEnum,
            Map<String, Object> licenseData,
            Function<byte[], byte[]> signer,
            Certificate[] certChain,
            Certificate[] trustedRoots
    ) throws LicenseException {
        // Get dynamic enum value names
        DynamicEnum.EnumValue[] enumValues = licenseFieldsEnum.values();
        List<String> licenseFields = Arrays.stream(enumValues)
                .map(DynamicEnum.EnumValue::name)
                .toList();

        return createLicense(
                licenseFieldsEnum,
                licenseFields,
                licenseData,
                signer,
                certChain,
                trustedRoots
        );
    }

    /**
     * Loads a license from a sequenced map containing the license data.
     *
     * @param licenseData  the map containing the license data
     * @param keyClass     the enum class defining the keys used in the license
     * @param trustedRoots the trusted root certificates
     * @return a {@code License} instance created using the provided properties and public key
     * @throws LicenseException if a problem occurs while loading or processing the license
     */
    public static License load(
            SequencedMap<String, Object> licenseData,
            Class<? extends Enum<?>> keyClass,
            Certificate[] trustedRoots
    ) throws LicenseException {
        // Convert JSON data to a map of string to object with proper types
        Map<String, Object> properties = new HashMap<>();
        for (Map.Entry<String, Object> entry : licenseData.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            // Try to parse dates
            if (key.equals(EXPIRY_DATE_LICENSE_FIELD) || key.equals(ISSUE_DATE_LICENSE_FIELD)) {
                try {
                    if (value instanceof String s) {
                        properties.put(key, LocalDate.parse(s));
                    } else {
                        properties.put(key, value);
                    }
                } catch (DateTimeParseException e) {
                    throw new LicenseException("invalid value for field '" + key + "'", e);
                }
            } else {
                properties.put(key, value);
            }
        }

        return new License(keyClass.asSubclass(Enum.class), properties, trustedRoots);
    }

    /**
     * Loads a license from the specified file path.
     *
     * @param path the path to the license file.
     * @param keyClass the class of the enum used for license keys.
     * @param trustedRoots an array of trusted root certificates for
     *                     validating the license.
     * @return the loaded license.
     * @throws IOException if an I/O error occurs while reading the license file.
     * @throws LicenseException if the license is invalid or cannot be loaded.
     */
    public static License load(Path path, Class<? extends Enum<?>> keyClass, Certificate[] trustedRoots) throws IOException, LicenseException {
        try (InputStream in = Files.newInputStream(path)) {
            return load(in, keyClass, trustedRoots);
        }
    }

    /**
     * Loads a license from an input stream and validates it against the provided key class and trusted root certificates.
     *
     * @param in the input stream containing the license data
     * @param keyClass the class type of the enum used for license keys
     * @param trustedRoots an array of trusted root certificates for license validation
     * @return the loaded and validated License object
     * @throws IOException if an I/O error occurs while reading from the input stream
     * @throws LicenseException if the license is invalid or cannot be validated
     */
    public static License load(InputStream in, Class<? extends Enum<?>> keyClass, Certificate[] trustedRoots) throws IOException, LicenseException {
        return load(
                new ObjectMapper().reader().forType(SequencedMap.class).<SequencedMap<String, Object>>readValue(in),
                keyClass,
                trustedRoots
        );
    }

    /**
     * Saves the current state to the specified file path.
     * <p>
     * The method opens an output stream to the provided file path
     * and delegates the actual save operation to the {@code save(OutputStream)} method.
     *
     * @param path the file path where the current state should be saved
     * @throws IOException if an I/O error occurs while saving
     */
    public void save(Path path) throws IOException {
        try (OutputStream out = Files.newOutputStream(path)) {
            save(out);
        }
    }

    /**
     * Serializes the data object into JSON format and writes it to the provided OutputStream.
     *
     * @param out the OutputStream where the JSON representation of the data will be written
     * @throws IOException if an I/O error occurs during writing to the OutputStream
     */
    public void save(OutputStream out) throws IOException {
        // build a properties map including signature and data, converting values to JSON-friendly types
        Map<String, Object> props = new LinkedHashMap<>(data.size() + 1);
        for (Map.Entry<Object, Object> e : data.entrySet()) {
            String k = e.getKey().toString();
            Object v = e.getValue();
            switch (v) {
                case LocalDate ld -> props.put(k, ld.toString());
                case Version ver -> props.put(k, ver.toString());
                case null, default -> props.put(k, v);
            }
        }
        try {
            String sig = TextUtil.base64Encode(signatureBytes);
            String chain = TextUtil.base64Encode(CertificateUtil.toPkiPathBytes(certChain));
            props.put(SIGNATURE_LICENSE_FIELD, sig + ":" + chain);
        } catch (CertificateException e) {
            throw new IOException("could not serialize certificate chain", e);
        }

        new ObjectMapper()
                .findAndRegisterModules()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .writerWithDefaultPrettyPrinter()
                .writeValue(out, props);
    }

    /**
     * Creates a license with the specified license fields and data, signs it with the provided key,
     * and returns the signed license data.
     *
     * @param keyClass      the key class defining the license fields
     * @param licenseFields the list of license field names
     * @param licenseData   the license data
     * @param signer        the signing function
     * @param certChain     the certificate chain used for signing
     * @param trustedRoots  the trusted certificates
     * @return an unmodifiable sequenced map containing the signed license data
     */
    private static License createLicense(
            Object keyClass,
            List<String> licenseFields,
            Map<String, Object> licenseData,
            Function<byte[], byte[]> signer,
            Certificate[] certChain,
            Certificate[] trustedRoots
    ) throws LicenseException {
        try {
            // check that the certificate chain is not empty and its root certificate is trusted
            LangUtil.check(validateCertificateChain(certChain, trustedRoots), "invalid certificate chain");

            // validate the certificate chain
            CertificateUtil.verifyCertificateChain(certChain);

            // Validate that all license data keys are in the license fields
            for (String key : licenseData.keySet()) {
                if (!licenseFields.contains(key) && !key.equals(SIGNATURE_LICENSE_FIELD)) {
                    throw new IllegalArgumentException("License data contains key not in license fields: " + key);
                }
            }

            // Create a copy of the license data without the signature
            Map<String, Object> dataToSign = new LinkedHashMap<>(licenseData);
            dataToSign.remove(SIGNATURE_LICENSE_FIELD);

            // Sign the data
            byte[] dataToSignBytes = prepareSigningData(dataToSign);
            byte[] signatureBytes = signer.apply(dataToSignBytes);
            String signatureBase64 = TextUtil.base64Encode(signatureBytes);

            byte[] certChainBytes = CertificateUtil.toPkiPathBytes(certChain);
            String certChainBase64 = TextUtil.base64Encode(certChainBytes);

            // Add the signature to the license data
            SequencedMap<String, Object> finalLicenseData = new LinkedHashMap<>(licenseData);
            finalLicenseData.put(SIGNATURE_LICENSE_FIELD, signatureBase64 + ":" + certChainBase64);

            return new License(keyClass, finalLicenseData, trustedRoots);
        } catch (CertificateException e) {
            throw new LicenseException("could not create license", e);
        }
    }

    /**
     * Prepares the data for signing.
     *
     * @param data the license data
     * @return the data to be signed as a byte array
     */
    public static byte[] prepareSigningData(Map<?, ?> data) {
        // create deterministic representation independent of map iteration order
        Map<String, Object> sorted = new java.util.TreeMap<>();
        for (Map.Entry<?, ?> e : data.entrySet()) {
            String k = String.valueOf(e.getKey());
            Object v = e.getValue();
            switch (v) {
                case LocalDate ld -> sorted.put(k, ld.toString());
                case Version ver -> sorted.put(k, ver.toString());
                case null, default -> sorted.put(k, v);
            }
        }
        return sorted.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Retrieves the license text associated with this instance.
     *
     * @return an Optional holding the license text, or an empty Optional if it is not set
     */
    public Optional<String> getLicenseText() {
        return Optional.ofNullable(licenseText);
    }

    /**
     * Retrieves the license ID stored in the license data.
     *
     * @return the license ID as a string, or null if the license ID is not set
     */
    public String getLicenseId() {
        return (String) get(toKey(LICENSE_ID_LICENSE_FIELD));
    }

    /**
     * Retrieves the value associated with the specified key from the license data.
     * The behavior of this method depends on the type of the key and its compatibility
     * with the predefined key class.
     *
     * @param key the key used to lookup the value; this must be compatible with the
     *            key class (either a DynamicEnum or an Enum class)
     * @return the value associated with the specified key, or null if no value is
     * associated with the key
     * @throws IllegalArgumentException if the key is of an invalid type or not
     *                                  compatible with the key class
     */
    Object get(Object key) {
        return switch (keyClass) {
            case DynamicEnum de when key instanceof DynamicEnum.EnumValue enumValue && enumValue.parent() == keyClass ->
                    data.get(enumValue.name());
            case Class<?> cls when cls.isEnum() && cls.isAssignableFrom(key.getClass()) ->
                    data.get(((Enum<?>) key).name());
            default -> throw new IllegalArgumentException("invalid key");
        };
    }

    /**
     * Converts a string representation of a key into an object representation based on the key class.
     * The key class determines whether the key is an enumeration or a dynamic enumeration.
     *
     * @param name the string representation of the key to be converted
     * @return the key as an object, which may be an Enum or DynamicEnum value
     * @throws IllegalArgumentException if the key class is invalid or the key cannot be converted
     */
    @SuppressWarnings("unchecked")
    private Object toKey(String name) {
        return switch (keyClass) {
            case DynamicEnum de -> de.valueOf(name);
            case Class<?> cls when cls.isEnum() -> Enum.valueOf((Class<Enum>) cls, name);
            default -> throw new IllegalArgumentException("invalid key");
        };
    }

    /**
     * Retrieves the signature information stored in the license data.
     *
     * @return the signature as a string, or null if no signature is associated
     */
    public String getSignature() {
        String sig = TextUtil.base64Encode(signatureBytes);
        try {
            String chain = TextUtil.base64Encode(CertificateUtil.toPkiPathBytes(certChain));
            return sig + ":" + chain;
        } catch (CertificateException e) {
            throw new IllegalStateException("could not encode certificate chain", e);
        }
    }

    /**
     * Retrieves the issue date of the license.
     *
     * @return the issue date as a {@code LocalDate}, or {@code null} if the issue
     * date is not defined in the license data
     */
    public LocalDate getIssueDate() {
        return (LocalDate) get(toKey(ISSUE_DATE_LICENSE_FIELD));
    }

    /**
     * Retrieves the minimum version specified in the license data.
     *
     * @return the minimum version as a {@code Version} object
     */
    public Version getMinVersion() {
        return (Version) get(toKey(MIN_VERSION_LICENSE_FIELD));
    }

    /**
     * Retrieves the maximum version specified in the license data.
     *
     * @return the maximum version as a {@code Version} object
     */
    public Version getMaxVersion() {
        return (Version) get(toKey(MAX_VERSION_LICENSE_FIELD));
    }

    /**
     * Validates the license using the provided keystore, password, and version information.
     * The method checks the license data against the keystore and writes any validation
     * messages to the provided output.
     *
     * @param trustedRoots     the trusted root certificates
     * @param currentVersion   the current version of the application for version compatibility checks
     * @return the validation result
     */
    public ValidationResult validate(Certificate[] trustedRoots, Version currentVersion) {
        Map<String, Object> licenseData = new LinkedHashMap<>();

        // Convert internal data to a map of strings with JSON-friendly values
        for (Map.Entry<Object, Object> entry : data.entrySet()) {
            String k = entry.getKey().toString();
            Object v = entry.getValue();
            switch (v) {
                case LocalDate ld -> licenseData.put(k, ld.toString());
                case Version ver -> licenseData.put(k, ver.toString());
                case null, default -> licenseData.put(k, v);
            }
        }

        // add signature field from internal state
        licenseData.put(SIGNATURE_LICENSE_FIELD, getSignature());

        // Use the static validate method to validate the license data
        return validate(licenseData, trustedRoots, currentVersion);
    }

    record ValidationDetail(String key, boolean valid, String detail) {}

    record ValidationResult(List<ValidationDetail> details, boolean isValid) {
        static ValidationResult of(Collection<ValidationDetail> details) {
            boolean valid = details.stream().allMatch(ValidationDetail::valid);
            List<ValidationDetail> detailsList = List.copyOf(details);
            return new ValidationResult(detailsList, valid);
        }

        ValidationResult {
            boolean listValid = details.stream().allMatch(detail -> detail.valid);

            if (listValid != isValid) {
                throw new IllegalStateException("Validation result is inconsistent: " + details);
            }
        }

        public <T extends Appendable> T appendTo(T appendable) throws IOException {
            for (ValidationDetail detail : details) {
                appendable.append(detail.valid ? "✓" : "❌").append(" ").append(detail.detail).append("\n");
            }
            return appendable;
        }

        public String failuresToString() {
            StringBuilder appendable = new StringBuilder(512);
            for (ValidationDetail detail : details) {
                if (detail.valid) continue;
                appendable.append(detail.valid ? "✓" : "❌").append(" ").append(detail.detail).append("\n");
            }
            return appendable.toString();
        }

        @Override
        public String toString() {
            try {
                return appendTo(new StringBuilder(512)).toString();
            } catch (IOException e) {
                // should never happen with StringBuilder
                throw new UncheckedIOException(e);
            }
        }
    }

    /**
     * Validates a license from license data.
     *
     * @param licenseData      the license data to validate
     * @param trustedRoots     the trusted root certificates
     * @param currentVersion   the current version of the application for version compatibility checks
     * @return the result of validation as an {@link ValidationResult} instance
     */
    public static ValidationResult validate(Map<String, Object> licenseData, Certificate[] trustedRoots, @Nullable Version currentVersion) {
        List<ValidationDetail> validationDetails = new ArrayList<>();

        try {
            // Check that all required fields are present in the license
            String[] requiredFields = {
                    LICENSE_ID_LICENSE_FIELD,
                    SIGNATURE_LICENSE_FIELD,
                    ISSUE_DATE_LICENSE_FIELD,
                    EXPIRY_DATE_LICENSE_FIELD,
                    MIN_VERSION_LICENSE_FIELD,
                    MAX_VERSION_LICENSE_FIELD
            };

            boolean allRequiredFieldsPresent = true;
            for (String field : requiredFields) {
                if (!licenseData.containsKey(field)) {
                    validationDetails.add(new ValidationDetail(
                            "license fields[" + field + "]",
                            false,
                            "Required field missing: " + field
                    ));
                    allRequiredFieldsPresent = false;
                }
            }

            if (allRequiredFieldsPresent) {
                validationDetails.add(new ValidationDetail(
                        "license fields",
                        true,
                        "All required fields are present in the license."
                ));
            }

            // Find the signature field
            String signatureValue = Objects.requireNonNullElse(licenseData.get(SIGNATURE_LICENSE_FIELD), "").toString();
            if (signatureValue.isBlank()) {
                validationDetails.add(new ValidationDetail(
                        "signature",
                        false,
                        "No signature found in the license file."
                ));
            } else {
                validationDetails.add(new ValidationDetail(
                        "signature",
                        true,
                        "Signature found."
                ));
            }

            Certificate[] certChain;
            byte[] signatureBytes;
            try {
                String[] signatureParts = signatureValue.split(":");

                signatureBytes = TextUtil.base64Decode(signatureParts[0]);
                certChain = CertificateUtil.parsePkiPathBytes(TextUtil.base64Decode(signatureParts[1]));
                CertificateUtil.verifyCertificateChain(certChain);

                validationDetails.add(new ValidationDetail(
                        "signature.format",
                        true,
                        "Signature format is valid."
                ));
            } catch (GeneralSecurityException | ArrayIndexOutOfBoundsException | IllegalArgumentException e) {
                validationDetails.add(new ValidationDetail(
                        "signature.format",
                        false,
                        "Invalid signature format."
                ));
                certChain = null;
                signatureBytes = null;
            }

            if (signatureBytes != null) {
                // Create a copy of the license data without the signature for verification
                byte[] unsignedLicenseData = getUnsignedLicenseData(licenseData);

                // Verify the signature
                try {
                    if (certChain.length == 0) {
                        validationDetails.add(new ValidationDetail(
                                "signature.certchain",
                                false,
                                "Certificate chain is empty."
                        ));
                    } else {
                        if (!validateCertificateChain(certChain, trustedRoots)) {
                            validationDetails.add(new ValidationDetail(
                                    "signature.certchain",
                                    false,
                                    "Invalid or untrusted certificate chain."
                            ));
                        }

                        // Create signature instance
                        Signature signature = Signature.getInstance("SHA256withRSA");
                        signature.initVerify(certChain[0].getPublicKey());

                        // Update with the data to verify
                        signature.update(unsignedLicenseData);

                        // Verify the signature
                        boolean signatureValid = signature.verify(signatureBytes);

                        if (signatureValid) {
                            validationDetails.add(new ValidationDetail(
                                    "signature.validation",
                                    true,
                                    "Signature is valid."
                            ));
                        } else {
                            validationDetails.add(new ValidationDetail(
                                    "signature.validation",
                                    false,
                                    "Signature verification failed."
                            ));
                        }
                    }
                } catch (Exception e) {
                    validationDetails.add(new ValidationDetail(
                            "signature.validation",
                            false,
                            "Error verifying signature."
                    ));
                    LOG.warn("Exception occurred during signature verification: {}\n{}", e.getMessage(), signatureValue, e);
                }
            }

            // Check for license ID
            String licenseId = Objects.requireNonNullElse(licenseData.get(LICENSE_ID_LICENSE_FIELD), "").toString();

            if (licenseId.isBlank()) {
                validationDetails.add(new ValidationDetail(
                        "license_id",
                        false,
                        "No license ID field in the license file or it is empty."
                ));
            } else {
                // Check if the license ID is trimmed
                boolean isTrimmed = licenseId.equals(licenseId.trim());
                if (!isTrimmed) {
                    validationDetails.add(new ValidationDetail(
                            "license_id.format",
                            false,
                            "License ID contains leading or trailing whitespace."
                    ));
                }

                // Check if the license ID contains only ASCII characters
                boolean isAsciiOnly = licenseId.matches("\\A\\p{ASCII}*\\z");
                if (!isAsciiOnly) {
                    validationDetails.add(new ValidationDetail(
                            "license_id.format",
                            false,
                            "License ID contains non-ASCII characters."
                    ));
                }

                if (isTrimmed && isAsciiOnly) {
                    validationDetails.add(new ValidationDetail(
                            "license_id.format",
                            true,
                            "License ID is valid."
                    ));
                }
            }

            // Check for issue date
            LocalDate today = LocalDate.now();
            String issueDateStr = Objects.requireNonNullElse(licenseData.get(ISSUE_DATE_LICENSE_FIELD), "").toString();
            LocalDate issueDate = null;
            try {
                issueDate = LocalDate.parse(issueDateStr);
            } catch (DateTimeParseException e) {
                // Error parsing issue date
            }

            if (issueDateStr.isBlank()) {
                validationDetails.add(new ValidationDetail(
                        "issue.date",
                        false,
                        "No issue date field in the license file."
                ));
            } else if (issueDate == null) {
                validationDetails.add(new ValidationDetail(
                        "issue.date",
                        false,
                        "Invalid issue date."
                ));
            } else {
                validationDetails.add(new ValidationDetail(
                        "issue.date",
                        true,
                        "Issue date found."
                ));
            }

            if (issueDate != null && today.isBefore(issueDate)) {
                validationDetails.add(new ValidationDetail(
                        "issue.date.validity",
                        false,
                        "License issue date is in the future: " + issueDateStr
                ));
            } else if (issueDate != null) {
                validationDetails.add(new ValidationDetail(
                        "issue.date.validity",
                        true,
                        "License issue date is valid: " + issueDateStr
                ));
            }

            // Check for expiration date
            String expiryDateStr = Objects.requireNonNullElse(licenseData.get(EXPIRY_DATE_LICENSE_FIELD), "").toString();
            LocalDate expiryDate = null;
            try {
                expiryDate = LocalDate.parse(expiryDateStr);
            } catch (DateTimeParseException e) {
                // Error parsing expiry date
            }

            if (expiryDateStr.isBlank()) {
                validationDetails.add(new ValidationDetail(
                        "expiry.date.validity",
                        false,
                        "No expiry field in the license file."
                ));
            } else if (expiryDate == null) {
                validationDetails.add(new ValidationDetail(
                        "expiry.date.validity",
                        false,
                        "Invalid Expiry date."
                ));
            } else {
                validationDetails.add(new ValidationDetail(
                        "expiry.date.validity",
                        true,
                        "Expiry date found."
                ));
            }

            if (expiryDate != null && today.isAfter(expiryDate)) {
                validationDetails.add(new ValidationDetail(
                        "license.validity",
                        false,
                        "License has expired on " + expiryDateStr
                ));
            } else if (expiryDate != null) {
                validationDetails.add(new ValidationDetail(
                        "license.validity",
                        true,
                        "License expires on " + expiryDateStr
                ));
            }

            // Check for minimum version
            Version minVersion = getAndValidateVersion(licenseData, MIN_VERSION_LICENSE_FIELD);

            if (minVersion == null) {
                validationDetails.add(new ValidationDetail(
                        "license.version.min",
                        false,
                        "No valid minimum version field in the license file."
                ));
            } else {
                validationDetails.add(new ValidationDetail(
                        "license.version.min",
                        true,
                        "Minimum version found."
                ));
            }

            Version maxVersion = getAndValidateVersion(licenseData, MAX_VERSION_LICENSE_FIELD);

            if (maxVersion == null) {
                validationDetails.add(new ValidationDetail(
                        "license.version.max",
                        false,
                        "No valid maximum version field in the license file."
                ));
            } else {
                validationDetails.add(new ValidationDetail(
                        "license.version.max",
                        true,
                        "Maximum version found."
                ));
            }

            if (minVersion != null && maxVersion != null) {
                if (minVersion.compareTo(maxVersion) > 0) {
                    validationDetails.add(new ValidationDetail(
                            "license.version.consistency",
                            false,
                            "Mimimum version is greater than maximum version: " + minVersion + " > " + maxVersion
                    ));
                } else {
                    validationDetails.add(new ValidationDetail(
                            "license.version.consistency",
                            true,
                            "Minimum version <= maximum version"
                    ));
                }
            }

            if (currentVersion != null && minVersion != null && maxVersion != null) {
                if (!currentVersion.isBetween(minVersion, maxVersion)) {
                    validationDetails.add(new ValidationDetail(
                            "license.version.valid",
                            false,
                            "Version is not covered by this license: " + currentVersion
                    ));
                } else {
                    validationDetails.add(new ValidationDetail(
                            "license.version.valid",
                            true,
                            "Version is covered by this license."
                    ));
                }
            }
        } catch (RuntimeException e) {
            LOG.warn("Error during license validation: {}", e.getMessage(), e);
            validationDetails.add(new ValidationDetail(
                    "license.valid",
                    false,
                    "The license could not be verified."
            ));
        }

        return ValidationResult.of(validationDetails);
    }

    private static boolean validateCertificateChain(Certificate[] certChain, Certificate[] trustedRoots) throws CertificateException {
        if (certChain.length == 0) {
            LOG.warn("Certificate chain is empty");
            return false;
        }

        try {
            // Remove server-provided root; CertPath must *not* include trust anchor
            List<X509Certificate> x509Chain = Arrays.stream(certChain).map(X509Certificate.class::cast).toList();
            List<X509Certificate> x509Roots = Arrays.stream(trustedRoots).map(X509Certificate.class::cast).toList();

            // Convert trusted roots into trust anchors
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (X509Certificate root : x509Roots) {
                trustAnchors.add(new TrustAnchor(root, null));
            }

            // Build CertPath from the provided chain
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(x509Chain);

            // PKIX parameters with trust anchors
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false); // or true if you add CRL/OCSP support

            // Validate
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);
            return true;
        } catch (CertPathValidatorException e) {
            LOG.warn("Invalid certificate chain: {}", e.getMessage(), e);
            return false;
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | CertificateException e) {
            LOG.warn("Error validating certificate chain: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Extracts the unsigned license data by removing the signature field from the provided
     * license data map and converting the remaining map to a UTF-8 encoded byte array.
     * This method is used to prepare the license data for verification processes.
     *
     * @param licenseData a map containing the license data, which includes signed data
     *                    and associated metadata
     * @return a byte array representing the unsigned license data in UTF-8 encoding
     */
    public static byte[] getUnsignedLicenseData(Map<String, Object> licenseData) {
        Map<String, Object> dataToVerify = new java.util.TreeMap<>(licenseData);
        dataToVerify.remove(SIGNATURE_LICENSE_FIELD);
        return dataToVerify.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static @Nullable Version getAndValidateVersion(Map<String, Object> licenseData, String licenseFieldName) {
        String versionStr = Objects.requireNonNullElse(licenseData.get(licenseFieldName), "").toString();
        Version version = null;
        try {
            version = Version.valueOf(versionStr);
        } catch (IllegalArgumentException e) {
            // Error parsing version
        }
        return version;
    }

    /**
     * Calculates the number of valid days remaining until the license expires.
     * <p>
     * The method computes the difference in days between the current date and the
     * expiry date of the license. If the expiry date is in the past, it returns a
     * number less than or equal to zero.
     *
     * @return the number of valid days remaining, or a non-positive number if the license is expired
     */
    public int validDays() {
        LocalDate today = LocalDate.now();
        LocalDate expiryDate = getValidUntil();
        return today.until(expiryDate).getDays();
    }

    /**
     * Retrieves the expiry date of the license.
     *
     * @return the expiry date as a {@code LocalDate}
     */
    public LocalDate getValidUntil() {
        return (LocalDate) get(toKey(EXPIRY_DATE_LICENSE_FIELD));
    }

    /**
     * Retrieves the licensee of the license.
     *
     * @return the licensee
     */
    private String getLicensee() {
        return (String) get(toKey(LICENSEE_LICENSE_FIELD));
    }

    /**
     * Retrieves the license data associated with the current context.
     *
     * @return an instance of LicenseData containing details such as licensee information,
     *         validity period, license ID, and the license text if available.
     */
    public LicenseData getLicenseData() {
        return new LicenseData(
            getLicensee(),
            getValidUntil(),
            getLicenseId(),
            getLicenseText().map(t -> () -> t)
        );
    }

}
