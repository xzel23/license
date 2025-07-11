package com.dua3.license;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.function.Function;

/**
 * Represents a License with associated metadata and functionality for validation and processing.
 * The License class provides mfunctionality load, validate, and manage license data, supporting
 * cryptographic operations such as signing and signature verification.
 */
public final class License {
    private static final Logger LOG = LogManager.getLogger(License.class);

    private static final String SIGNATURE = "signature";

    /**
     * Represents the field name for the unique identifier of a license.
     * This constant is used as a key to access the license ID within a license object
     * or during license-related operations.
     */
    // required license fields
    public static final String LICENSE_ID_LICENSE_FIELD = "LICENSE_ID";
    /**
     * A constant representing the field name for the signing key alias
     * in the license system. This field is used to reference the alias
     * of the signing key associated with the license.
     */
    public static final String SIGNING_KEY_ALIAS_LICENSE_FIELD = "SIGNING_KEY_ALIAS";
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
     * Represents the field name used to access the expiry date of a license.
     * This constant is used to reference the expiry date
     * in the license.
     */
    public static final String EXPIRY_DATE_LICENSE_FIELD = "EXPIRY_DATE";

    private final Object keyClass;
    private final Map<Object, Object> data;
    private final String licenseString;

    /**
     * Prepares the data for signing.
     *
     * @param data the license data
     * @return the data to be signed as a byte array
     */
    public static byte[] prepareSigningData(Map<?, ?> data) {
        return data.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Loads a license from an input stream.
     *
     * @param keyClass     the enum class defining the keys used in the license
     * @param keySupplier  a supplier providing the public key for verifying the license signature
     * @param in           the input stream from which the license properties are loaded
     * @return a {@code License} instance created using the provided properties and public key
     * @throws LicenseException if a problem occurs while loading or processing the license
     */
    public static License load(
            Class<? extends Enum<?>> keyClass,
            Function<String, PublicKey> keySupplier,
            InputStream in
    ) throws LicenseException {
        try {
            // Load properties from the input stream
            Properties props = new Properties();
            props.load(in);

            // Convert properties to a map of string to object
            Map<String, Object> properties = new HashMap<>();
            for (String key : props.stringPropertyNames()) {
                String value = props.getProperty(key);

                // Try to parse dates
                if (key.equals(EXPIRY_DATE_LICENSE_FIELD) || key.equals(ISSUE_DATE_LICENSE_FIELD)) {
                    try {
                        properties.put(key, LocalDate.parse(value));
                    } catch (DateTimeParseException e) {
                        throw new LicenseException("invalid value for field '" + key + "'", e);
                    }
                } else {
                    properties.put(key, value);
                }
            }

            return new License(keyClass.asSubclass(Enum.class), properties, keySupplier);
        } catch (IOException e) {
            throw new LicenseException("Failed to load license from input stream", e.toString());
        }
    }

    /**
     * Constructs a new instance of the License class. This constructor verifies the signature of the license
     * properties against the provided public key and initializes the license data.
     *
     * @param keyClass      the class defining the keys used in the license; this must be an enum class or a DynamicEnum
     * @param properties    a map of license properties, including the signature and other license data
     * @param keySupplier   a function that supplies the public key for verifying the license signature, based on its alias
     * @throws LicenseException if the key class is invalid, the license signature is invalid, or any other error occurs during processing
     */
    private License(Object keyClass, Map<String, Object> properties, Function<String, PublicKey> keySupplier) throws LicenseException {
        try {
            Set<Object> keys;
            Function<Object, String> enumName;
            switch (keyClass) {
                case Class<?> cls -> {
                    if (!cls.isEnum()) {
                        throw new IllegalArgumentException("not an enum class");
                    }
                    keys = Set.copyOf(Arrays.asList((Object[]) (cls.getMethod("values").invoke(null))));
                    enumName = v -> ((Enum<?>)v).name();
                }
                case DynamicEnum de -> {
                    keys = Set.copyOf(Arrays.asList(de.values()));
                    enumName = v -> ((DynamicEnum.EnumValue) v).name();
                }
                default -> throw new IllegalArgumentException("invalid keyClass");
            }

            if (keys.stream().map(enumName).anyMatch(SIGNATURE::equalsIgnoreCase)) {
                throw new LicenseException("invalid keyClass");
            }

            this.keyClass = keyClass;

            // Verify the signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(keySupplier.apply(String.valueOf(properties.get(SIGNING_KEY_ALIAS_LICENSE_FIELD))));

            this.data = LinkedHashMap.newLinkedHashMap(keys.size());
            keys.forEach(key -> data.put(enumName.apply(key), properties.get(key.toString())));

            if (data.size() != properties.size() - 1) {
                throw new LicenseException("invalid license data", properties.toString());
            }

            signature.update(prepareSigningData(data));

            if (!switch (properties.get(SIGNATURE)) {
                case byte[] bytes -> signature.verify(bytes);
                case String s -> signature.verify(Base64.getDecoder().decode(s));
                default -> throw new LicenseException("invalid signature data");
            }) {
                throw new LicenseException("invalid signature");
            }

            this.licenseString = data.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new LicenseException("could not find verify license");
        } catch (SignatureException e) {
            throw new LicenseException("invalid signature");
        } catch (InvalidKeyException e) {
            throw new LicenseException("invalid license key");
        } catch (InvocationTargetException | IllegalAccessException | NoSuchMethodException e) {
            throw new LicenseException("error in key class", e.getMessage());
        }
    }

    /**
     * Retrieves the value associated with the specified key from the license data.
     * The behavior of this method depends on the type of the key and its compatibility
     * with the predefined key class.
     *
     * @param key the key used to lookup the value; this must be compatible with the
     *            key class (either a DynamicEnum or an Enum class)
     * @return the value associated with the specified key, or null if no value is
     *         associated with the key
     * @throws IllegalArgumentException if the key is of an invalid type or not
     *                                  compatible with the key class
     */
    Object get(Object key) {
        return switch (keyClass) {
            case DynamicEnum de
                    when key instanceof DynamicEnum.EnumValue enumValue && enumValue.parent() == keyClass -> data.get(key);
            case Class<?> cls
                    when cls.isEnum() && cls.isAssignableFrom(key.getClass()) -> data.get(key);
            default -> throw new IllegalArgumentException("invalid key");
        };
    }

    /**
     * Retrieves the license string associated with this instance.
     *
     * @return the license string, or null if it is not set
     */
    public String getLicenseString() {
        return licenseString;
    }

    /**
     * Converts a string representation of a key into an object representation based on the key class.
     * The key class determines whether the key is an enumeration or a dynamic enumeration.
     *
     * @param name the string representation of the key to be converted
     * @return the key as an object, which may be an Enum or DynamicEnum value
     * @throws IllegalArgumentException if the key class is invalid or the key cannot be converted
     */
    private Object toKey(String name) {
        return switch (keyClass) {
            case DynamicEnum de -> de.valueOf(name);
            case Class<?> cls when cls.isEnum() -> Enum.valueOf((Class<Enum>) cls, name);
            default -> throw new IllegalArgumentException("invalid key");
        };
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
     * Retrieves the alias of the signing key used for the license.
     *
     * @return a string representing the alias of the signing key, or null if the alias is not set
     */
    public String getSigningKeyAlias() {
        return (String) get(toKey(SIGNING_KEY_ALIAS_LICENSE_FIELD));
    }

    /**
     * Retrieves the signature information stored in the license data.
     *
     * @return the signature as a string, or null if no signature is associated
     */
    public String getSignature() {
        return (String) get(toKey(SIGNATURE_LICENSE_FIELD));
    }

    /**
     * Retrieves the issue date of the license.
     *
     * @return the issue date as a {@code LocalDate}, or {@code null} if the issue
     *         date is not defined in the license data
     */
    public LocalDate getIssueDate() {
        return (LocalDate) get(toKey(ISSUE_DATE_LICENSE_FIELD));
    }

    /**
     * Retrieves the expiry date of the license.
     *
     * @return the expiry date as a {@code LocalDate}, or null if the expiry date is not set
     */
    public LocalDate getExpiryDate() {
        return (LocalDate) get(toKey(EXPIRY_DATE_LICENSE_FIELD));
    }

    /**
     * Validates a license from license data.
     *
     * @param licenseData the license data to validate
     * @param keyStore the keystore containing the certificates
     * @param keyStorePassword the password for the keystore
     * @param validationOutput appendable to write validation messages to
     * @return true if the license is valid, false otherwise
     */
    public static boolean validate(Map<String, Object> licenseData, KeyStore keyStore, char[] keyStorePassword, Appendable validationOutput) {
        boolean isValid = true;

        try {
            // Check that all required fields are present in the license
            String[] requiredFields = {
                    LICENSE_ID_LICENSE_FIELD,
                    SIGNING_KEY_ALIAS_LICENSE_FIELD,
                    SIGNATURE_LICENSE_FIELD,
                    ISSUE_DATE_LICENSE_FIELD,
                    EXPIRY_DATE_LICENSE_FIELD
            };

            boolean allRequiredFieldsPresent = true;
            for (String field : requiredFields) {
                if (!licenseData.containsKey(field)) {
                    validationOutput.append("❌ Required field missing: ").append(field).append("\n");
                    isValid = false;
                    allRequiredFieldsPresent = false;
                }
            }

            if (allRequiredFieldsPresent) {
                validationOutput.append("✓ All required fields are present in the license.\n");
            }

            // Find the signature field
            String signingKeyAlias = Objects.requireNonNullElse(licenseData.get(SIGNING_KEY_ALIAS_LICENSE_FIELD), "").toString();
            String signatureValue = Objects.requireNonNullElse(licenseData.get(SIGNATURE_LICENSE_FIELD), "").toString();

            if (signatureValue.isBlank()) {
                validationOutput.append("❌ No valid signature found in the license file.\n");
                isValid = false;
            } else {
                validationOutput.append("✓ Signature found.\n");
            }

            if (signingKeyAlias.isBlank()) {
                validationOutput.append("❌ No signing key information found in the license.\n");
                isValid = false;
            } else {
                validationOutput.append("✓ Signing key alias found.\n");
            }

            if (isValid) {
                // Create a copy of the license data without the signature for verification
                Map<String, Object> dataToVerify = new LinkedHashMap<>(licenseData);
                dataToVerify.remove(SIGNATURE_LICENSE_FIELD);

                // Verify the signature
                try {
                    Certificate cert = keyStore.getCertificate(signingKeyAlias);

                    if (cert == null) {
                        validationOutput.append("❌ Certificate not found for key: ").append(signingKeyAlias).append("\n");
                        isValid = false;
                    } else {
                        PublicKey publicKey = cert.getPublicKey();

                        // Create signature instance
                        Signature signature = Signature.getInstance("SHA256withRSA");
                        signature.initVerify(publicKey);

                        // Update with the data to verify
                        byte[] dataToSign = dataToVerify.toString().getBytes(StandardCharsets.UTF_8);
                        signature.update(dataToSign);

                        // Verify the signature
                        byte[] signatureBytes = Base64.getDecoder().decode(signatureValue);
                        boolean signatureValid = signature.verify(signatureBytes);

                        if (signatureValid) {
                            validationOutput.append("✓ Signature is valid.\n");
                        } else {
                            validationOutput.append("❌ Signature verification failed.\n");
                            isValid = false;
                        }
                    }
                } catch (Exception e) {
                    validationOutput.append("❌ Error verifying signature: ").append(e.getMessage()).append("\n");
                    isValid = false;
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
                validationOutput.append("❌ No issue date field in the license file.\n");
                isValid = false;
            } else if (issueDate == null) {
                validationOutput.append("❌ Invalid issue date.\n");
                isValid = false;
            } else {
                validationOutput.append("✓ Issue date found.\n");
            }

            if (issueDate != null && today.isBefore(issueDate)) {
                validationOutput.append("❌ License issue date is in the future: ").append(issueDateStr).append("\n");
                isValid = false;
            } else if (issueDate != null) {
                validationOutput.append("✓ License issue date is valid: ").append(issueDateStr).append("\n");
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
                validationOutput.append("❌ No expiry field in the license file.\n");
                isValid = false;
            } else if (expiryDate == null) {
                validationOutput.append("❌ Invalid Expiry date.\n");
                isValid = false;
            } else {
                validationOutput.append("✓ Expiry date found.\n");
            }

            if (expiryDate != null && today.isAfter(expiryDate)) {
                validationOutput.append("❌ License has expired on ").append(expiryDateStr).append("\n");
                isValid = false;
            } else if (expiryDate != null) {
                validationOutput.append("✓ License is valid until ").append(expiryDateStr).append("\n");
            }

            // Check for license ID
            String licenseId = Objects.requireNonNullElse(licenseData.get(LICENSE_ID_LICENSE_FIELD), "").toString();

            if (licenseId.isBlank()) {
                validationOutput.append("❌ No license ID field in the license file or it is empty.\n");
                isValid = false;
            } else {
                // Check if the license ID is trimmed
                if (!licenseId.equals(licenseId.trim())) {
                    validationOutput.append("❌ License ID contains leading or trailing whitespace.\n");
                    isValid = false;
                }

                // Check if the license ID contains only ASCII characters
                if (!licenseId.matches("\\A\\p{ASCII}*\\z")) {
                    validationOutput.append("❌ License ID contains non-ASCII characters.\n");
                    isValid = false;
                }

                if (licenseId.equals(licenseId.trim()) && licenseId.matches("\\A\\p{ASCII}*\\z")) {
                    validationOutput.append("✓ License ID is valid.\n");
                }
            }
        } catch (IOException e) {
            LOG.warn("Error during license validation: {}", e.getMessage(), e);
            isValid = false;
        }

        return isValid;
    }

    /**
     * Validates the license data.
     *
     * @param keyStore the keystore containing the certificates
     * @param keyStorePassword the password for the keystore
     * @param validationOutput appendable to write validation messages to
     * @return true if the license is valid, false otherwise
     */
    public boolean validate(KeyStore keyStore, char[] keyStorePassword, Appendable validationOutput) {
        Map<String, Object> licenseData = new LinkedHashMap<>();

        // Convert internal data to a map of strings
        for (Map.Entry<Object, Object> entry : data.entrySet()) {
            licenseData.put(entry.getKey().toString(), entry.getValue());
        }

        // Use the static validate method to validate the license data
        return validate(licenseData, keyStore, keyStorePassword, validationOutput);
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
        LocalDate expiryDate = getExpiryDate();
        return today.until(expiryDate).getDays();
    }
}
