package com.dua3.license;

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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

public final class License {
    private static final String SIGNATURE = "signature";

    // required license fields
    public static final String LICENSE_ID_LICENSE_FIELD = "LICENSE_ID";
    public static final String SIGNING_KEY_ALIAS_LICENSE_FIELD = "SIGNING_KEY_ALIAS";
    public static final String SIGNATURE_LICENSE_FIELD = "SIGNATURE";
    public static final String ISSUE_DATE_LICENSE_FIELD = "ISSUE_DATE";
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

    public static License of(Class<? extends Enum<?>> keyClass, Map<String, Object> properties, Supplier<PublicKey> keySupplier) throws LicenseException {
        return new License(keyClass.asSubclass(Enum.class), properties, keySupplier);
    }

    public static License of(DynamicEnum keyEnum, Map<String, Object> properties, Supplier<PublicKey> keySupplier) throws LicenseException {
        return new License(keyEnum, properties, keySupplier);
    }

    private License(Object keyClass, Map<String, Object> properties, Supplier<PublicKey> keySupplier) throws LicenseException {
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
            signature.initVerify(keySupplier.get());

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

    Object get(Object key) {
        return switch (keyClass) {
            case DynamicEnum de
                    when key instanceof DynamicEnum.EnumValue enumValue && enumValue.parent() == keyClass -> data.get(key);
            case Class<?> cls
                    when cls.isEnum() && cls.isAssignableFrom(key.getClass()) -> data.get(key);
            default -> throw new IllegalArgumentException("invalid key");
        };
    }

    public String getLicenseString() {
        return licenseString;
    }

    private Object toKey(String name) {
        return switch (keyClass) {
            case DynamicEnum de -> de.valueOf(name);
            case Class<?> cls when cls.isEnum() -> Enum.valueOf((Class<Enum>) cls, name);
            default -> throw new IllegalArgumentException("invalid key");
        };
    }

    public String getLicenseId() {
        return (String) get(toKey(LICENSE_ID_LICENSE_FIELD));
    }

    public String getSigningKeyAlias() {
        return (String) get(toKey(SIGNING_KEY_ALIAS_LICENSE_FIELD));
    }

    public String getSignature() {
        return (String) get(toKey(SIGNATURE_LICENSE_FIELD));
    }

    public LocalDate getIssueDate() {
        return (LocalDate) get(toKey(ISSUE_DATE_LICENSE_FIELD));
    }

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
        } catch (Exception e) {
            try {
                validationOutput.append("❌ Error during validation: ").append(e.getMessage()).append("\n");
            } catch (Exception appendError) {
                // Ignore errors when appending to the output
            }
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
}
