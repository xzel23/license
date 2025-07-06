package com.dua3.license;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

public final class License {
    public static final String SIGNATURE = "signature";

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

            this.data = HashMap.newHashMap(keys.size());
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
}
