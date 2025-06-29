package com.dua3.license;

import java.util.Arrays;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A class that provides a dynamic, runtime-defined enum-like functionality.
 * This allows for defining a set of enumerated values at runtime, as opposed
 * to traditional Java enums which are defined at compile time.
 */
public final class DynamicEnum {

    private static final Pattern PATTERN_ENUM_NAME = Pattern.compile("[A-Z0-9][A-Z0-9_]*");

    public record EnumValue(int ordinal, String name, String value, DynamicEnum parent) {
        public String toString() {
            return value;
        }
    }

    /**
     * An array holding the enumerated values for this dynamic enum.
     * Each {@code EnumValue} in the array represents a unique enumerated value,
     * defined at runtime with its ordinal, name, and associated value.
     *
     * The values in this array are immutable, ensuring the integrity and consistency
     * of the dynamic enum definition once it has been created.
     */
    private final EnumValue[] values;

    /**
     * Creates a new instance of {@code DynamicEnum} with the specified names.
     * Each name will correspond to a unique value in the {@code DynamicEnum}, and must be non-duplicate.
     *
     * @param names the names of the dynamically defined enum values. Each name must be unique.
     * @return a new {@code DynamicEnum} instance containing the provided enum names as values.
     * @throws IllegalArgumentException if any duplicate names are provided or a name does map to an invalid enum name
     */
    public static DynamicEnum ofNames(String... names) {
        return new DynamicEnum(names);
    }

    /**
     * Creates a new instance of {@code DynamicEnum} using the specified names and values.
     * Each name will correspond to a unique value, and both names and values must have the same length.
     *
     * @param names an array of Strings representing the enum names. Each name must be unique.
     * @param values an array of Strings representing the corresponding enum values.
     * @return a new {@code DynamicEnum} instance containing the provided names and values.
     * @throws IllegalArgumentException if the lengths of {@code names} and {@code values} do not match,
     *                                  if duplicates exist in {@code names}, or if names contain invalid enum names.
     */
    public static DynamicEnum ofNamesAndValues(String[] names, String[] values) {
        return new DynamicEnum(names, values);
    }

    /**
     * Creates a new instance of {@code DynamicEnum} from a Java Properties instance.
     * The property names will be used as the enum names and values.
     *
     * @param properties the Properties instance containing the enum names
     * @return a new {@code DynamicEnum} instance containing the property names as enum names and values
     * @throws IllegalArgumentException if the Properties instance is empty, contains duplicate names,
     *                                 or contains names that map to invalid enum names
     */
    public static DynamicEnum fromProperties(Properties properties) {
        if (properties.isEmpty()) {
            throw new IllegalArgumentException("properties cannot be empty");
        }

        String[] names = properties.stringPropertyNames().toArray(new String[0]);
        return new DynamicEnum(names);
    }

    /**
     * Creates a new instance of {@code DynamicEnum} from a Java Properties instance.
     * The property names will be used as the enum names and the property values will be used as the enum values.
     *
     * @param properties the Properties instance containing the enum names and values
     * @return a new {@code DynamicEnum} instance containing the property names as enum names and property values as enum values
     * @throws IllegalArgumentException if the Properties instance is empty, contains duplicate names,
     *                                 or contains names that map to invalid enum names
     */
    public static DynamicEnum fromPropertiesWithValues(Properties properties) {
        if (properties.isEmpty()) {
            throw new IllegalArgumentException("properties cannot be empty");
        }

        int size = properties.size();
        String[] names = new String[size];
        String[] values = new String[size];

        int i = 0;
        for (String name : properties.stringPropertyNames()) {
            names[i] = name;
            values[i] = properties.getProperty(name);
            i++;
        }

        return new DynamicEnum(names, values);
    }

    /**
     * Constructs a new instance of the DynamicEnum class encapsulating a set of dynamic EnumValue objects.
     * For each String, an {@code EnumValue} instance will be created that uses the uppercase name as {@code name()}
     * and the original name as {@code toString()} value.
     *
     * @param names an array of Strings representing the enum values {}@code toString()} values
     */
    private DynamicEnum(String[] names) {
        this(names, names);
    }

    /**
     * Constructs a new instance of the DynamicEnum class encapsulating a set of dynamic EnumValue objects.
     * For each pair of name and value, an {@code EnumValue} instance will be created that uses the uppercase name as {@code name()}
     * and the provided value as {@code toString()} value.
     *
     * @param names an array of Strings representing the enum names
     * @param values an array of Strings representing the enum values {}@code toString()} values
     */
    private DynamicEnum(String[] names, String[] values) {
        if (names.length == 0) {
            throw new IllegalArgumentException("no enum values provided");
        }

        if (names.length != values.length) {
            throw new IllegalArgumentException("names and values arrays must have the same length");
        }

        EnumValue[] enumValues = new EnumValue[names.length];
        for (int i = 0; i < names.length; i++) {
            String enumName = names[i].toUpperCase(Locale.ROOT).replace('-', '_');
            if (!PATTERN_ENUM_NAME.matcher(enumName).matches()) {
                throw new IllegalArgumentException("invalid enum name: " + enumName);
            }
            enumValues[i] = new EnumValue(i, enumName, values[i], this);
        }

        Set<String> allNames = Arrays.stream(enumValues).map(EnumValue::name).collect(Collectors.toSet());
        if (allNames.size() != names.length) {
            throw new IllegalArgumentException("duplicate enum value names");
        }

        this.values = enumValues;
    }

    /**
     * Retrieves an array containing all the enum-like values defined in this {@code DynamicEnum} instance.
     * The returned array is a copy and modifications to it will not affect the original data.
     *
     * @return an array of {@link EnumValue} instances representing the values of this {@code DynamicEnum}
     */
    public EnumValue[] values() {
        return Arrays.copyOf(values, values.length);
    }

    /**
     * Retrieves an {@code EnumValue} object from the dynamic enum based on its name.
     *
     * @param name the name of the desired {@code EnumValue}; must be a non-null, case-sensitive string matching the name of an existing {@code EnumValue}
     * @return the {@code EnumValue} corresponding to the specified name
     * @throws IllegalArgumentException if the provided {@code name} does not match any existing {@code EnumValue} in the dynamic enum
     */
    public EnumValue valueOf(String name) {
        for (EnumValue v : values) {
            if (v.name.equals(name)) {
                return v;
            }
        }
        throw new IllegalArgumentException("unknown enum value: " + name);
    }
}
