package com.dua3.license;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Properties;
import java.util.Arrays;
import java.util.stream.Collectors;

class DynamicEnumTest {

    @Test
    void testFromProperties() {
        // Create a Properties object with test values
        Properties props = new Properties();
        props.setProperty("key1", "value1");
        props.setProperty("key2", "value2");
        props.setProperty("key3", "value3");

        // Create a DynamicEnum from the Properties
        DynamicEnum dynamicEnum = DynamicEnum.fromProperties(props);

        // Verify the DynamicEnum contains the expected values
        DynamicEnum.EnumValue[] values = dynamicEnum.values();
        assertEquals(3, values.length, "Should have 3 enum values");

        // Get all names from the enum values
        var names = Arrays.stream(values)
                .map(DynamicEnum.EnumValue::value)
                .collect(Collectors.toSet());

        // Verify all property names are present in the enum
        assertTrue(names.contains("key1"), "Should contain key1");
        assertTrue(names.contains("key2"), "Should contain key2");
        assertTrue(names.contains("key3"), "Should contain key3");
    }

    @Test
    void testFromPropertiesWithValues() {
        // Create a Properties object with test values
        Properties props = new Properties();
        props.setProperty("key1", "value1");
        props.setProperty("key2", "value2");
        props.setProperty("key3", "value3");

        // Create a DynamicEnum from the Properties with values
        DynamicEnum dynamicEnum = DynamicEnum.fromPropertiesWithValues(props);

        // Verify the DynamicEnum contains the expected values
        DynamicEnum.EnumValue[] values = dynamicEnum.values();
        assertEquals(3, values.length, "Should have 3 enum values");

        // Get all values from the enum values
        var enumValues = Arrays.stream(values)
                .map(DynamicEnum.EnumValue::value)
                .collect(Collectors.toSet());

        // Verify all property values are present in the enum
        assertTrue(enumValues.contains("value1"), "Should contain value1");
        assertTrue(enumValues.contains("value2"), "Should contain value2");
        assertTrue(enumValues.contains("value3"), "Should contain value3");

        // Get all names from the enum values
        var enumNames = Arrays.stream(values)
                .map(DynamicEnum.EnumValue::name)
                .collect(Collectors.toSet());

        // Verify all property names are used as enum names
        assertTrue(enumNames.contains("KEY1"), "Should contain KEY1");
        assertTrue(enumNames.contains("KEY2"), "Should contain KEY2");
        assertTrue(enumNames.contains("KEY3"), "Should contain KEY3");
    }

    @Test
    void testFromPropertiesWithEmptyProperties() {
        // Create an empty Properties object
        Properties emptyProps = new Properties();

        // Verify that creating a DynamicEnum from empty properties throws an exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            DynamicEnum.fromProperties(emptyProps);
        });

        assertTrue(exception.getMessage().contains("cannot be empty"), 
                "Exception message should mention that properties cannot be empty");
    }

    @Test
    void testFromPropertiesWithValuesWithEmptyProperties() {
        // Create an empty Properties object
        Properties emptyProps = new Properties();

        // Verify that creating a DynamicEnum from empty properties throws an exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            DynamicEnum.fromPropertiesWithValues(emptyProps);
        });

        assertTrue(exception.getMessage().contains("cannot be empty"), 
                "Exception message should mention that properties cannot be empty");
    }

    // Note: Testing with null properties is not included as it throws an AssertionError
    // due to project configuration. This behavior is documented in the method's Javadoc.
}
