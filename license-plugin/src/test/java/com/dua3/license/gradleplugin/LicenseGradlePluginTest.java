package com.dua3.license.gradleplugin;

import org.gradle.api.Project;
import org.gradle.api.Task;
import org.gradle.api.tasks.TaskContainer;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the {@link LicenseGradlePlugin} class.
 * <p>
 * These tests verify that the plugin correctly registers the createTrialSigningKeystore task
 * and that the task is properly configured.
 */
class LicenseGradlePluginTest {

    @TempDir
    Path tempDir;

    private Project project;

    @BeforeEach
    void setUp() {
        // Create a test project
        project = ProjectBuilder.builder()
                .withProjectDir(tempDir.toFile())
                .build();
    }

    /**
     * Tests that the plugin correctly registers the createTrialSigningKeystore task.
     */
    @Test
    void testPluginRegistersTask() {
        // Apply the plugin to the project
        project.getPlugins().apply(LicenseGradlePlugin.class);

        // Verify that the task is registered
        assertTrue(project.getTasks().getNames().contains("createTrialSigningKeystore"),
                "Plugin should register 'createTrialSigningKeystore' task");

        // Get the task
        Task task = project.getTasks().getByName("createTrialSigningKeystore");

        // Verify task properties
        assertEquals("build setup", task.getGroup(),
                "Task should be in 'build setup' group");
        assertEquals("Generates a short-lived trial signing keystore", task.getDescription(),
                "Task should have correct description");
        assertTrue(task instanceof LicenseGradlePlugin.CreateTrialSigningKeystoreTask,
                "Task should be an instance of CreateTrialSigningKeystoreTask");
    }

    /**
     * Tests the getStringProperty method of the CreateTrialSigningKeystoreTask.
     * This is a utility method used by the task to get properties from the project.
     */
    @Test
    void testGetStringProperty() {
        // Apply the plugin to the project
        project.getPlugins().apply(LicenseGradlePlugin.class);

        // Set a test property
        project.getExtensions().getExtraProperties().set("testProperty", "testValue");

        // Get the task
        LicenseGradlePlugin.CreateTrialSigningKeystoreTask task =
                (LicenseGradlePlugin.CreateTrialSigningKeystoreTask) project.getTasks().getByName("createTrialSigningKeystore");
        assertNotNull(task, "Task should be registered");

        // Use reflection to access the private static method
        try {
            java.lang.reflect.Method method = LicenseGradlePlugin.CreateTrialSigningKeystoreTask.class
                    .getDeclaredMethod("getStringProperty", Project.class, String.class);
            method.setAccessible(true);
            String value = (String) method.invoke(null, project, "testProperty");
            assertEquals("testValue", value, "getStringProperty should return the correct value");
        } catch (Exception e) {
            fail("Failed to invoke getStringProperty method: " + e.getMessage());
        }
    }

    /**
     * Tests that the task throws an exception when a required property is missing.
     */
    @Test
    void testGetStringPropertyMissingProperty() {
        // Apply the plugin to the project
        project.getPlugins().apply(LicenseGradlePlugin.class);

        // Get the task
        LicenseGradlePlugin.CreateTrialSigningKeystoreTask task =
                (LicenseGradlePlugin.CreateTrialSigningKeystoreTask) project.getTasks().getByName("createTrialSigningKeystore");
        assertNotNull(task, "Task should be registered");

        // Use reflection to access the private static method
        try {
            java.lang.reflect.Method method = LicenseGradlePlugin.CreateTrialSigningKeystoreTask.class
                    .getDeclaredMethod("getStringProperty", Project.class, String.class);
            method.setAccessible(true);
            
            // This should throw a NullPointerException because the property doesn't exist
            Exception exception = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> {
                method.invoke(null, project, "nonExistentProperty");
            });
            
            // The cause should be a NullPointerException
            assertTrue(exception.getCause() instanceof NullPointerException,
                    "getStringProperty should throw NullPointerException for missing property");
            assertTrue(exception.getCause().getMessage().contains("missing property nonExistentProperty"),
                    "Exception message should mention the missing property");
        } catch (Exception e) {
            fail("Failed to invoke getStringProperty method: " + e.getMessage());
        }
    }

    /**
     * Tests the CI mode of the task by setting environment variables.
     * This test verifies that the task correctly processes environment variables in CI mode.
     * <p>
     * Note: This test doesn't actually execute the task, as that would require setting up
     * a more complex environment with actual keys and certificates. Instead, it verifies
     * that the task can be configured for CI mode.
     */
    @Test
    void testTaskCIMode() throws IOException {
        // Apply the plugin to the project
        project.getPlugins().apply(LicenseGradlePlugin.class);

        // Create resources directory
        Path resourcesDir = tempDir.resolve("src/main/resources/keys");
        Files.createDirectories(resourcesDir);

        // We can't actually set environment variables in a test, but we can verify
        // that the task is configured to use them by checking the code
        
        // This is a limited test that just verifies the task can be created and configured
        // A more comprehensive test would require mocking the environment variables
        // and actually executing the task, which is beyond the scope of this test
        
        // Get the task
        Task task = project.getTasks().getByName("createTrialSigningKeystore");
        assertNotNull(task, "Task should be registered");
    }

    /**
     * Tests the local mode of the task by setting project properties.
     * This test verifies that the task correctly processes project properties in local mode.
     * <p>
     * Note: This test doesn't actually execute the task, as that would require setting up
     * a more complex environment with actual keystores. Instead, it verifies that the task
     * can be configured for local mode.
     */
    @Test
    void testTaskLocalMode() throws IOException {
        // Apply the plugin to the project
        project.getPlugins().apply(LicenseGradlePlugin.class);

        // Create resources directory
        Path resourcesDir = tempDir.resolve("src/main/resources/keys");
        Files.createDirectories(resourcesDir);

        // Set up project properties for local mode
        project.getExtensions().getExtraProperties().set("developerKeystorePath", "dummy.jks");
        project.getExtensions().getExtraProperties().set("developerKeystorePassword", "dummyPassword");
        project.getExtensions().getExtraProperties().set("developerKeystoreDeveloperKeyAlias", "dummyAlias");

        // This is a limited test that just verifies the task can be created and configured
        // A more comprehensive test would require mocking the environment variables
        // and actually executing the task, which is beyond the scope of this test

        // Get the task
        Task task = project.getTasks().getByName("createTrialSigningKeystore");
        assertNotNull(task, "Task should be registered");
    }
}