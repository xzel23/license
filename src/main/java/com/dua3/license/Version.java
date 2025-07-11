package com.dua3.license;

/**
 * Represents a software version with major, minor, patch components and an optional suffix.
 * This class provides functionality to parse a version string, access version components, and format
 * the version as a string.
 * @param major the major version
 * @param minor the minor version
 * @param patch the patch level
 * @param suffix the suffix
 */
public record Version(int major, int minor, int patch, String suffix) {

    /**
     * Parse a version string and return a Version object.
     * The format should be "major.minor.patch" or "major.minor.patch-suffix".
     *
     * @param versionString the string to parse
     * @return the parsed Version
     * @throws IllegalArgumentException if the string cannot be parsed as a valid version
     */
    public static Version valueOf(String versionString) {
        if (versionString.isBlank()) {
            throw new IllegalArgumentException("Version string cannot be empty");
        }

        String[] parts = versionString.split("-", 2);
        String versionPart = parts[0];
        String suffix = parts.length > 1 ? parts[1] : "";

        String[] versionComponents = versionPart.split("\\.");
        if (versionComponents.length != 3) {
            throw new IllegalArgumentException("Version must be in format 'major.minor.patch' or 'major.minor.patch-suffix'");
        }

        try {
            int major = Integer.parseInt(versionComponents[0]);
            int minor = Integer.parseInt(versionComponents[1]);
            int patch = Integer.parseInt(versionComponents[2]);

            return new Version(major, minor, patch, suffix);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Version components must be valid integers", e);
        }
    }

    @Override
    public String toString() {
        return major + "." + minor + "." + patch + (suffix.isEmpty() ? "" : "-" + suffix);
    }
}
