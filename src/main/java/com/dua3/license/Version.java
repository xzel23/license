package com.dua3.license;

public record Version(int major, int minor, int patch, String suffix) {
    @Override
    public String toString() {
        return major + "." + minor + "." + patch + (suffix.isEmpty() ? "" : "-" + suffix);
    }
}
