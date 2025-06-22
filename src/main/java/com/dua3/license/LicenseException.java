package com.dua3.license;

import org.jspecify.annotations.Nullable;

import java.util.Optional;

public class LicenseException extends Exception {
    private final @Nullable String detail;

    public LicenseException(@Nullable String message) {
        super(message);
        this.detail = null;
    }
    public LicenseException(@Nullable String message, @Nullable String detail) {
        super(message);
        this.detail = detail;
    }

    public Optional<String> getDetail() {
        return Optional.ofNullable(detail);
    }
}
