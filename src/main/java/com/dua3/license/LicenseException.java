package com.dua3.license;

import org.jspecify.annotations.Nullable;

import java.util.Optional;

/**
 * A custom exception that is thrown when there is a license-related error.
 * This exception can optionally include additional details about the error.
 */
public class LicenseException extends Exception {
    private final @Nullable String detail;

    /**
     * Constructs a new LicenseException with the specified detail message.
     *
     * @param message the detail message, which can be null
     */
    public LicenseException(@Nullable String message) {
        super(message);
        this.detail = null;
    }

    /**
     * Constructs a {@code LicenseException} with the specified detail message and cause.
     *
     * @param message the detail message, which can be {@code null}.
     * @param cause the cause of the exception, which can be {@code null}.
     */
    public LicenseException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
        this.detail = null;
    }

    /**
     * Constructs a new LicenseException with the specified detail message and additional detail.
     *
     * @param message the detail message explaining the reason for the exception, can be null
     * @param detail additional information about the license-related error, can be null
     */
    public LicenseException(@Nullable String message, @Nullable String detail) {
        super(message);
        this.detail = detail;
    }

    /**
     * Retrieves the additional detail associated with this exception, if available.
     *
     * @return an {@link Optional} containing the detail string if present, or an empty {@link Optional} if no detail exists
     */
    public Optional<String> getDetail() {
        return Optional.ofNullable(detail);
    }
}
