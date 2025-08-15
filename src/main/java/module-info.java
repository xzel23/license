import org.jspecify.annotations.NullMarked;

/**
 * Provides classes and interfaces for building and managing JavaFX applications.
 */
@NullMarked
open module com.dua3.license {
    exports com.dua3.license;

    requires com.dua3.utility;

    requires org.apache.logging.log4j;

    requires java.prefs;
    requires org.jspecify;
}
