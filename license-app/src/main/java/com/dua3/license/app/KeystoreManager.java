package com.dua3.license.app;

import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.data.Pair;
import com.dua3.utility.swing.FileInput;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import java.awt.Component;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.prefs.Preferences;

/**
 * Dialog for selecting or creating a keystore.
 */
public class KeystoreManager {
    private static final Logger LOG = LogManager.getLogger(KeystoreManager.class);
    private static final String PREF_KEYSTORE_PATH = "keystorePath";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    /**
     * Enum to specify the mode of the keystore dialog.
     */
    public enum DialogMode {
        LOAD_EXISTING,
        CREATE_NEW
    }

    private byte[] encryptedPassword;
    private byte[] encryptionKey;
    private Path keystorePath;
    private KeyStore keyStore;

    /**
     * Shows a dialog at startup that asks the user to either load an existing keystore or create a new one.
     * If there's an error, it shows the error message and asks if the user wants to try again.
     *
     * @param parent the parent component
     * @return true if a keystore was successfully loaded or created, false otherwise
     */
    public boolean showDialog(Component parent) {
        String errorMessage = null;
        boolean retry = false;

        do {
            // Create a simple panel for the initial dialog
            JPanel panel = new JPanel(new MigLayout("fill, insets 10", "[grow]", "[]"));

            // Add error message if there was an error
            if (errorMessage != null) {
                JLabel errorLabel = new JLabel("<html><font color='red'>Error: " + errorMessage + "</font></html>");
                panel.add(errorLabel, "wrap");
            }

            // Only show "Load Keystore" and "New Keystore" buttons
            String[] options = new String[]{"Load Keystore", "New Keystore"};
            String defaultOption = "Load Keystore";

            int option = JOptionPane.showOptionDialog(
                    parent,
                    panel,
                    "Keystore Selection",
                    JOptionPane.DEFAULT_OPTION,
                    errorMessage != null ? JOptionPane.WARNING_MESSAGE : JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    defaultOption
            );

            // Process the user's choice
            if (option == 0) {
                // Load existing keystore
                LOG.debug("User chose to load an existing keystore");
                boolean success = showLoadCreateKeystoreDialog(parent, DialogMode.LOAD_EXISTING);
                if (success) {
                    return true; // Successfully loaded
                } else {
                    // Get the error message from the dialog
                    errorMessage = "Failed to load keystore. Please check the path and password.";
                    retry = true; // Try again
                }
            } else if (option == 1) {
                // Create new keystore
                LOG.debug("User chose to create a new keystore");
                boolean success = showLoadCreateKeystoreDialog(parent, DialogMode.CREATE_NEW);
                if (success) {
                    return true; // Successfully created
                } else {
                    // Get the error message from the dialog
                    errorMessage = "Failed to create keystore. Please check the path and password.";
                    retry = true; // Try again
                }
            } else {
                // User chose to cancel or quit
                return false;
            }

        } while (retry);

        return false;
    }

    /**
     * Shows a dialog for loading or creating a keystore.
     *
     * @param parent the parent component
     * @param mode the dialog mode (LOAD_EXISTING or CREATE_NEW)
     * @return true if successful, false otherwise
     */
    private boolean showLoadCreateKeystoreDialog(Component parent, DialogMode mode) {
        LOG.debug("Showing {} keystore dialog", mode == DialogMode.LOAD_EXISTING ? "load" : "create");

        // First, show a file selection dialog
        Path defaultPath = getStoredKeystorePath();
        Optional<Path> selectedPath = switch (mode) {
            case LOAD_EXISTING ->
                    SwingUtil.showFileOpenDialog(parent, defaultPath, Pair.of("Java Keystore File", new String[]{"jks"}));
            case CREATE_NEW ->
                    SwingUtil.showFileSaveDialog(parent, defaultPath, Pair.of("Java Keystore File", new String[]{"jks"}));
        };

        // Check if a path was selected
        if (selectedPath.isEmpty()) {
            LOG.warn("No keystore path specified for {}", mode == DialogMode.LOAD_EXISTING ? "loading" : "creation");
            JOptionPane.showMessageDialog(parent, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        //
        Path path = selectedPath.get();
        LOG.debug("Selected path for {} keystore: {}", mode == DialogMode.LOAD_EXISTING ? "loading" : "creating", path);

        // For new keystores, check if file exists and confirm overwrite
        if (mode == DialogMode.CREATE_NEW && Files.exists(path)) {
            LOG.debug("Keystore file already exists at path: {}", path);
            int choice = JOptionPane.showConfirmDialog(
                    parent,
                    "The keystore file already exists. Do you want to overwrite it?",
                    "File Exists",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
            );

            if (choice != JOptionPane.YES_OPTION) {
                LOG.debug("User chose not to overwrite existing keystore file");
                // Ask for a new filename
                FileInput newPathInput = new FileInput(FileInput.SelectionMode.SELECT_FILE, path, 20);
                int newResult = JOptionPane.showConfirmDialog(
                        parent,
                        newPathInput,
                        "Enter a new keystore path",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE
                );

                if (newResult == JOptionPane.OK_OPTION && newPathInput.getPath().isPresent()) {
                    path = newPathInput.getPath().get();
                    LOG.debug("User provided new keystore path: {}", path);
                } else {
                    LOG.debug("User cancelled keystore creation");
                    return false;
                }
            }
        }

        // Now, show the password dialog
        JPanel passwordPanel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]"));
        passwordPanel.add(new JLabel("Keystore Password:"));
        JPasswordField keystorePasswordField = new JPasswordField(20);
        passwordPanel.add(keystorePasswordField, "growx, wrap");

        // Add confirmation field for new keystores
        JPasswordField confirmPasswordField = null;
        if (mode == DialogMode.CREATE_NEW) {
            passwordPanel.add(new JLabel("Confirm Password:"));
            confirmPasswordField = new JPasswordField(20);
            passwordPanel.add(confirmPasswordField, "growx");
        }

        // Show the password dialog
        String passwordDialogTitle = mode == DialogMode.LOAD_EXISTING ? "Enter Keystore Password" : "Create Keystore Password";
        int passwordResult = JOptionPane.showConfirmDialog(
                parent,
                passwordPanel,
                passwordDialogTitle,
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );

        if (passwordResult != JOptionPane.OK_OPTION) {
            LOG.debug("User cancelled password entry for {} keystore", mode == DialogMode.LOAD_EXISTING ? "loading" : "creating");
            return false;
        }

        // For new keystores, verify that passwords match
        if (mode == DialogMode.CREATE_NEW && confirmPasswordField != null) {
            char[] password = keystorePasswordField.getPassword();
            char[] confirmPassword = confirmPasswordField.getPassword();

            if (!java.util.Arrays.equals(password, confirmPassword)) {
                LOG.debug("Passwords do not match for new keystore creation");
                JOptionPane.showMessageDialog(parent, 
                    "Passwords do not match. Please try again.", 
                    "Password Mismatch", 
                    JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }

        // Process the password
        if (!storePassword(keystorePasswordField.getPassword(), mode)) {
            return false;
        }

        // Process the keystore
        if (mode == DialogMode.LOAD_EXISTING) {
            // Load existing keystore
            try {
                KeyStore loadedKeyStore = KeyStoreUtil.loadKeyStoreFromFile(path, getPassword());

                // Store the keystore path and instance
                this.keystorePath = path;
                this.keyStore = loadedKeyStore;
                saveKeystorePath(path);

                LOG.debug("Keystore loaded successfully from: {}", path);
                return true;
            } catch (GeneralSecurityException | IOException e) {
                LOG.warn("Error loading keystore from path: {}", path, e);
                JOptionPane.showMessageDialog(parent, "Error loading keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        } else {
            // Create new keystore
            try {
                // Create a new KeyStore instance directly
                KeyStore newKeyStore = KeyStore.getInstance("PKCS12");
                newKeyStore.load(null, getPassword());

                // No need to backup here as this is a new keystore
                KeyStoreUtil.saveKeyStoreToFile(newKeyStore, path, getPassword());
                this.keystorePath = path;
                this.keyStore = newKeyStore;
                saveKeystorePath(path);

                LOG.debug("Keystore created successfully at: {}", path);
                return true;
            } catch (GeneralSecurityException | IOException e) {
                LOG.warn("Error creating keystore at path: {}", path, e);
                JOptionPane.showMessageDialog(parent, "Error creating keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }
    }

    private boolean storePassword(char[] password, DialogMode mode) {
        // Validate password only when creating a new keystore
        if (mode == DialogMode.CREATE_NEW) {
            PasswordValidationResult validationResult = validatePassword(password);
            if (!validationResult.isValid()) {
                JOptionPane.showMessageDialog(null,
                        validationResult.getErrorMessage() + """


                                        Password requirements:
                                        - At least 8 characters
                                        - Maximum 80 characters
                                        - Contains digits, uppercase and lowercase letters
                                        - All characters are valid ASCII
                                        - At least one special character
                                """,
                        "Invalid Password", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }

        try {
            // Generate a random symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
            keyGen.init(KEY_SIZE, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();

            // Convert password to bytes
            byte[] passwordBytes = new byte[password.length * 2];
            for (int i = 0; i < password.length; i++) {
                passwordBytes[i * 2] = (byte) (password[i] >> 8);
                passwordBytes[i * 2 + 1] = (byte) password[i];
            }

            // Encrypt the password
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Store the encrypted password and key in memory
            this.encryptedPassword = cipher.doFinal(passwordBytes);
            this.encryptionKey = secretKey.getEncoded();

            LOG.debug("Password encrypted and stored in memory successfully");
            return true;
        } catch (Exception e) {
            LOG.error("Error encrypting and storing password", e);
            return false;
        }
    }

    /**
     * Retrieves and decrypts the stored password.
     *
     * @return the decrypted password as a char array
     * @throws IllegalStateException if no password is stored
     * @throws GeneralSecurityException if decryption fails
     */
    public char[] getPassword() throws GeneralSecurityException {
        if (encryptedPassword == null || encryptionKey == null) {
            throw new IllegalStateException("No password stored in memory");
        }

        // Recreate the secret key
        SecretKey secretKey = new SecretKeySpec(encryptionKey, ENCRYPTION_ALGORITHM);

        // Decrypt the password
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] passwordBytes = cipher.doFinal(encryptedPassword);

        // Convert bytes back to char array
        char[] password = new char[passwordBytes.length / 2];
        for (int i = 0; i < password.length; i++) {
            password[i] = (char) ((passwordBytes[i * 2] << 8) | (passwordBytes[i * 2 + 1] & 0xFF));
        }

        LOG.debug("Password retrieved and decrypted successfully from memory");
        return password;
    }

    /**
     * Gets the stored keystore path from preferences or returns a default path if none is stored.
     *
     * @return the stored keystore path or a default path
     */
    private Path getStoredKeystorePath() {
        Preferences prefs = Preferences.userNodeForPackage(KeystoreManager.class);
        String storedPath = prefs.get(PREF_KEYSTORE_PATH, null);
        return storedPath != null ? Paths.get(storedPath) : Paths.get(".");
    }

    /**
     * Saves the keystore path to preferences.
     *
     * @param path the path to save
     */
    private void saveKeystorePath(Path path) {
        if (path != null) {
            Preferences prefs = Preferences.userNodeForPackage(KeystoreManager.class);
            prefs.put(PREF_KEYSTORE_PATH, path.toString());
        }
    }

    private void setKeystore(Path keystorePath, KeyStore keyStore, char[] keyStorePassword) {
        this.keystorePath = keystorePath;
        this.keyStore = keyStore;
        this.encryptedPassword = null;
        saveKeystorePath(keystorePath);
    }

    /**
     * Validates a password against security requirements.
     * 
     * @param password the password to validate
     * @return a validation result containing success status and error message if any
     */
    public static PasswordValidationResult validatePassword(char[] password) {
        if (password == null || password.length == 0) {
            return new PasswordValidationResult(false, "Password cannot be empty");
        }

        // Check length requirements
        if (password.length < 8) {
            return new PasswordValidationResult(false, "Password must be at least 8 characters long");
        }

        if (password.length > 80) {
            return new PasswordValidationResult(false, "Password cannot exceed 80 characters");
        }

        boolean hasDigit = false;
        boolean hasUpperCase = false;
        boolean hasLowerCase = false;
        boolean hasSpecialChar = false;

        // Check character requirements
        for (char c : password) {
            // Check if all characters are valid ASCII
            if (c > 127) {
                return new PasswordValidationResult(false, "Password must contain only ASCII characters");
            }

            if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (Character.isUpperCase(c)) {
                hasUpperCase = true;
            } else if (Character.isLowerCase(c)) {
                hasLowerCase = true;
            } else if (isPunctuation(c) || c == '+' || c == '-' || c == '$' || c == '@' || c == '!' || c == '%' || c == '&' || c == '*' || c == '=' || c == '_') {
                hasSpecialChar = true;
            }
        }

        if (!hasDigit) {
            return new PasswordValidationResult(false, "Password must contain at least one digit");
        }

        if (!hasUpperCase) {
            return new PasswordValidationResult(false, "Password must contain at least one uppercase letter");
        }

        if (!hasLowerCase) {
            return new PasswordValidationResult(false, "Password must contain at least one lowercase letter");
        }

        if (!hasSpecialChar) {
            return new PasswordValidationResult(false, "Password must contain at least one special character (punctuation, +, -, $, etc)");
        }

        return new PasswordValidationResult(true, null);
    }

    /**
     * Helper method to check if a character is a punctuation symbol.
     */
    private static boolean isPunctuation(char c) {
        return (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || 
               (c >= 91 && c <= 96) || (c >= 123 && c <= 126);
    }

    /**
     * Class to hold password validation results.
     */
    public static class PasswordValidationResult {
        private final boolean valid;
        private final String errorMessage;

        public PasswordValidationResult(boolean valid, String errorMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
        }

        public boolean isValid() {
            return valid;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Gets the keystore that was loaded or created.
     *
     * @return the keystore
     */
    public KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * Gets the path of the keystore that was loaded or created.
     *
     * @return the keystore path
     */
    public Path getKeystorePath() {
        return keystorePath;
    }

    /**
     * Gets the password for the keystore.
     *
     * @return the keystore password
     * @throws GeneralSecurityException if there's a security-related error
     */
    public char[] getKeystorePassword() throws GeneralSecurityException {
        return getPassword();
    }
}
