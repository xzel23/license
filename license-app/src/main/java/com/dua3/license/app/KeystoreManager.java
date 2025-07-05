package com.dua3.license.app;

import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.swing.FileInput;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
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
import java.util.prefs.Preferences;

/**
 * Dialog for selecting or creating a keystore.
 */
public class KeystoreManager {
    private static final Logger LOG = LogManager.getLogger(KeystoreManager.class);
    private static final String PREF_KEYSTORE_PATH = "keystorePath";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    @Nullable private FileInput keyStorePathInput;
    @Nullable private JPasswordField keystorePasswordField;
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
            // Create the panel for keystore input
            JPanel panel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]10[]10[]"));

            // Keystore path
            panel.add(new JLabel("Keystore Path:"));
            Path defaultPath = getStoredKeystorePath();
            keyStorePathInput = new FileInput(FileInput.SelectionMode.SELECT_FILE, defaultPath, 20);
            panel.add(keyStorePathInput, "growx, wrap");

            // Keystore password
            panel.add(new JLabel("Keystore Password:"));
            keystorePasswordField = new JPasswordField(20);
            panel.add(keystorePasswordField, "growx, wrap");

            // Add error message if there was an error
            if (errorMessage != null) {
                JLabel errorLabel = new JLabel("<html><font color='red'>Error: " + errorMessage + "</font></html>");
                panel.add(errorLabel, "span 2, wrap");
            }

            // Determine dialog options based on whether there was an error
            String[] options;
            String defaultOption;

            if (errorMessage != null) {
                // If there was an error, show options with error message displayed
                options = new String[]{"Load Existing Keystore", "Create New Keystore", "Cancel"};
                defaultOption = "Load Existing Keystore";
            } else {
                // Initial dialog with standard options
                options = new String[]{"Load Existing Keystore", "Create New Keystore", "Cancel"};
                defaultOption = "Load Existing Keystore";
            }

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
                LOG.debug("Attempting to load keystore from dialog");
                boolean success = keyStorePathInput.getPath().map(path -> {
                    LOG.debug("Loading keystore from path: {}", path);
                    readAndStorePassword();

                    try {
                        KeyStore loadedKeyStore = KeyStoreUtil.loadKeyStoreFromFile(path, getPassword());

                        // Store the keystore path and instance
                        this.keystorePath = path;
                        this.keyStore = loadedKeyStore;

                        LOG.debug("Keystore loaded successfully from: {}", path);
                        return true;
                    } catch (GeneralSecurityException | IOException e) {
                        LOG.warn("Error loading keystore from path: {}", path, e);
                        return false;
                    }
                }).orElseGet(() -> {
                    LOG.warn("No keystore path specified for loading");
                    JOptionPane.showMessageDialog(parent, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
                    return false;
                });
                if (success) {
                    return true; // Successfully loaded
                } else {
                    // Get the error message from the dialog
                    errorMessage = "Failed to load keystore. Please check the path and password.";
                    retry = true; // Try again
                }
            } else if (option == 1) {
                // Create new keystore
                boolean success = createKeystoreFromDialog(parent);
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
     * Creates a new keystore from the dialog input.
     *
     * @param parent the parent component
     * @return true if successful, false otherwise
     */
    private boolean createKeystoreFromDialog(Component parent) {
        LOG.debug("Attempting to create keystore from dialog");
        return keyStorePathInput.getPath().map(path -> {
            LOG.debug("Creating keystore at path: {}", path);
            readAndStorePassword();

            // Check if file exists
            if (Files.exists(path)) {
                LOG.debug("Keystore file already exists at path: {}", path);
                int choice = JOptionPane.showConfirmDialog(null, "The keystore file already exists. Do you want to overwrite it?", "File Exists", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

                if (choice != JOptionPane.YES_OPTION) {
                    LOG.debug("User chose not to overwrite existing keystore file");
                    // Ask for a new filename
                    FileInput newPathInput = new FileInput(FileInput.SelectionMode.SELECT_FILE, path, 20);
                    int result = JOptionPane.showConfirmDialog(null, newPathInput, "Enter a new keystore path", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);

                    if (result == JOptionPane.OK_OPTION && newPathInput.getPath().isPresent()) {
                        path = newPathInput.getPath().get();
                        LOG.debug("User provided new keystore path: {}", path);
                    } else {
                        LOG.debug("User cancelled keystore creation");
                        return false;
                    }
                }
            }

            try {
                // Create a new KeyStore instance directly
                KeyStore newKeyStore = KeyStore.getInstance("PKCS12");
                newKeyStore.load(null, getPassword());

                // No need to backup here as this is a new keystore
                KeyStoreUtil.saveKeyStoreToFile(newKeyStore, path, getPassword());
                this.keystorePath = path;
                this.keyStore = newKeyStore;

                LOG.debug("Keystore created successfully at: {}", path);
                return true;
            } catch (GeneralSecurityException | IOException e) {
                LOG.warn("Error creating keystore at path: {}", path, e);
                JOptionPane.showMessageDialog(parent, "Error creating keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }).orElseGet(() -> {
            LOG.warn("No keystore path specified for creation");
            JOptionPane.showMessageDialog(parent, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        });
    }

    private void readAndStorePassword() {
        char[] password = keystorePasswordField.getPassword();
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
        } catch (Exception e) {
            LOG.error("Error encrypting and storing password", e);
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
