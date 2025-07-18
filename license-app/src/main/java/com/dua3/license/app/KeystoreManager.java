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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import java.awt.Component;
import java.io.IOException;
import java.net.URL;
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
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String PREF_KEYSTORE_PATH = "keystorePath";
    private static final String PREF_ENCRYPTION_KEY = "encryptionKey";
    private static final String PREF_IV = "iv";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int KEY_SIZE = 256;
    private static final String ERROR = "Error";
    private static final String LOGO_PATH_64 = "/com/dua3/license/app/Keytool-64.png";
    private static final String LOGO_PATH_128 = "/com/dua3/license/app/Keytool-128.png";
    private static final String LOGO_PATH_256 = "/com/dua3/license/app/Keytool-256.png";
    private static final String LOGO_PATH_512 = "/com/dua3/license/app/Keytool-512.png";
    private byte[] iv;

    /**
     * Gets the appropriate logo icon based on the screen resolution.
     *
     * @return the logo icon
     */
    private ImageIcon getLogoIcon() {
        // Get the screen resolution
        int screenResolution = java.awt.Toolkit.getDefaultToolkit().getScreenResolution();

        // Choose the appropriate logo size based on the screen resolution
        String logoPath;
        if (screenResolution > 200) {
            logoPath = LOGO_PATH_512;
        } else if (screenResolution > 120) {
            logoPath = LOGO_PATH_256;
        } else if (screenResolution > 80) {
            logoPath = LOGO_PATH_128;
        } else {
            logoPath = LOGO_PATH_64;
        }

        // Load the logo
        URL logoUrl = KeystoreManager.class.getResource(logoPath);
        if (logoUrl != null) {
            return new ImageIcon(logoUrl);
        } else {
            LOG.warn("Could not load logo from path: {}", logoPath);
            return null;
        }
    }

    /**
     * Creates a panel with the logo icon centered horizontally and the specified message below it.
     * 
     * @param message the message to display below the icon, can be a string or a component
     * @return a panel with the centered logo icon and message
     */
    private JPanel createCenteredLogoPanel(Object message) {
        ImageIcon icon = getLogoIcon();
        JPanel panel = new JPanel(new MigLayout("fillx, wrap 1, insets 10", "[center]", "[][]"));

        // Add the icon at the top, centered
        if (icon != null) {
            JLabel iconLabel = new JLabel(icon);
            panel.add(iconLabel, "center, wrap");
        }

        // Add the message below the icon
        if (message != null) {
            if (message instanceof Component component) {
                panel.add(component, "growx");
            } else {
                panel.add(new JLabel(message.toString()), "center");
            }
        }

        return panel;
    }

    /**
     * Constructs an instance of KeystoreManager.
     */
    public KeystoreManager() { /* nothing to do */ }

    /**
     * Enum to specify the mode of the keystore dialog.
     */
    public enum DialogMode {
        /**
         * Specifies the mode for loading an existing keystore in the dialog.
         */
        LOAD_EXISTING,
        /**
         * Specifies the mode for creating a new keystore in the dialog.
         */
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

        do {
            // Create a panel for error message if needed
            JPanel messagePanel = null;
            if (errorMessage != null) {
                messagePanel = new JPanel(new MigLayout("fill, insets 0", "[grow]", "[]"));
                JLabel errorLabel = new JLabel("<html><font color='red'>Error: " + errorMessage + "</font></html>");
                messagePanel.add(errorLabel, "wrap");
            }

            // Create a panel with centered logo and message
            JPanel panel = createCenteredLogoPanel(messagePanel);

            // Only show "Load Keystore" and "New Keystore" buttons
            String[] options = new String[]{"Load Keystore", "New Keystore"};
            String defaultOption = "Load Keystore";

            int option = JOptionPane.showOptionDialog(
                    parent,
                    panel,
                    "Keystore Selection",
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                    null, // No icon since we're including it in the panel
                    options,
                    defaultOption
            );

            // Process the user's choice
            switch (option) {
                case 0 -> {
                    // Load existing keystore
                    LOG.debug("User chose to load an existing keystore");
                    boolean success = showLoadCreateKeystoreDialog(parent, DialogMode.LOAD_EXISTING);
                    if (success) {
                        return true; // Successfully loaded
                    } else {
                        // Get the error message from the dialog
                        errorMessage = "Failed to load keystore. Please check the path and password.";
                    }
                }
                case 1 -> {
                    // Create new keystore
                    LOG.debug("User chose to create a new keystore");
                    boolean success = showLoadCreateKeystoreDialog(parent, DialogMode.CREATE_NEW);
                    if (success) {
                        return true; // Successfully created
                    } else {
                        // Get the error message from the dialog
                        errorMessage = "Failed to create keystore. Please check the path and password.";
                    }
                }
                default -> {
                    // User chose to cancel or quit
                    return false;
                }
            }

        } while (true);
    }

    /**
     * Shows a dialog for loading or creating a keystore.
     *
     * @param parent the parent component
     * @param mode the dialog mode (LOAD_EXISTING or CREATE_NEW)
     * @return true if successful, false otherwise
     */
    private boolean showLoadCreateKeystoreDialog(Component parent, DialogMode mode) {
        String modeString = mode == DialogMode.LOAD_EXISTING ? "loading" : "creating";
        LOG.debug("Showing {} keystore dialog", modeString);

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
            LOG.warn("No keystore path specified for {}", modeString);
            JOptionPane.showMessageDialog(parent, createCenteredLogoPanel("Please specify a keystore path."), ERROR, JOptionPane.PLAIN_MESSAGE, null);
            return false;
        }

        //
        Path path = selectedPath.get();
        LOG.debug("Selected path for {} keystore: {}", modeString, path);

        // For new keystores, check if file exists and confirm overwrite
        if (mode == DialogMode.CREATE_NEW && Files.exists(path)) {
            LOG.debug("Keystore file already exists at path: {}", path);
            int choice = JOptionPane.showConfirmDialog(
                    parent,
                    createCenteredLogoPanel("The keystore file already exists. Do you want to overwrite it?"),
                    "File Exists",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.PLAIN_MESSAGE,
                    null
            );

            if (choice != JOptionPane.YES_OPTION) {
                LOG.debug("User chose not to overwrite existing keystore file");
                // Ask for a new filename
                FileInput newPathInput = new FileInput(FileInput.SelectionMode.SELECT_FILE, path, 20);
                int newResult = JOptionPane.showConfirmDialog(
                        parent,
                        createCenteredLogoPanel(newPathInput),
                        "Enter a new keystore path",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.PLAIN_MESSAGE,
                        null
                );

                Optional<Path> optionalPath = newPathInput.getPath();
                if (newResult == JOptionPane.OK_OPTION && optionalPath.isPresent()) {
                    path = optionalPath.get();
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
                createCenteredLogoPanel(passwordPanel),
                passwordDialogTitle,
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE,
                null
        );

        if (passwordResult != JOptionPane.OK_OPTION) {
            LOG.debug("User cancelled password entry for {} keystore", modeString);
            return false;
        }

        // For new keystores, verify that passwords match
        if (confirmPasswordField != null) {
            char[] password = keystorePasswordField.getPassword();
            char[] confirmPassword = confirmPasswordField.getPassword();

            if (!java.util.Arrays.equals(password, confirmPassword)) {
                LOG.debug("Passwords do not match for new keystore creation");
                JOptionPane.showMessageDialog(parent,
                        createCenteredLogoPanel("Passwords do not match. Please try again."),
                        "Password Mismatch",
                        JOptionPane.PLAIN_MESSAGE,
                        null);
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
                JOptionPane.showMessageDialog(parent, createCenteredLogoPanel("Error loading keystore: " + e.getMessage()), ERROR, JOptionPane.PLAIN_MESSAGE, null);
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
                JOptionPane.showMessageDialog(parent, createCenteredLogoPanel("Error creating keystore: " + e.getMessage()), ERROR, JOptionPane.PLAIN_MESSAGE, null);
                return false;
            }
        }
    }

    private boolean storePassword(char[] password, DialogMode mode) {
        // Validate password only when creating a new keystore
        if (mode == DialogMode.CREATE_NEW) {
            PasswordValidationResult validationResult = validatePassword(password);
            if (!validationResult.valid()) {
                JOptionPane.showMessageDialog(null,
                        createCenteredLogoPanel(validationResult.errorMessage() + """
                                
                                
                                        Password requirements:
                                        - At least 8 characters
                                        - Maximum 80 characters
                                        - Contains digits, uppercase and lowercase letters
                                        - All characters are valid ASCII
                                        - At least one special character
                                """),
                        "Invalid Password", JOptionPane.PLAIN_MESSAGE, null);
                return false;
            }
        }

        try {
            // Generate a random symmetric key
            KeyGenerator keyGen = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
            keyGen.init(KEY_SIZE, SECURE_RANDOM);
            SecretKey secretKey = keyGen.generateKey();

            // Convert password to bytes
            byte[] passwordBytes = new byte[password.length * 2];
            for (int i = 0; i < password.length; i++) {
                passwordBytes[i * 2] = (byte) (password[i] >> 8);
                passwordBytes[i * 2 + 1] = (byte) password[i];
            }

            // Generate random IV for GCM
            byte[] ivBytes = new byte[GCM_IV_LENGTH];
            SECURE_RANDOM.nextBytes(ivBytes);

            // Encrypt the password using GCM mode
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes); // 128-bit tag
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

            // Store the encrypted password, key, and IV in memory
            this.encryptedPassword = cipher.doFinal(passwordBytes);
            this.encryptionKey = secretKey.getEncoded();
            this.iv = ivBytes;

            // Persist the encryption key and IV in preferences
            Preferences prefs = Preferences.userNodeForPackage(KeystoreManager.class);
            prefs.putByteArray(PREF_ENCRYPTION_KEY, encryptionKey);
            prefs.putByteArray(PREF_IV, iv);

            LOG.debug("Password encrypted and stored successfully");
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
        // Try to load encryption key and IV from preferences if not available in memory
        if (encryptionKey == null || iv == null) {
            Preferences prefs = Preferences.userNodeForPackage(KeystoreManager.class);
            encryptionKey = prefs.getByteArray(PREF_ENCRYPTION_KEY, null);
            iv = prefs.getByteArray(PREF_IV, null);
            
            if (encryptionKey == null || iv == null) {
                LOG.warn("Could not retrieve encryption key or IV from preferences");
                throw new IllegalStateException("No encryption data available");
            }
            
            LOG.debug("Retrieved encryption key and IV from preferences");
        }
        
        // If we don't have the encrypted password in memory, prompt the user to re-enter it
        if (encryptedPassword == null) {
            LOG.info("No encrypted password stored in memory, prompting user to re-enter");
            return promptForPasswordAndStore();
        }

        try {
            // Recreate the secret key
            SecretKey secretKey = new SecretKeySpec(encryptionKey, ENCRYPTION_ALGORITHM);

            // Decrypt the password using GCM mode
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            byte[] passwordBytes = cipher.doFinal(encryptedPassword);

            // Convert bytes back to char array
            char[] password = new char[passwordBytes.length / 2];
            for (int i = 0; i < password.length; i++) {
                password[i] = (char) ((passwordBytes[i * 2] << 8) | (passwordBytes[i * 2 + 1] & 0xFF));
            }

            LOG.debug("Password retrieved and decrypted successfully");
            return password;
        } catch (GeneralSecurityException e) {
            LOG.error("Failed to decrypt password", e);
            
            // Clear the stored encryption data to force re-entry of password
            encryptedPassword = null;
            encryptionKey = null;
            iv = null;
            
            // Clear preferences as well
            Preferences prefs = Preferences.userNodeForPackage(KeystoreManager.class);
            prefs.remove(PREF_ENCRYPTION_KEY);
            prefs.remove(PREF_IV);
            
            throw new GeneralSecurityException("Failed to decrypt password. Please re-enter your password.", e);
        }
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
     * Represents the result of a password validation process.
     * @param valid a boolean indicating whether the password is considered valid.
     * @param errorMessage string containing an error message if the password is invalid,
     */
    public record PasswordValidationResult(boolean valid, String errorMessage) {
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
    
    /**
     * Prompts the user to enter their password and stores it.
     * This is used when the encrypted password is not available in memory.
     *
     * @return the entered password
     * @throws GeneralSecurityException if there's a security-related error
     */
    private char[] promptForPasswordAndStore() throws GeneralSecurityException {
        JPanel panel = new JPanel(new MigLayout("fillx, wrap 1", "[grow]", "[][]"));
        JLabel label = new JLabel("Please enter your keystore password:");
        JPasswordField passwordField = new JPasswordField(20);
        
        panel.add(label);
        panel.add(passwordField, "growx");
        
        int result = JOptionPane.showConfirmDialog(
                null, 
                createCenteredLogoPanel(panel),
                "Password Required", 
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        
        if (result != JOptionPane.OK_OPTION) {
            throw new IllegalStateException("Password entry cancelled by user");
        }
        
        char[] password = passwordField.getPassword();
        
        // Store the password
        if (!storePassword(password, DialogMode.LOAD_EXISTING)) {
            throw new GeneralSecurityException("Failed to store password");
        }
        
        return password;
    }
}
