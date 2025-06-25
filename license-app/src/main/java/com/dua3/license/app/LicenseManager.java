package com.dua3.license.app;

import com.dua3.utility.crypt.AsymmetricAlgorithm;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.swing.FileInput;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.prefs.Preferences;

public class LicenseManager {

    private static final Logger LOG = LogManager.getLogger(LicenseManager.class);
    private static final String APP_NAME = LicenseManager.class.getSimpleName();
    private static final String PREF_KEYSTORE_PATH = "keystorePath";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    // In-memory storage for encrypted password and encryption key
    private byte[] encryptedPassword;
    private byte[] encryptionKey;

    static {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Exception e) {
            System.err.println("Failed to register Bouncy Castle provider: " + e.getMessage());
        }
    }

    private JFrame mainFrame;
    private JTabbedPane tabbedPane;
    private JPanel keysPanel;
    private JPanel licensesPanel;

    private FileInput keyStorePathInput;
    private JPasswordField keystorePasswordField;
    private JTextField keyAliasField;
    private JTextField keySubjectField;
    private JTextField keyValidDaysField;

    private final JComboBox<String> licenseKeyAliasComboBox = new JComboBox<>();
    private JPanel licenseFieldsPanel;
    private final List<JTextField[]> licenseFieldRows = new ArrayList<>();

    private JTextArea licenseOutputArea;
    private JTextArea verificationOutputArea;

    // Table for displaying keys
    private javax.swing.JTable keysTable;
    private javax.swing.table.DefaultTableModel keysTableModel;

    private KeyStore keyStore;
    private Path keystorePath;

    public static void main(String[] args) {
        LOG.debug("Starting License Manager application");
        SwingUtil.setNativeLookAndFeel(APP_NAME);
        SwingUtilities.invokeLater(() -> {
            LicenseManager app = new LicenseManager();
            app.createAndShowGUI();
        });
    }

    private void createAndShowGUI() {
        LOG.debug("Creating and showing GUI");
        // Show startup dialog to load or create keystore
        if (!showKeystoreStartupDialog()) {
            // User chose to exit
            LOG.info("User chose to exit after keystore loading failure");
            System.exit(0);
            return;
        }

        LOG.debug("Keystore loaded successfully, initializing main window");
        mainFrame = new JFrame(APP_NAME);
        mainFrame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        mainFrame.setSize(800, 600);

        tabbedPane = new JTabbedPane();

        // Create panels for each tab
        createKeysPanel();
        createLicensesPanel();

        // Add the new tabs as required
        tabbedPane.addTab("Keys", keysPanel);
        tabbedPane.addTab("Licenses", licensesPanel);

        mainFrame.getContentPane().add(tabbedPane, BorderLayout.CENTER);

        mainFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                // Clean up resources if needed
                System.exit(0);
            }
        });

        mainFrame.setLocationRelativeTo(null);
        mainFrame.setVisible(true);
    }

    /**
     * Creates the Keys panel with a table showing key information.
     */
    private void createKeysPanel() {
        keysPanel = new JPanel(new BorderLayout(10, 10));
        keysPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create table model with columns for key information
        String[] columnNames = {"Alias", "Algorithm", "Key Size", "Certificate Subject", "Public Key", ""};
        keysTableModel = new javax.swing.table.DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // Only the last column (button column) is editable
                return column == 5;
            }
        };

        // Create table
        keysTable = new javax.swing.JTable(keysTableModel);
        keysTable.setFillsViewportHeight(true);
        keysTable.setRowHeight(25);

        // Set column widths
        keysTable.getColumnModel().getColumn(0).setPreferredWidth(100); // Alias
        keysTable.getColumnModel().getColumn(1).setPreferredWidth(80);  // Algorithm
        keysTable.getColumnModel().getColumn(2).setPreferredWidth(60);  // Key Size
        keysTable.getColumnModel().getColumn(3).setPreferredWidth(200); // Certificate Subject
        keysTable.getColumnModel().getColumn(4).setPreferredWidth(300); // Public Key
        keysTable.getColumnModel().getColumn(5).setPreferredWidth(100); // Button column

        // Add tooltips to show full text when it doesn't fit
        keysTable.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            @Override
            public void mouseMoved(java.awt.event.MouseEvent e) {
                int row = keysTable.rowAtPoint(e.getPoint());
                int col = keysTable.columnAtPoint(e.getPoint());
                if (row >= 0 && col >= 0) {
                    Object value = keysTable.getValueAt(row, col);
                    if (value != null) {
                        keysTable.setToolTipText(value.toString());
                    } else {
                        keysTable.setToolTipText(null);
                    }
                }
            }
        });

        // Add button renderer and editor for the last column
        keysTable.getColumnModel().getColumn(5).setCellRenderer(new javax.swing.table.TableCellRenderer() {
            @Override
            public java.awt.Component getTableCellRendererComponent(javax.swing.JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JButton button = new JButton("Show Private Key");
                return button;
            }
        });

        keysTable.getColumnModel().getColumn(5).setCellEditor(new javax.swing.DefaultCellEditor(new JTextField()) {
            private final JButton button = new JButton("Show Private Key");

            {
                button.addActionListener(e -> {
                    fireEditingStopped();
                    int row = keysTable.getSelectedRow();
                    if (row >= 0) {
                        String alias = (String) keysTable.getValueAt(row, 0);
                        showPrivateKey(alias);
                    }
                });
            }

            @Override
            public java.awt.Component getTableCellEditorComponent(javax.swing.JTable table, Object value, boolean isSelected, int row, int column) {
                return button;
            }
        });

        // Add table to scroll pane
        JScrollPane scrollPane = new JScrollPane(keysTable);
        keysPanel.add(scrollPane, BorderLayout.CENTER);

        // Add buttons
        JButton refreshButton = new JButton("Refresh Keys");
        refreshButton.addActionListener(e -> updateKeysTable());

        JButton addKeyButton = new JButton("Add Key");
        addKeyButton.addActionListener(e -> {
            // Reuse the key generation functionality from the Key Management tab
            if (keyStore == null) {
                JOptionPane.showMessageDialog(mainFrame, "Please load or create a keystore first.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Show a dialog to get key information
            JTextField aliasField = new JTextField(20);
            JTextField subjectField = new JTextField("CN=License Key, O=Your Organization, L=Your City, ST=Your State, C=Your Country", 20);
            JTextField validDaysField = new JTextField("3650", 5);

            JPanel panel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]10[]10[]"));
            panel.add(new JLabel("Key Alias:"));
            panel.add(aliasField, "growx, wrap");
            panel.add(new JLabel("Key Subject:"));
            panel.add(subjectField, "growx, wrap");
            panel.add(new JLabel("Valid Days:"));
            panel.add(validDaysField, "growx");

            int result = JOptionPane.showConfirmDialog(mainFrame, panel, "Add New Key", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (result == JOptionPane.OK_OPTION) {
                String alias = aliasField.getText().trim();
                String subject = subjectField.getText().trim();
                String validDaysStr = validDaysField.getText().trim();

                if (alias.isEmpty()) {
                    JOptionPane.showMessageDialog(mainFrame, "Please specify a key alias.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                if (subject.isEmpty()) {
                    JOptionPane.showMessageDialog(mainFrame, "Please specify a key subject.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                int validDays;
                try {
                    validDays = Integer.parseInt(validDaysStr);
                    if (validDays <= 0) {
                        throw new NumberFormatException("Valid days must be positive");
                    }
                } catch (NumberFormatException e1) {
                    JOptionPane.showMessageDialog(mainFrame, "Please enter a valid number of days.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                try {
                    KeyStoreUtil.generateAndStoreKeyPairWithX509Certificate(keyStore, alias, AsymmetricAlgorithm.RSA, 2048, getPassword(), subject, validDays);

                    // Backup the keystore file before saving
                    backupKeystoreFile(keystorePath);

                    KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, getPassword());

                    updateKeyAliasComboBox();

                    JOptionPane.showMessageDialog(mainFrame, "Key pair generated and stored successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                } catch (GeneralSecurityException | IOException ex) {
                    LOG.warn("Error generating key pair", ex);
                    JOptionPane.showMessageDialog(mainFrame, "Error generating key pair: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        JButton deleteKeyButton = new JButton("Delete Key");
        deleteKeyButton.addActionListener(e -> {
            if (keyStore == null) {
                JOptionPane.showMessageDialog(mainFrame, "Please load or create a keystore first.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            int row = keysTable.getSelectedRow();
            if (row < 0) {
                JOptionPane.showMessageDialog(mainFrame, "Please select a key to delete.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String alias = (String) keysTable.getValueAt(row, 0);

            // Ask user to type the exact alias for confirmation
            String input = JOptionPane.showInputDialog(mainFrame, "To confirm deletion, please type the exact alias of the key: " + alias, "Confirm Deletion", JOptionPane.WARNING_MESSAGE);

            if (input != null && input.equals(alias)) {
                try {
                    // Use the stored password if available, otherwise prompt the user
                    deleteKey(alias);
                    JOptionPane.showMessageDialog(mainFrame, "Key deleted successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    LOG.warn("Error deleting key", ex);
                    JOptionPane.showMessageDialog(mainFrame, "Error deleting key: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else if (input != null) {
                JOptionPane.showMessageDialog(mainFrame, "The alias you entered does not match. Deletion cancelled.", "Deletion Cancelled", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(addKeyButton);
        buttonPanel.add(deleteKeyButton);
        buttonPanel.add(refreshButton);
        keysPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Initial population of the table
        updateKeysTable();
    }

    /**
     * Updates the keys table with the current keystore information.
     */
    private void updateKeysTable() {
        // Clear the table
        keysTableModel.setRowCount(0);

        if (keyStore == null) {
            return;
        }

        try {
            keyStore.aliases().asIterator().forEachRemaining(alias -> {
                try {
                    if (keyStore.isKeyEntry(alias)) {
                        // Get certificate information
                        java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                        String algorithm = "N/A";
                        int keySize = 0;
                        String subject = "N/A";
                        String publicKeyString = "N/A";

                        if (cert != null) {
                            PublicKey publicKey = cert.getPublicKey();
                            algorithm = publicKey.getAlgorithm();

                            // Estimate key size
                            if (publicKey instanceof java.security.interfaces.RSAKey) {
                                keySize = ((java.security.interfaces.RSAKey) publicKey).getModulus().bitLength();
                            } else if (publicKey instanceof java.security.interfaces.DSAKey) {
                                keySize = ((java.security.interfaces.DSAKey) publicKey).getParams().getP().bitLength();
                            } else if (publicKey instanceof java.security.interfaces.ECKey) {
                                keySize = ((java.security.interfaces.ECKey) publicKey).getParams().getCurve().getField().getFieldSize();
                            }

                            // Get subject from X509Certificate
                            if (cert instanceof java.security.cert.X509Certificate) {
                                subject = ((java.security.cert.X509Certificate) cert).getSubjectX500Principal().getName();
                            }

                            // Format public key as Base64
                            publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
                            if (publicKeyString.length() > 30) {
                                publicKeyString = publicKeyString.substring(0, 27) + "...";
                            }
                        }

                        // Add row to table
                        keysTableModel.addRow(new Object[]{alias, algorithm, keySize > 0 ? String.valueOf(keySize) : "N/A", subject, publicKeyString, ""  // Button placeholder
                        });
                    }
                } catch (Exception e) {
                    // Skip this alias if there's an error
                    LOG.warn("Error processing key alias: {}", alias, e);
                }
            });
        } catch (Exception e) {
            LOG.warn("Error loading key information", e);
            JOptionPane.showMessageDialog(mainFrame, "Error loading key information: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Shows the private key for the given alias after password verification.
     *
     * @param alias the key alias
     */
    private void showPrivateKey(String alias) {
        LOG.debug("Attempting to show private key for alias: {}", alias);
        if (keyStore == null) {
            LOG.warn("Attempted to show private key but no keystore is loaded");
            JOptionPane.showMessageDialog(mainFrame, "No keystore loaded.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            // Get the private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, getPassword());
            if (privateKey == null) {
                JOptionPane.showMessageDialog(mainFrame, "No private key found for alias: " + alias, "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Display the private key
            String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            JTextArea textArea = new JTextArea(10, 40);
            textArea.setText(privateKeyString);
            textArea.setEditable(false);
            textArea.setLineWrap(true);
            textArea.setWrapStyleWord(true);

            JScrollPane scrollPane = new JScrollPane(textArea);
            JOptionPane.showMessageDialog(mainFrame, scrollPane, "Private Key for " + alias, JOptionPane.INFORMATION_MESSAGE);

        } catch (GeneralSecurityException e) {
            LOG.warn("Error retrieving private key for alias: {}", alias, e);
            JOptionPane.showMessageDialog(mainFrame, "Error retrieving private key: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Creates the Licenses panel (placeholder for now).
     */
    private void createLicensesPanel() {
        licensesPanel = new JPanel(new BorderLayout());
        licensesPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel placeholderLabel = new JLabel("Licenses tab content will be filled in later.", SwingConstants.CENTER);
        placeholderLabel.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 16));
        licensesPanel.add(placeholderLabel, BorderLayout.CENTER);
    }

    /**
     * Shows a dialog at startup that asks the user to either load an existing keystore or create a new one.
     * If there's an error, it shows the error message and asks if the user wants to try again.
     *
     * @return true if a keystore was successfully loaded or created, false otherwise
     */
    private boolean showKeystoreStartupDialog() {
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
                null, 
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
                        keyStore = KeyStoreUtil.loadKeyStoreFromFile(path, getPassword());
                        setKeystorePath(path);

                        LOG.debug("Keystore loaded successfully from: {}", path);
                        return true;
                    } catch (GeneralSecurityException | IOException e) {
                        LOG.warn("Error loading keystore from path: {}", path, e);
                        return false;
                    }
                }).orElseGet(() -> {
                    LOG.warn("No keystore path specified for loading");
                    JOptionPane.showMessageDialog(null, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
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
                boolean success = createKeystoreFromDialog();
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
     * Creates a new keystore from the dialog input.
     *
     * @return true if successful, false otherwise
     */
    private boolean createKeystoreFromDialog() {
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
                keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, getPassword());

                // No need to backup here as this is a new keystore
                KeyStoreUtil.saveKeyStoreToFile(keyStore, path, getPassword());
                setKeystorePath(path);

                LOG.debug("Keystore created successfully at: {}", path);
                return true;
            } catch (GeneralSecurityException | IOException e) {
                LOG.warn("Error creating keystore at path: {}", path, e);
                JOptionPane.showMessageDialog(null, "Error creating keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }).orElseGet(() -> {
            LOG.warn("No keystore path specified for creation");
            JOptionPane.showMessageDialog(null, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        });
    }

    private void setKeystorePath(Path keystorePath) {
        this.keystorePath = keystorePath;
        saveKeystorePath(keystorePath);
    }

    private void updateKeyAliasComboBox() {
        LOG.debug("Updating key alias combo box");
        if (keyStore == null) {
            LOG.debug("No keystore loaded, skipping key alias update");
            return;
        }

        licenseKeyAliasComboBox.removeAllItems();

        try {
            keyStore.aliases().asIterator().forEachRemaining(alias -> {
                try {
                    if (keyStore.isKeyEntry(alias)) {
                        licenseKeyAliasComboBox.addItem(alias);
                    }
                } catch (Exception e) {
                    // Skip this alias if there's an error
                    LOG.warn("Error processing key alias for combo box: {}", alias, e);
                }
            });
        } catch (Exception e) {
            LOG.warn("Error loading key aliases", e);
            JOptionPane.showMessageDialog(mainFrame, "Error loading key aliases: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }

        // Update the keys table as well
        updateKeysTable();
    }

    /**
     * Gets the stored keystore path from preferences or returns a default path if none is stored.
     *
     * @return the stored keystore path or a default path
     */
    private Path getStoredKeystorePath() {
        Preferences prefs = Preferences.userNodeForPackage(LicenseManager.class);
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
            Preferences prefs = Preferences.userNodeForPackage(LicenseManager.class);
            prefs.put(PREF_KEYSTORE_PATH, path.toString());
        }
    }

    /**
     * Encrypts the keystore password and stores it in memory.
     *
     * @param password the password to encrypt and store
     */
    private void encryptAndStorePassword(char[] password) {
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
     * @return the decrypted password as a char array, or null if no password is stored or decryption fails
     */
    private char[] getPassword() {
        try {
            if (encryptedPassword == null || encryptionKey == null) {
                LOG.debug("No stored password or encryption key found in memory");
                return null;
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
        } catch (Exception e) {
            LOG.error("Error retrieving and decrypting password", e);
            return null;
        }
    }

    /**
     * Clears the stored encrypted password and encryption key.
     */
    private void clearStoredPassword() {
        this.encryptedPassword = null;
        this.encryptionKey = null;
        LOG.debug("Stored password and encryption key cleared from memory");
    }

    /**
     * Deletes a key from the keystore.
     *
     * @param alias the alias of the key to delete
     * @param password the keystore password
     * @throws GeneralSecurityException if there's a security-related error
     * @throws IOException if there's an I/O error
     */
    /**
     * Backs up the keystore file before it is updated.
     * The backup file is named with a timestamp in the format yyyymmddhhmmssss.
     *
     * @param keystorePath the path to the keystore file
     * @throws IOException if there's an I/O error
     */
    private void backupKeystoreFile(Path keystorePath) throws IOException {
        if (keystorePath == null || !Files.exists(keystorePath)) {
            return; // Nothing to backup
        }

        // Create timestamp in format yyyymmddhhmmssss where ssss is seconds with decimal precision
        LocalDateTime now = LocalDateTime.now();
        String timestamp = String.format("%04d%02d%02d%02d%02d%04d", now.getYear(), now.getMonthValue(), now.getDayOfMonth(), now.getHour(), now.getMinute(), now.getSecond() * 100 + now.getNano() / 10_000_000); // Convert to seconds.hundredths

        // Create backup file path
        String fileName = keystorePath.getFileName().toString();
        int dotIndex = fileName.lastIndexOf('.');
        String baseName = (dotIndex > 0) ? fileName.substring(0, dotIndex) : fileName;
        String extension = (dotIndex > 0) ? fileName.substring(dotIndex) : "";
        Path backupPath = keystorePath.resolveSibling(baseName + "-" + timestamp + extension);

        // Copy the file
        Files.copy(keystorePath, backupPath);
        LOG.debug("Created keystore backup at: {}", backupPath);
    }

    private void deleteKey(String alias) throws GeneralSecurityException, IOException {
        if (keyStore == null) {
            throw new IllegalStateException("No keystore loaded");
        }

        keyStore.deleteEntry(alias);
        backupKeystoreFile(keystorePath);
        KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, getPassword());
        updateKeyAliasComboBox();
    }

}
