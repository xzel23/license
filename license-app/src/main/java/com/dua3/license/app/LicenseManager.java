package com.dua3.license.app;

import com.dua3.license.DynamicEnum;
import com.dua3.license.License;
import com.dua3.utility.crypt.AsymmetricAlgorithm;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.swing.FileInput;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.prefs.Preferences;

public class LicenseManager {

    private static final Logger LOG = LogManager.getLogger(LicenseManager.class);
    private static final String APP_NAME = LicenseManager.class.getSimpleName();
    private static final String APP_DESCRIPTION = "License Manager";
    private static final String PREF_KEYSTORE_PATH = "keystorePath";

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
    private JPanel keyManagementPanel;
    private JPanel licenseGenerationPanel;
    private JPanel licenseVerificationPanel;

    private FileInput keyStorePathInput;
    private JPasswordField keystorePasswordField;
    private JTextField keyAliasField;
    private JTextField keySubjectField;
    private JTextField keyValidDaysField;

    private JComboBox<String> licenseKeyAliasComboBox;
    private JPanel licenseFieldsPanel;
    private List<JTextField[]> licenseFieldRows = new ArrayList<>();

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
            // User canceled, exit application
            LOG.info("User canceled keystore selection, exiting application");
            System.exit(0);
            return;
        }

        LOG.debug("Keystore loaded successfully, initializing main window");
        mainFrame = new JFrame(APP_NAME);
        mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
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
            public java.awt.Component getTableCellRendererComponent(javax.swing.JTable table, Object value, 
                    boolean isSelected, boolean hasFocus, int row, int column) {
                JButton button = new JButton("Show Private Key");
                return button;
            }
        });

        keysTable.getColumnModel().getColumn(5).setCellEditor(new javax.swing.DefaultCellEditor(new JTextField()) {
            private JButton button = new JButton("Show Private Key");

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
            public java.awt.Component getTableCellEditorComponent(javax.swing.JTable table, Object value, 
                    boolean isSelected, int row, int column) {
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

            int result = JOptionPane.showConfirmDialog(mainFrame, panel, "Add New Key", 
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

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

                // Ask for password
                JPasswordField passwordField = new JPasswordField(20);
                int pwdResult = JOptionPane.showConfirmDialog(mainFrame, 
                        new Object[]{"Enter password for keystore:", passwordField}, 
                        "Password Required", JOptionPane.OK_CANCEL_OPTION);

                if (pwdResult == JOptionPane.OK_OPTION) {
                    char[] password = passwordField.getPassword();
                    if (password.length == 0) {
                        JOptionPane.showMessageDialog(mainFrame, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    try {
                        KeyStoreUtil.generateAndStoreKeyPairWithX509Certificate(
                                keyStore,
                                alias,
                                AsymmetricAlgorithm.RSA,
                                2048,
                                password,
                                subject,
                                validDays
                        );

                        KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, password);
                        updateKeyAliasComboBox();

                        JOptionPane.showMessageDialog(mainFrame, "Key pair generated and stored successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    } catch (GeneralSecurityException | IOException ex) {
                        LOG.warn("Error generating key pair", ex);
                        JOptionPane.showMessageDialog(mainFrame, "Error generating key pair: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    }
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
            String input = JOptionPane.showInputDialog(mainFrame, 
                    "To confirm deletion, please type the exact alias of the key: " + alias, 
                    "Confirm Deletion", JOptionPane.WARNING_MESSAGE);

            if (input != null && input.equals(alias)) {
                // Ask for password
                JPasswordField passwordField = new JPasswordField(20);
                int result = JOptionPane.showConfirmDialog(mainFrame, 
                        new Object[]{"Enter password for keystore:", passwordField}, 
                        "Password Required", JOptionPane.OK_CANCEL_OPTION);

                if (result == JOptionPane.OK_OPTION) {
                    char[] password = passwordField.getPassword();
                    if (password.length == 0) {
                        JOptionPane.showMessageDialog(mainFrame, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    try {
                        deleteKey(alias, password);
                        JOptionPane.showMessageDialog(mainFrame, "Key deleted successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    } catch (Exception ex) {
                        LOG.warn("Error deleting key", ex);
                        JOptionPane.showMessageDialog(mainFrame, "Error deleting key: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    }
                }
            } else if (input != null) {
                JOptionPane.showMessageDialog(mainFrame, "The alias you entered does not match. Deletion cancelled.", 
                        "Deletion Cancelled", JOptionPane.INFORMATION_MESSAGE);
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
                        keysTableModel.addRow(new Object[]{
                            alias,
                            algorithm,
                            keySize > 0 ? String.valueOf(keySize) : "N/A",
                            subject,
                            publicKeyString,
                            ""  // Button placeholder
                        });
                    }
                } catch (Exception e) {
                    // Skip this alias if there's an error
                    LOG.warn("Error processing key alias: {}", alias, e);
                }
            });
        } catch (Exception e) {
            LOG.warn("Error loading key information", e);
            JOptionPane.showMessageDialog(mainFrame, "Error loading key information: " + e.getMessage(), 
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Shows the private key for the given alias after password verification.
     * @param alias the key alias
     */
    private void showPrivateKey(String alias) {
        LOG.debug("Attempting to show private key for alias: {}", alias);
        if (keyStore == null) {
            LOG.warn("Attempted to show private key but no keystore is loaded");
            JOptionPane.showMessageDialog(mainFrame, "No keystore loaded.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Ask for password
        JPasswordField passwordField = new JPasswordField(20);
        int option = JOptionPane.showConfirmDialog(mainFrame, 
                new Object[]{"Enter password for key '" + alias + "':", passwordField}, 
                "Password Required", JOptionPane.OK_CANCEL_OPTION);

        if (option == JOptionPane.OK_OPTION) {
            char[] password = passwordField.getPassword();
            try {
                // Get the private key
                PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
                if (privateKey == null) {
                    JOptionPane.showMessageDialog(mainFrame, "No private key found for alias: " + alias, 
                            "Error", JOptionPane.ERROR_MESSAGE);
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
                JOptionPane.showMessageDialog(mainFrame, scrollPane, 
                        "Private Key for " + alias, JOptionPane.INFORMATION_MESSAGE);

            } catch (GeneralSecurityException e) {
                LOG.warn("Error retrieving private key for alias: {}", alias, e);
                JOptionPane.showMessageDialog(mainFrame, "Error retrieving private key: " + e.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Creates the Licenses panel (placeholder for now).
     */
    private void createLicensesPanel() {
        licensesPanel = new JPanel(new BorderLayout());
        licensesPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel placeholderLabel = new JLabel("Licenses tab content will be filled in later.", JLabel.CENTER);
        placeholderLabel.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 16));
        licensesPanel.add(placeholderLabel, BorderLayout.CENTER);
    }

    /**
     * Shows a dialog at startup that asks the user to either load an existing keystore or create a new one.
     * @return true if a keystore was successfully loaded or created, false otherwise
     */
    private boolean showKeystoreStartupDialog() {
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

        int option = JOptionPane.showOptionDialog(
            null, 
            panel, 
            "Keystore Selection", 
            JOptionPane.DEFAULT_OPTION, 
            JOptionPane.QUESTION_MESSAGE, 
            null, 
            new String[]{"Load Existing Keystore", "Create New Keystore", "Cancel"}, 
            "Load Existing Keystore"
        );

        if (option == 0) {
            // Load existing keystore
            return loadKeystoreFromDialog();
        } else if (option == 1) {
            // Create new keystore
            return createKeystoreFromDialog();
        } else {
            // Cancel
            return false;
        }
    }

    /**
     * Loads a keystore from the dialog input.
     * @return true if successful, false otherwise
     */
    private boolean loadKeystoreFromDialog() {
        LOG.debug("Attempting to load keystore from dialog");
        return keyStorePathInput.getPath().map(path -> {
            LOG.debug("Loading keystore from path: {}", path);
            char[] password = keystorePasswordField.getPassword();
            if (password.length == 0) {
                LOG.warn("Attempted to load keystore with empty password");
                JOptionPane.showMessageDialog(null, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            try {
                keyStore = KeyStoreUtil.loadKeyStoreFromFile(path, password);
                setKeystorePath(path);
                LOG.debug("Keystore loaded successfully from: {}", path);
                return true;
            } catch (GeneralSecurityException | IOException e) {
                LOG.warn("Error loading keystore from path: {}", path, e);
                JOptionPane.showMessageDialog(null, "Error loading keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }
        }).orElseGet(() -> {
            LOG.warn("No keystore path specified for loading");
            JOptionPane.showMessageDialog(null, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        });
    }

    /**
     * Creates a new keystore from the dialog input.
     * @return true if successful, false otherwise
     */
    private boolean createKeystoreFromDialog() {
        LOG.debug("Attempting to create keystore from dialog");
        return keyStorePathInput.getPath().map(path -> {
            LOG.debug("Creating keystore at path: {}", path);
            char[] password = keystorePasswordField.getPassword();
            if (password.length == 0) {
                LOG.warn("Attempted to create keystore with empty password");
                JOptionPane.showMessageDialog(null, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
                return false;
            }

            try {
                // Create a new KeyStore instance directly
                keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, password);
                KeyStoreUtil.saveKeyStoreToFile(keyStore, path, password);
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

    private void createKeyManagementPanel() {
        keyManagementPanel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]10[]10[]10[]10[]10[]"));

        // Keystore path
        keyManagementPanel.add(new JLabel("Keystore Path:"));
        Path defaultPath = getStoredKeystorePath();
        keyStorePathInput = new FileInput(FileInput.SelectionMode.SELECT_FILE, defaultPath, 20);
        keyManagementPanel.add(keyStorePathInput, "growx, wrap");

        // Keystore password
        keyManagementPanel.add(new JLabel("Keystore Password:"));
        keystorePasswordField = new JPasswordField(20);
        keyManagementPanel.add(keystorePasswordField, "growx, wrap");

        // Key alias
        keyManagementPanel.add(new JLabel("Key Alias:"));
        keyAliasField = new JTextField(20);
        keyManagementPanel.add(keyAliasField, "growx, wrap");

        // Key subject
        keyManagementPanel.add(new JLabel("Key Subject:"));
        keySubjectField = new JTextField("CN=License Key, O=Your Organization, L=Your City, ST=Your State, C=Your Country");
        keyManagementPanel.add(keySubjectField, "growx, wrap");

        // Valid days
        keyManagementPanel.add(new JLabel("Valid Days:"));
        keyValidDaysField = new JTextField("3650");
        keyManagementPanel.add(keyValidDaysField, "growx, wrap");

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton loadKeystoreButton = new JButton("Load Keystore");
        loadKeystoreButton.addActionListener(e -> loadKeystore());
        buttonPanel.add(loadKeystoreButton);

        JButton createKeystoreButton = new JButton("Create Keystore");
        createKeystoreButton.addActionListener(e -> createKeystore());
        buttonPanel.add(createKeystoreButton);

        JButton generateKeyButton = new JButton("Generate Key Pair");
        generateKeyButton.addActionListener(e -> generateKeyPair());
        buttonPanel.add(generateKeyButton);

        keyManagementPanel.add(buttonPanel, "span, growx");
    }

    private void createLicenseGenerationPanel() {
        licenseGenerationPanel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]10[]10[]10[]"));

        // Key selection
        licenseGenerationPanel.add(new JLabel("Select Key:"));
        licenseKeyAliasComboBox = new JComboBox<>();
        licenseGenerationPanel.add(licenseKeyAliasComboBox, "growx, wrap");

        // License fields
        licenseGenerationPanel.add(new JLabel("License Fields:"), "top");
        licenseFieldsPanel = new JPanel(new MigLayout("fillx", "[right][grow][]", "[]"));
        licenseGenerationPanel.add(licenseFieldsPanel, "growx, wrap");

        // Add initial field row
        addLicenseFieldRow();

        // Add field button
        JButton addFieldButton = new JButton("Add Field");
        addFieldButton.addActionListener(e -> addLicenseFieldRow());
        licenseGenerationPanel.add(addFieldButton, "skip 1, wrap");

        // License output
        licenseGenerationPanel.add(new JLabel("License:"), "top");
        licenseOutputArea = new JTextArea(10, 40);
        licenseOutputArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(licenseOutputArea);
        licenseGenerationPanel.add(scrollPane, "grow, wrap");

        // Generate button
        JButton generateButton = new JButton("Generate License");
        generateButton.addActionListener(e -> generateLicense());
        licenseGenerationPanel.add(generateButton, "skip 1, align right");
    }

    private void createLicenseVerificationPanel() {
        licenseVerificationPanel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]10[]10[]"));

        // License input
        licenseVerificationPanel.add(new JLabel("License:"), "top");
        JTextArea licenseInputArea = new JTextArea(10, 40);
        JScrollPane inputScrollPane = new JScrollPane(licenseInputArea);
        licenseVerificationPanel.add(inputScrollPane, "grow, wrap");

        // Verification output
        licenseVerificationPanel.add(new JLabel("Verification Result:"), "top");
        verificationOutputArea = new JTextArea(10, 40);
        verificationOutputArea.setEditable(false);
        JScrollPane outputScrollPane = new JScrollPane(verificationOutputArea);
        licenseVerificationPanel.add(outputScrollPane, "grow, wrap");

        // Verify button
        JButton verifyButton = new JButton("Verify License");
        verifyButton.addActionListener(e -> verifyLicense(licenseInputArea.getText()));
        licenseVerificationPanel.add(verifyButton, "skip 1, align right");
    }

    private void addLicenseFieldRow() {
        JTextField nameField = new JTextField(15);
        JTextField valueField = new JTextField(20);
        JButton removeButton = new JButton("Remove");

        licenseFieldsPanel.add(nameField, "");
        licenseFieldsPanel.add(valueField, "growx");
        licenseFieldsPanel.add(removeButton, "wrap");

        JTextField[] fieldRow = {nameField, valueField};
        licenseFieldRows.add(fieldRow);

        removeButton.addActionListener(e -> {
            licenseFieldRows.remove(fieldRow);
            licenseFieldsPanel.remove(nameField);
            licenseFieldsPanel.remove(valueField);
            licenseFieldsPanel.remove(removeButton);
            licenseFieldsPanel.revalidate();
            licenseFieldsPanel.repaint();
        });

        licenseFieldsPanel.revalidate();
        licenseFieldsPanel.repaint();
    }

    private void loadKeystore() {
        LOG.debug("Loading keystore from UI input");
        keyStorePathInput.getPath().ifPresentOrElse(
    keystorePath -> {
            LOG.debug("Loading keystore from path: {}", keystorePath);
            char[] password = keystorePasswordField.getPassword();
            if (password.length == 0) {
                LOG.warn("Attempted to load keystore with empty password");
                JOptionPane.showMessageDialog(mainFrame, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                keyStore = KeyStoreUtil.loadKeyStoreFromFile(keystorePath, password);
                setKeystorePath(keystorePath);
                updateKeyAliasComboBox();
                LOG.debug("Keystore loaded successfully from: {}", keystorePath);
                JOptionPane.showMessageDialog(mainFrame, "Keystore loaded successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (GeneralSecurityException | IOException e) {
                LOG.warn("Error loading keystore from path: {}", keystorePath, e);
                JOptionPane.showMessageDialog(mainFrame, "Error loading keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        },
        () -> {
            LOG.warn("No keystore path specified for loading");
            JOptionPane.showMessageDialog(mainFrame, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
        }
        );
    }

    private void setKeystorePath(Path keystorePath) {
        this.keystorePath = keystorePath;
        saveKeystorePath(keystorePath);
    }

    private void createKeystore() {
        LOG.debug("Creating keystore from UI input");
        keyStorePathInput.getPath().ifPresentOrElse(
                keystorePath -> {
                    LOG.debug("Creating keystore at path: {}", keystorePath);
                    char[] password = keystorePasswordField.getPassword();
                    if (password.length == 0) {
                        LOG.warn("Attempted to create keystore with empty password");
                        JOptionPane.showMessageDialog(mainFrame, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    try {
                        // Create a new KeyStore instance directly
                        keyStore = KeyStore.getInstance("PKCS12");
                        keyStore.load(null, password);
                        KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, password);
                        setKeystorePath(keystorePath);
                        LOG.debug("Keystore created successfully at: {}", keystorePath);
                        JOptionPane.showMessageDialog(mainFrame, "Keystore created successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                    } catch (GeneralSecurityException | IOException e) {
                        LOG.warn("Error creating keystore at path: {}", keystorePath, e);
                        JOptionPane.showMessageDialog(mainFrame, "Error creating keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    }
                },
                () -> {
                    LOG.warn("No keystore path specified for creation");
                    JOptionPane.showMessageDialog(mainFrame, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
                }
        );
    }

    private void generateKeyPair() {
        LOG.debug("Attempting to generate key pair");
        if (keyStore == null) {
            LOG.warn("Attempted to generate key pair but no keystore is loaded");
            JOptionPane.showMessageDialog(mainFrame, "Please load or create a keystore first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String alias = keyAliasField.getText().trim();
        if (alias.isEmpty()) {
            LOG.warn("Attempted to generate key pair with empty alias");
            JOptionPane.showMessageDialog(mainFrame, "Please specify a key alias.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String subject = keySubjectField.getText().trim();
        if (subject.isEmpty()) {
            LOG.warn("Attempted to generate key pair with empty subject");
            JOptionPane.showMessageDialog(mainFrame, "Please specify a key subject.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int validDays;
        try {
            validDays = Integer.parseInt(keyValidDaysField.getText().trim());
            if (validDays <= 0) {
                throw new NumberFormatException("Valid days must be positive");
            }
        } catch (NumberFormatException e) {
            LOG.warn("Invalid valid days value: {}", keyValidDaysField.getText().trim(), e);
            JOptionPane.showMessageDialog(mainFrame, "Please enter a valid number of days.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        char[] password = keystorePasswordField.getPassword();
        if (password.length == 0) {
            LOG.warn("Attempted to generate key pair with empty password");
            JOptionPane.showMessageDialog(mainFrame, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            LOG.debug("Generating key pair with alias: {}, subject: {}, valid days: {}", alias, subject, validDays);
            KeyStoreUtil.generateAndStoreKeyPairWithX509Certificate(
                    keyStore,
                    alias,
                    AsymmetricAlgorithm.RSA,
                    2048,
                    password,
                    subject,
                    validDays
            );

            KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, password);
            updateKeyAliasComboBox();

            LOG.debug("Key pair generated and stored successfully for alias: {}", alias);
            JOptionPane.showMessageDialog(mainFrame, "Key pair generated and stored successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (GeneralSecurityException | IOException e) {
            LOG.warn("Error generating key pair for alias: {}", alias, e);
            JOptionPane.showMessageDialog(mainFrame, "Error generating key pair: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
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

    private void generateLicense() {
        LOG.debug("Attempting to generate license");
        if (keyStore == null) {
            LOG.warn("Attempted to generate license but no keystore is loaded");
            JOptionPane.showMessageDialog(mainFrame, "Please load a keystore first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String alias = (String) licenseKeyAliasComboBox.getSelectedItem();
        if (alias == null || alias.isEmpty()) {
            LOG.warn("Attempted to generate license with no key alias selected");
            JOptionPane.showMessageDialog(mainFrame, "Please select a key alias.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        char[] password = keystorePasswordField.getPassword();
        if (password.length == 0) {
            LOG.warn("Attempted to generate license with empty password");
            JOptionPane.showMessageDialog(mainFrame, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Collect license fields
        Map<String, Object> licenseData = new HashMap<>();
        List<String> fieldNames = new ArrayList<>();

        for (JTextField[] row : licenseFieldRows) {
            String name = row[0].getText().trim();
            String value = row[1].getText().trim();

            if (!name.isEmpty() && !value.isEmpty()) {
                licenseData.put(name, value);
                fieldNames.add(name);
            }
        }

        if (licenseData.isEmpty()) {
            LOG.warn("Attempted to generate license with no license fields");
            JOptionPane.showMessageDialog(mainFrame, "Please add at least one license field.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            // Get the private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);

            // Create a dynamic enum for the license fields
            DynamicEnum keyEnum = DynamicEnum.of(fieldNames.toArray(new String[0]));

            // Generate signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(licenseData.toString().getBytes());
            byte[] signatureBytes = signature.sign();

            // Add signature to license data
            licenseData.put(License.SIGNATURE, Base64.getEncoder().encodeToString(signatureBytes));

            // Display the license
            licenseOutputArea.setText(licenseData.toString());

        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainFrame, "Error generating license: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Gets the stored keystore path from preferences or returns a default path if none is stored.
     * @return the stored keystore path or a default path
     */
    private Path getStoredKeystorePath() {
        Preferences prefs = Preferences.userNodeForPackage(LicenseManager.class);
        String storedPath = prefs.get(PREF_KEYSTORE_PATH, null);
        return storedPath != null ? Paths.get(storedPath) : Paths.get(".");
    }

    /**
     * Saves the keystore path to preferences.
     * @param path the path to save
     */
    private void saveKeystorePath(Path path) {
        if (path != null) {
            Preferences prefs = Preferences.userNodeForPackage(LicenseManager.class);
            prefs.put(PREF_KEYSTORE_PATH, path.toString());
        }
    }

    private void verifyLicense(String licenseText) {
        if (keyStore == null) {
            JOptionPane.showMessageDialog(mainFrame, "Please load a keystore first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String alias = (String) licenseKeyAliasComboBox.getSelectedItem();
        if (alias == null || alias.isEmpty()) {
            JOptionPane.showMessageDialog(mainFrame, "Please select a key alias.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            // Parse the license text into a map
            // This is a simplified approach - in a real app, you'd need proper parsing
            licenseText = licenseText.trim();
            if (!licenseText.startsWith("{") || !licenseText.endsWith("}")) {
                throw new IllegalArgumentException("Invalid license format");
            }

            // Get the public key
            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

            // For demonstration purposes, we'll just show the verification attempt
            verificationOutputArea.setText("Verification attempted with key: " + alias + "\n");
            verificationOutputArea.append("Public key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");
            verificationOutputArea.append("Note: Full verification requires proper license parsing which is beyond the scope of this demo.");

        } catch (Exception e) {
            verificationOutputArea.setText("Error verifying license: " + e.getMessage());
        }
    }

    /**
     * Deletes a key from the keystore.
     * 
     * @param alias the alias of the key to delete
     * @param password the keystore password
     * @throws GeneralSecurityException if there's a security-related error
     * @throws IOException if there's an I/O error
     */
    private void deleteKey(String alias, char[] password) throws GeneralSecurityException, IOException {
        if (keyStore == null) {
            throw new IllegalStateException("No keystore loaded");
        }

        // Delete the key entry
        keyStore.deleteEntry(alias);

        // Save the keystore
        KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, password);

        // Update UI components
        updateKeyAliasComboBox();
    }
}
