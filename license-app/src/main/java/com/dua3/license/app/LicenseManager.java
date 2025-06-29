package com.dua3.license.app;

import com.dua3.utility.crypt.AsymmetricAlgorithm;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.swing.FileInput;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;

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
import java.awt.Color;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.prefs.Preferences;

import com.dua3.license.DynamicEnum;

public class LicenseManager {

    private static final Logger LOG = LogManager.getLogger(LicenseManager.class);
    private static final String APP_NAME = LicenseManager.class.getSimpleName();
    private static final String PREF_KEYSTORE_PATH = "keystorePath";
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    // In-memory storage for encrypted password and encryption key
    @Nullable private byte[] encryptedPassword;
    @Nullable private byte[] encryptionKey;

    static {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Exception e) {
            System.err.println("Failed to register Bouncy Castle provider: " + e.getMessage());
        }
    }

    @Nullable private JFrame mainFrame;
    @Nullable private JTabbedPane tabbedPane;
    @Nullable private JPanel keysPanel;
    @Nullable private JPanel licensesPanel;

    @Nullable private FileInput keyStorePathInput;
    @Nullable private JPasswordField keystorePasswordField;

    private final JComboBox<String> licenseKeyAliasComboBox = new JComboBox<>();

    // Table for displaying keys
    private javax.swing.JTable keysTable;
    private javax.swing.table.DefaultTableModel keysTableModel;

    @Nullable private KeyStore keyStore;
    @Nullable private Path keystorePath;

    public static void main(String[] args) {
        LOG.debug("Starting License Manager application");
        SwingUtil.setNativeLookAndFeel(APP_NAME);
        SwingUtilities.invokeLater(() -> {
            LicenseManager app = new LicenseManager();
            app.createAndShowGUI();
        });
    }

    public static Path getTemplatesDirectory() {
        return Paths.get("templates");
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
        String[] columnNames = {"Alias", "Algorithm", "Key Size", "Certificate Subject", "Public Key"};
        keysTableModel = new javax.swing.table.DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // No columns are editable
                return false;
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

        // Add mouse listener for double-click to show details
        keysTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = keysTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        String alias = (String) keysTable.getValueAt(row, 0);
                        showKeyDetails(alias);
                    }
                }
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
            JTextField cnField = new JTextField("License Key", 20);
            JTextField oField = new JTextField("Your Organization", 20);
            JTextField ouField = new JTextField("", 20);
            JTextField cField = new JTextField("US", 2);
            JTextField stField = new JTextField("", 20);
            JTextField lField = new JTextField("", 20);
            JTextField emailField = new JTextField("", 20);
            JTextField validDaysField = new JTextField("3650", 5);

            JPanel panel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]5[]5[]5[]5[]5[]5[]5[]5[]"));
            panel.add(new JLabel("Key Alias:"));
            panel.add(aliasField, "growx, wrap");

            // Add subject fields with required fields marked
            panel.add(new JLabel("CN - Common Name: *"));
            panel.add(cnField, "growx, wrap");
            panel.add(new JLabel("O - Organization:"));
            panel.add(oField, "growx, wrap");
            panel.add(new JLabel("OU - Organizational Unit:"));
            panel.add(ouField, "growx, wrap");
            panel.add(new JLabel("C - Country: *"));
            panel.add(cField, "growx, wrap");
            panel.add(new JLabel("ST - State/Province:"));
            panel.add(stField, "growx, wrap");
            panel.add(new JLabel("L - Locality (City):"));
            panel.add(lField, "growx, wrap");
            panel.add(new JLabel("Email Address:"));
            panel.add(emailField, "growx, wrap");

            panel.add(new JLabel("Valid Days:"));
            panel.add(validDaysField, "growx");

            int result = JOptionPane.showConfirmDialog(mainFrame, panel, "Add New Key", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

            if (result == JOptionPane.OK_OPTION) {
                String alias = aliasField.getText().trim();
                String cn = cnField.getText().trim();
                String o = oField.getText().trim();
                String ou = ouField.getText().trim();
                String c = cField.getText().trim();
                String st = stField.getText().trim();
                String l = lField.getText().trim();
                String email = emailField.getText().trim();
                String validDaysStr = validDaysField.getText().trim();

                if (alias.isEmpty()) {
                    JOptionPane.showMessageDialog(mainFrame, "Please specify a key alias.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Validate required fields
                if (cn.isEmpty()) {
                    JOptionPane.showMessageDialog(mainFrame, "Common Name (CN) is required.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                if (c.isEmpty()) {
                    JOptionPane.showMessageDialog(mainFrame, "Country (C) is required.", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Build the subject string in X.500 Distinguished Name format
                StringBuilder subjectBuilder = new StringBuilder();
                subjectBuilder.append("CN=").append(cn);

                if (!o.isEmpty()) {
                    subjectBuilder.append(", O=").append(o);
                }

                if (!ou.isEmpty()) {
                    subjectBuilder.append(", OU=").append(ou);
                }

                subjectBuilder.append(", C=").append(c);

                if (!st.isEmpty()) {
                    subjectBuilder.append(", ST=").append(st);
                }

                if (!l.isEmpty()) {
                    subjectBuilder.append(", L=").append(l);
                }

                if (!email.isEmpty()) {
                    subjectBuilder.append(", EMAILADDRESS=").append(email);
                }

                String subject = subjectBuilder.toString();

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
                        keysTableModel.addRow(new Object[]{alias, algorithm, keySize > 0 ? String.valueOf(keySize) : "N/A", subject, publicKeyString
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
     * @param privateKeyTextArea the text area to display the private key in
     */
    private void showPrivateKey(String alias, JTextArea privateKeyTextArea) {
        LOG.debug("Attempting to show private key for alias: {}", alias);
        if (keyStore == null) {
            LOG.warn("Attempted to show private key but no keystore is loaded");
            JOptionPane.showMessageDialog(mainFrame, "No keystore loaded.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Create password input dialog
        JPasswordField passwordField = new JPasswordField(20);
        JPanel passwordPanel = new JPanel(new BorderLayout(10, 10));
        passwordPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JLabel promptLabel = new JLabel("Please re-enter the keystore password to view the private key:");
        passwordPanel.add(promptLabel, BorderLayout.NORTH);
        passwordPanel.add(passwordField, BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(
                mainFrame,
                passwordPanel,
                "Password Verification",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE
        );

        if (result != JOptionPane.OK_OPTION) {
            return; // User cancelled
        }

        char[] enteredPassword = passwordField.getPassword();

        try {
            // Get the private key using the entered password
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, enteredPassword);
            if (privateKey == null) {
                JOptionPane.showMessageDialog(mainFrame, "No private key found for alias: " + alias, "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Display the private key in the provided text area
            String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            privateKeyTextArea.setText(privateKeyString);
        } catch (GeneralSecurityException e) {
            LOG.warn("Error retrieving private key for alias: {}", alias, e);
            JOptionPane.showMessageDialog(mainFrame, "Error retrieving private key: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        } finally {
            // Clear the password from memory
            java.util.Arrays.fill(enteredPassword, '\0');
        }
    }

    /**
     * Shows the key details for the given alias, including subject fields and buttons for additional actions.
     *
     * @param alias the key alias
     */
    private void showKeyDetails(String alias) {
        LOG.debug("Showing key details for alias: {}", alias);
        if (keyStore == null) {
            LOG.warn("Attempted to show key details but no keystore is loaded");
            JOptionPane.showMessageDialog(mainFrame, "No keystore loaded.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            // Get certificate information
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            if (cert == null) {
                JOptionPane.showMessageDialog(mainFrame, "No certificate found for alias: " + alias, "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Get public key
            PublicKey publicKey = cert.getPublicKey();
            String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            // Create main dialog panel with vertical layout
            JPanel panel = new JPanel();
            panel.setLayout(new javax.swing.BoxLayout(panel, javax.swing.BoxLayout.Y_AXIS));
            panel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

            // ===== SECTION 1: Subject Fields =====
            JPanel subjectPanel = new JPanel(new BorderLayout(5, 5));
            subjectPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 0, 10, 0));

            // Add headline for subject fields
            JLabel subjectHeadline = new JLabel("Subject Fields");
            subjectHeadline.setFont(new java.awt.Font("Dialog", java.awt.Font.BOLD, 14));
            subjectPanel.add(subjectHeadline, BorderLayout.NORTH);

            // Create table for subject fields
            String[] columnNames = {"Field", "Value"};
            javax.swing.table.DefaultTableModel tableModel = new javax.swing.table.DefaultTableModel(columnNames, 0);

            // Add subject fields to table if it's an X509Certificate
            if (cert instanceof java.security.cert.X509Certificate) {
                java.security.cert.X509Certificate x509Cert = (java.security.cert.X509Certificate) cert;
                String subjectDN = x509Cert.getSubjectX500Principal().getName();

                // Parse the subject DN into individual fields
                String[] subjectParts = subjectDN.split(",");
                for (String part : subjectParts) {
                    String[] keyValue = part.trim().split("=", 2);
                    if (keyValue.length == 2) {
                        tableModel.addRow(new Object[]{keyValue[0], keyValue[1]});
                    }
                }

                // Add additional certificate information
                tableModel.addRow(new Object[]{"Algorithm", publicKey.getAlgorithm()});
                tableModel.addRow(new Object[]{"Valid From", x509Cert.getNotBefore()});
                tableModel.addRow(new Object[]{"Valid Until", x509Cert.getNotAfter()});

                // Add key size information
                int keySize = 0;
                if (publicKey instanceof java.security.interfaces.RSAKey) {
                    keySize = ((java.security.interfaces.RSAKey) publicKey).getModulus().bitLength();
                } else if (publicKey instanceof java.security.interfaces.DSAKey) {
                    keySize = ((java.security.interfaces.DSAKey) publicKey).getParams().getP().bitLength();
                } else if (publicKey instanceof java.security.interfaces.ECKey) {
                    keySize = ((java.security.interfaces.ECKey) publicKey).getParams().getCurve().getField().getFieldSize();
                }

                if (keySize > 0) {
                    tableModel.addRow(new Object[]{"Key Size", keySize + " bits"});
                }
            }

            // Create table and add to panel
            javax.swing.JTable detailsTable = new javax.swing.JTable(tableModel);
            detailsTable.setDefaultEditor(Object.class, null); // Make table non-editable
            JScrollPane tableScrollPane = new JScrollPane(detailsTable);
            tableScrollPane.setPreferredSize(new java.awt.Dimension(500, 150));
            subjectPanel.add(tableScrollPane, BorderLayout.CENTER);

            // Add subject panel to main panel
            panel.add(subjectPanel);

            // ===== SECTION 2: Public Key =====
            JPanel publicKeyPanel = new JPanel(new BorderLayout(5, 5));
            publicKeyPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 0, 10, 0));

            // Add headline for public key
            JLabel publicKeyHeadline = new JLabel("Public Key");
            publicKeyHeadline.setFont(new java.awt.Font("Dialog", java.awt.Font.BOLD, 14));
            publicKeyPanel.add(publicKeyHeadline, BorderLayout.NORTH);

            // Create text area for public key
            JTextArea publicKeyTextArea = new JTextArea(5, 40);
            publicKeyTextArea.setText(publicKeyString);
            publicKeyTextArea.setEditable(false);
            publicKeyTextArea.setLineWrap(true);
            publicKeyTextArea.setWrapStyleWord(true);
            JScrollPane publicKeyScrollPane = new JScrollPane(publicKeyTextArea);
            publicKeyPanel.add(publicKeyScrollPane, BorderLayout.CENTER);

            // Add copy button for public key
            JButton copyPublicKeyButton = new JButton("Copy to Clipboard");
            copyPublicKeyButton.addActionListener(e -> {
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                        new java.awt.datatransfer.StringSelection(publicKeyString), null);
                JOptionPane.showMessageDialog(mainFrame, "Public key copied to clipboard.", "Success", JOptionPane.INFORMATION_MESSAGE);
            });

            JPanel publicKeyButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            publicKeyButtonPanel.add(copyPublicKeyButton);
            publicKeyPanel.add(publicKeyButtonPanel, BorderLayout.SOUTH);

            // Add public key panel to main panel
            panel.add(publicKeyPanel);

            // ===== SECTION 3: Private Key =====
            JPanel privateKeyPanel = new JPanel(new BorderLayout(5, 5));
            privateKeyPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 0, 0, 0));

            // Add headline for private key
            JLabel privateKeyHeadline = new JLabel("Private Key");
            privateKeyHeadline.setFont(new java.awt.Font("Dialog", java.awt.Font.BOLD, 14));
            privateKeyPanel.add(privateKeyHeadline, BorderLayout.NORTH);

            // Create text area for private key (initially empty)
            JTextArea privateKeyTextArea = new JTextArea(5, 40);
            privateKeyTextArea.setEditable(false);
            privateKeyTextArea.setLineWrap(true);
            privateKeyTextArea.setWrapStyleWord(true);
            JScrollPane privateKeyScrollPane = new JScrollPane(privateKeyTextArea);
            privateKeyPanel.add(privateKeyScrollPane, BorderLayout.CENTER);

            // Add show/hide button for private key
            JButton showPrivateKeyButton = new JButton("Show Private Key");
            showPrivateKeyButton.addActionListener(e -> {
                if (privateKeyTextArea.getText().isEmpty()) {
                    // Private key is not shown, show it
                    showPrivateKey(alias, privateKeyTextArea);
                    if (!privateKeyTextArea.getText().isEmpty()) {
                        // Private key was successfully shown, update button text
                        showPrivateKeyButton.setText("Hide Private Key");
                    }
                } else {
                    // Private key is shown, hide it
                    privateKeyTextArea.setText("");
                    showPrivateKeyButton.setText("Show Private Key");
                }
            });

            JPanel privateKeyButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            privateKeyButtonPanel.add(showPrivateKeyButton);
            privateKeyPanel.add(privateKeyButtonPanel, BorderLayout.SOUTH);

            // Add private key panel to main panel
            panel.add(privateKeyPanel);

            // Show dialog
            JOptionPane.showMessageDialog(mainFrame, panel, "Key Details for " + alias, JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception e) {
            LOG.warn("Error retrieving key details for alias: {}", alias, e);
            JOptionPane.showMessageDialog(mainFrame, "Error retrieving key details: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Creates the Licenses panel with buttons for creating and validating licenses.
     */
    private void createLicensesPanel() {
        licensesPanel = new JPanel(new BorderLayout(10, 10));
        licensesPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create a panel for the content
        JPanel contentPanel = new JPanel(new BorderLayout(10, 10));

        // Create a panel for the description
        JPanel descriptionPanel = new JPanel(new BorderLayout());
        JLabel descriptionLabel = new JLabel("Use this tab to create and validate licenses.", SwingConstants.CENTER);
        descriptionLabel.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 16));
        descriptionPanel.add(descriptionLabel, BorderLayout.CENTER);
        contentPanel.add(descriptionPanel, BorderLayout.NORTH);

        // Create a panel for the buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));

        // Create License button
        JButton createLicenseButton = new JButton("Create License");
        createLicenseButton.addActionListener(e -> {
            // Show dialog to create a license
            showCreateLicenseDialog();
        });
        buttonPanel.add(createLicenseButton);

        // Validate License button
        JButton validateLicenseButton = new JButton("Validate License");
        validateLicenseButton.addActionListener(e -> {
            // Show dialog to validate a license
            JOptionPane.showMessageDialog(mainFrame,
                "Validate License functionality will be implemented here.",
                "Validate License",
                JOptionPane.INFORMATION_MESSAGE);
        });
        buttonPanel.add(validateLicenseButton);

        // Manage Templates button
        JButton manageTemplatesButton = new JButton("Manage Templates");
        manageTemplatesButton.addActionListener(e -> {
            // Show the template editor dialog
            LicenseTemplateEditor editor = new LicenseTemplateEditor(mainFrame);
            editor.setVisible(true);
        });
        buttonPanel.add(manageTemplatesButton);

        contentPanel.add(buttonPanel, BorderLayout.CENTER);

        // Add the content panel to the licenses panel
        licensesPanel.add(contentPanel, BorderLayout.CENTER);
    }

    /**
     * Shows a dialog to create a license using a template.
     */
    private void showCreateLicenseDialog() {
        // Get available templates
        String[] templates = LicenseTemplateEditor.getAvailableTemplates();

        if (templates.length == 0) {
            JOptionPane.showMessageDialog(mainFrame,
                "No license templates available. Please create a template first.",
                "No Templates",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Create the dialog panel
        JPanel panel = new JPanel(new MigLayout("fillx", "[][grow]", "[]10[]"));

        // Template selection
        panel.add(new JLabel("License Template:"));
        JComboBox<String> templateComboBox = new JComboBox<>(templates);
        panel.add(templateComboBox, "growx, wrap");

        // Show the dialog
        int result = JOptionPane.showConfirmDialog(
            mainFrame,
            panel,
            "Create License",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        );

        if (result == JOptionPane.OK_OPTION) {
            String selectedTemplate = (String) templateComboBox.getSelectedItem();
            if (selectedTemplate != null) {
                try {
                    // Load the template
                    Path jsonFile = getTemplatesDirectory().resolve(selectedTemplate + ".json");
                    LicenseTemplate template = LicenseTemplate.loadTemplate(jsonFile);
                    // Show license creation form with the template
                    showLicenseCreationForm(template);
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(mainFrame,
                            "Failed to load the selected template.",
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    /**
     * Shows a form to create a license using the selected template.
     *
     * @param templateName the name of the template
     * @param template the DynamicEnum template
     */
    private void showLicenseCreationForm(LicenseTemplate template) {
        // Create the dialog panel
        JPanel panel = new JPanel(new MigLayout("fillx", "[][grow][]", "[]10[]"));

        // Add a label for the template
        panel.add(new JLabel("Template:"));
        panel.add(new JLabel(template.getName()), "growx, wrap");

        // Create input fields for each template value
        List<LicenseTemplate.LicenseField> fields = template.getFields();
        JTextField[] valueFields = new JTextField[fields.size()];
        for (int i = 0; i < fields.size(); i++) {
            LicenseTemplate.LicenseField field = fields.get(i);
            panel.add(new JLabel(field.name() + ":"));
            valueFields[i] = new JTextField(field.defaultValue(), 20);
            panel.add(valueFields[i], "growx");

            // Add info icon with tooltip showing the description
            JLabel infoLabel = new JLabel("ⓘ");
            String description = field.defaultValue();
            infoLabel.setToolTipText(description);
            infoLabel.setForeground(Color.BLUE);
            panel.add(infoLabel, "wrap");
        }

        // Show the dialog
        int result = JOptionPane.showConfirmDialog(
            mainFrame,
            panel,
            "Create License with Template: " + template.getName(),
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        );

        if (result == JOptionPane.OK_OPTION) {
            // Create a map of properties for the license
            Map<String, Object> properties = new HashMap<>();
            for (int i = 0; i < fields.size(); i++) {
                properties.put(fields.get(i).name(), valueFields[i].getText());
            }

            // TODO: Generate the license using the properties and a selected key
            JOptionPane.showMessageDialog(mainFrame,
                "License would be created with the following properties:\n" + properties,
                "License Creation",
                JOptionPane.INFORMATION_MESSAGE);
        }
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
     * @return the decrypted password as a char array
     * @throws IllegalStateException if no password is stored
     * @throws GeneralSecurityException if decryption fails
     */
    private char[] getPassword() throws GeneralSecurityException {
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
