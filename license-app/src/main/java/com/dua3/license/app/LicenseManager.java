package com.dua3.license.app;

import com.dua3.utility.crypt.AsymmetricAlgorithm;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
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
import java.security.PublicKey;
import java.security.Security;
import java.time.LocalDateTime;
import java.util.Base64;

public class LicenseManager {

    private static final Logger LOG = LogManager.getLogger(LicenseManager.class);
    public static final String INFO_SYMBOL = "ⓘ";
    private static final String APP_NAME = LicenseManager.class.getSimpleName();
    private static final String ERROR = "Error";

    static {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Exception e) {
            LOG.error("Failed to register Bouncy Castle provider", e);
        }
    }

    private final KeystoreManager keystoreManager = new KeystoreManager();

    @Nullable private JFrame mainFrame;
    @Nullable private JTabbedPane tabbedPane;
    @Nullable private JPanel keysPanel;
    @Nullable private JPanel licensesPanel;
    @Nullable private LicenseEditor licenseEditor;


    private final JComboBox<String> licenseKeyAliasComboBox = new JComboBox<>();

    // Table for displaying keys
    private javax.swing.JTable keysTable;
    private javax.swing.table.DefaultTableModel keysTableModel;

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
        if (!keystoreManager.showDialog(null)) {
            // User chose to exit
            LOG.info("User chose to exit after keystore loading failure");
            System.exit(0);
            return;
        }

        LOG.debug("Keystore loaded successfully, initializing main window");
        mainFrame = new JFrame(APP_NAME);
        mainFrame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        mainFrame.setSize(800, 600);

        // Initialize the license editor
        licenseEditor = new LicenseEditor(mainFrame);

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
                        new KeyDetailsDialog(mainFrame, keystoreManager.getKeyStore(), alias).showDialog();
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
            KeyStore keyStore = keystoreManager.getKeyStore();
            if (keyStore == null) {
                JOptionPane.showMessageDialog(mainFrame, "Please load or create a keystore first.", ERROR, JOptionPane.ERROR_MESSAGE);
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

            // Create a helper method to add a label with info icon and tooltip
            JPanel panel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]5[]5[]5[]5[]5[]5[]5[]5[]"));

            // Add field with label, info icon, and tooltip
            addLabeledFieldWithTooltip(panel, "Key Alias:", 
                "A unique identifier for this key in the keystore", aliasField);

            // Add subject fields with required fields marked
            addLabeledFieldWithTooltip(panel, "CN - Common Name: *", 
                "The name of the entity this certificate represents (required)", cnField);

            addLabeledFieldWithTooltip(panel, "O - Organization:", 
                "The organization to which the entity belongs", oField);

            addLabeledFieldWithTooltip(panel, "OU - Organizational Unit:", 
                "The department or division within the organization", ouField);

            addLabeledFieldWithTooltip(panel, "C - Country: *", 
                "The two-letter country code (e.g., US, UK, DE) (required)", cField);

            addLabeledFieldWithTooltip(panel, "ST - State/Province:", 
                "The state or province where the organization is located", stField);

            addLabeledFieldWithTooltip(panel, "L - Locality (City):", 
                "The city where the organization is located", lField);

            addLabeledFieldWithTooltip(panel, "Email Address:", 
                "Contact email address for the certificate owner", emailField);

            addLabeledFieldWithTooltip(panel, "Valid Days:", 
                "Number of days the certificate will be valid from creation date", validDaysField);

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
                    JOptionPane.showMessageDialog(mainFrame, "Please specify a key alias.", ERROR, JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Validate required fields
                if (cn.isEmpty()) {
                    JOptionPane.showMessageDialog(mainFrame, "Common Name (CN) is required.", ERROR, JOptionPane.ERROR_MESSAGE);
                    return;
                }

                if (c.isEmpty()) {
                    JOptionPane.showMessageDialog(mainFrame, "Country (C) is required.", ERROR, JOptionPane.ERROR_MESSAGE);
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
                    JOptionPane.showMessageDialog(mainFrame, "Please enter a valid number of days.", ERROR, JOptionPane.ERROR_MESSAGE);
                    return;
                }

                try {
                    KeyStoreUtil.generateAndStoreKeyPairWithX509Certificate(keyStore, alias, AsymmetricAlgorithm.RSA, 2048, keystoreManager.getPassword(), subject, validDays);

                    // Backup the keystore file before saving
                    Path keystorePath = keystoreManager.getKeystorePath();
                    backupKeystoreFile(keystorePath);

                    KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, keystoreManager.getPassword());

                    updateKeyAliasComboBox();

                    JOptionPane.showMessageDialog(mainFrame, "Key pair generated and stored successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
                } catch (GeneralSecurityException | IOException ex) {
                    LOG.warn("Error generating key pair", ex);
                    JOptionPane.showMessageDialog(mainFrame, "Error generating key pair: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        JButton deleteKeyButton = new JButton("Delete Key");
        deleteKeyButton.addActionListener(e -> {
            KeyStore keyStore = keystoreManager.getKeyStore();
            if (keyStore == null) {
                JOptionPane.showMessageDialog(mainFrame, "Please load or create a keystore first.", ERROR, JOptionPane.ERROR_MESSAGE);
                return;
            }

            int row = keysTable.getSelectedRow();
            if (row < 0) {
                JOptionPane.showMessageDialog(mainFrame, "Please select a key to delete.", ERROR, JOptionPane.ERROR_MESSAGE);
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
                    JOptionPane.showMessageDialog(mainFrame, "Error deleting key: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
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
        KeyStore keyStore = keystoreManager.getKeyStore();

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
                            if (publicKey instanceof java.security.interfaces.RSAKey rsaKey) {
                                keySize = rsaKey.getModulus().bitLength();
                            } else if (publicKey instanceof java.security.interfaces.DSAKey dsaKey) {
                                keySize = dsaKey.getParams().getP().bitLength();
                            } else if (publicKey instanceof java.security.interfaces.ECKey ecKey) {
                                keySize = ecKey.getParams().getCurve().getField().getFieldSize();
                            }

                            // Get subject from X509Certificate
                            if (cert instanceof java.security.cert.X509Certificate x509Certificate) {
                                subject = x509Certificate.getSubjectX500Principal().getName();
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
            JOptionPane.showMessageDialog(mainFrame, "Error loading key information: " + e.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
        }
    }


    /**
     * Creates the Licenses panel with buttons for creating and validating licenses.
     */
    private void createLicensesPanel() {
        // Use the LicenseEditor to create the licenses panel
        licensesPanel = licenseEditor.createLicensesPanel();
    }


    private void updateKeyAliasComboBox() {
        KeyStore keyStore = keystoreManager.getKeyStore();
        if (keyStore == null) {
            LOG.debug("No keystore loaded, skipping key alias update");
            return;
        }

        LOG.debug("Updating key alias combo box");
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
            JOptionPane.showMessageDialog(mainFrame, "Error loading key aliases: " + e.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
        }

        // Update the keys table as well
        updateKeysTable();
    }

    /**
     * Backs up the keystore file before it is updated.
     * The backup file is named with a timestamp in the format yyyymmddhhmmssss.
     *
     * @param keystorePath the path to the keystore file
     * @throws IOException if there's an I/O error
     */
    private static void backupKeystoreFile(Path keystorePath) throws IOException {
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
        KeyStore keyStore = keystoreManager.getKeyStore();
        if (keyStore == null) {
            throw new IllegalStateException("No keystore loaded");
        }

        keyStore.deleteEntry(alias);
        Path keystorePath = keystoreManager.getKeystorePath();
        backupKeystoreFile(keystorePath);
        KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, keystoreManager.getPassword());
        updateKeyAliasComboBox();
    }

    /**
     * Adds a labeled field with an information icon that shows a tooltip with the field's description.
     *
     * @param panel The panel to add the components to
     * @param labelText The text for the label
     * @param description The description to show in the tooltip
     * @param field The text field to add
     */
    private void addLabeledFieldWithTooltip(JPanel panel, String labelText, String description, JTextField field) {
        // Create and add the label
        JLabel label = new JLabel(labelText);
        panel.add(label);

        // Add the label panel and field to the main panel
        panel.add(field, "grow x");

        // Create the info icon with tooltip
        JLabel infoIcon = new JLabel(INFO_SYMBOL);
        infoIcon.setToolTipText(description);
        panel.add(infoIcon, "wrap");
    }

}
