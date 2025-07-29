package com.dua3.license.app;

import com.dua3.utility.crypt.AsymmetricAlgorithm;
import com.dua3.utility.crypt.CertificateUtil;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.crypt.KeyUtil;
import com.dua3.utility.data.Pair;
import com.dua3.utility.io.IoUtil;
import com.dua3.utility.math.MathUtil;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
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
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

/**
 * The LicenseManager class is responsible for managing software licenses
 * and keystore operations as part of an application. It also provides
 * a graphical user interface for interacting with license keys, keystores,
 * and licenses.
 */
public class LicenseManager {

    private static final Logger LOG = LogManager.getLogger(LicenseManager.class);

    private static final int FRAME_WIDTH = 1024;

    /**
     * A constant string representing an information symbol "ⓘ".
     * <p>
     * This symbol is used to add tooltips to input elements in the user interface.
     */
    public static final String INFO_SYMBOL = "ⓘ";
    private static final String APP_NAME = LicenseManager.class.getSimpleName();
    private static final String ERROR = "Error";
    private static final String PRIVATEKEY_SUFFIX = "-privatekey";

    static {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        } catch (Exception e) {
            LOG.error("Failed to register Bouncy Castle provider", e);
        }
    }

    private final KeystoreManager keystoreManager;
    private final JComboBox<String> licenseKeyAliasComboBox = new JComboBox<>();
    private final JFrame mainFrame;

    @Nullable
    private JTabbedPane tabbedPane;
    @Nullable
    private JPanel keysPanel;
    @Nullable
    private JPanel licensesPanel;
    @Nullable
    private JPanel certificatesPanel;
    @Nullable
    private LicenseEditor licenseEditor;

    // Table for displaying keys
    private javax.swing.JTable keysTable;
    private javax.swing.table.DefaultTableModel keysTableModel;

    // Table for displaying certificates
    private javax.swing.JTable certificatesTable;
    private javax.swing.table.DefaultTableModel certificatesTableModel;

    /**
     * Constructs a new instance of the LicenseManager class.
     */
    public LicenseManager() {
        this.mainFrame = createFrame();
        this.keystoreManager = new KeystoreManager(mainFrame);

        createAndShowGUI();
    }

    /**
     * Creates and initializes a {@code JFrame} instance configured with default settings.
     * The frame's size is determined by the static {@code FRAME_WIDTH} field and the golden ratio,
     * and its default close operation is set to exit the application.
     *
     * @return the configured {@code JFrame} instance
     */
    private static final JFrame createFrame() {
        JFrame frame = new JFrame();
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setSize(FRAME_WIDTH, (int) Math.round(FRAME_WIDTH / MathUtil.GOLDEN_RATIO));
        return frame;
    }

    /**
     * The main method serves as the entry point for the License Manager application.
     * It initializes the application's look and feel and invokes the creation of the main GUI.
     *
     * @param args Command-line arguments passed to the application.
     */
    public static void main(String[] args) {
        LOG.debug("Starting License Manager application");
        SwingUtil.setNativeLookAndFeel(APP_NAME);
        SwingUtilities.invokeLater(() -> {
            LicenseManager app = new LicenseManager();
        });
    }

    /**
     * Initializes and displays the main graphical user interface (GUI) of the application.
     * This method ensures that the keystore is loaded or created before proceeding.
     * If loading the keystore fails and the user opts to exit, the method will terminate early.
     */
    private void createAndShowGUI() {
        LOG.debug("Creating and showing GUI");

        // Show startup dialog to load or create keystore
        if (!keystoreManager.showDialog()) {
            mainFrame.dispose();
            return;
        }

        LOG.debug("Keystore loaded successfully, initializing main window");

        // Initialize the license editor
        licenseEditor = new LicenseEditor(mainFrame, keystoreManager);
        // Register callback to refresh keys table when a license is created
        licenseEditor.setLicenseCreationCallback(this::updateKeysTable);

        tabbedPane = new JTabbedPane();

        // Create panels for each tab
        createKeysPanel();
        createLicensesPanel();
        createCertificatesPanel();

        // Add the new tabs as required
        tabbedPane.addTab("Certificates", certificatesPanel);
        tabbedPane.addTab("Keys", keysPanel);
        tabbedPane.addTab("Licenses", licensesPanel);

        mainFrame.getContentPane().add(tabbedPane, BorderLayout.CENTER);

        mainFrame.setLocationRelativeTo(null);
        mainFrame.setVisible(true);
    }

    /**
     * Updates the keys table with the current keystore information.
     */
    private void updateKeysTable() {
        KeyStore keyStore = keystoreManager.getKeyStore();

        // Clear the table
        keysTableModel.setRowCount(0);

        try {
            keyStore.aliases().asIterator().forEachRemaining(alias -> {
                try {
                    // Process only key entries
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
                        new KeyDetailsDialog(mainFrame, keystoreManager.getKeyStore(), alias, keystoreManager.getKeystorePath()).showDialog();
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

            // Create a combobox for certificate selection
            JComboBox<String> certComboBox = new JComboBox<>();
            certComboBox.addItem("-- Create new certificate --");

            // Populate the combobox with available certificates
            try {
                keyStore.aliases().asIterator().forEachRemaining(certAlias -> {
                    try {
                        // Only process certificate entries
                        if (keyStore.isCertificateEntry(certAlias)) {
                            // Get certificate information
                            java.security.cert.Certificate cert = keyStore.getCertificate(certAlias);

                            if (cert instanceof java.security.cert.X509Certificate x509Cert) {
                                String subject = x509Cert.getSubjectX500Principal().getName();
                                certComboBox.addItem(certAlias + " - " + subject);
                            }
                        }
                    } catch (KeyStoreException ex) {
                        // Skip this alias if there's an error
                        LOG.warn("Error processing certificate alias: {}", certAlias, ex);
                    }
                });
            } catch (Exception ex) {
                LOG.warn("Error loading certificate information", ex);
            }

            // Add listener to update fields when a certificate is selected
            certComboBox.addActionListener(evt -> {
                int selectedIndex = certComboBox.getSelectedIndex();
                if (selectedIndex > 0) { // Not "Create new certificate"
                    String selectedItem = (String) certComboBox.getSelectedItem();
                    String certAlias = selectedItem.substring(0, selectedItem.indexOf(" - "));

                    try {
                        java.security.cert.Certificate cert = keyStore.getCertificate(certAlias);
                        if (cert instanceof java.security.cert.X509Certificate x509Cert) {
                            String subject = x509Cert.getSubjectX500Principal().getName();

                            // Parse the subject DN and update the fields
                            parseSubjectDN(subject, cnField, oField, ouField, cField, stField, lField, emailField);
                        }
                    } catch (Exception ex) {
                        LOG.warn("Error getting certificate information", ex);
                    }
                } else {
                    // Reset to default values
                    cnField.setText("License Key");
                    oField.setText("Your Organization");
                    ouField.setText("");
                    cField.setText("US");
                    stField.setText("");
                    lField.setText("");
                    emailField.setText("");
                }
            });

            // Create a helper method to add a label with info icon and tooltip
            JPanel panel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]5[]5[]5[]5[]5[]5[]5[]5[]5[]"));

            // Add certificate selection combobox
            addLabeledComboBoxWithTooltip(panel, "Certificate:",
                    "Select an existing certificate or create a new one", certComboBox);

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

        JButton exportKeystoreButton = new JButton("Export public keys and certificates to new Keystore");
        exportKeystoreButton.addActionListener(e -> {
            int row = keysTable.getSelectedRow();
            if (row < 0) {
                JOptionPane.showMessageDialog(mainFrame, "Please select a key to export.", ERROR, JOptionPane.ERROR_MESSAGE);
                return;
            }

            String alias = (String) keysTable.getValueAt(row, 0);

            try {
                exportKeystore(alias);
            } catch (Exception ex) {
                LOG.warn("Error exporting keystore", ex);
                JOptionPane.showMessageDialog(mainFrame, "Error exporting keystore: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
            }
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(addKeyButton);
        buttonPanel.add(deleteKeyButton);
        buttonPanel.add(exportKeystoreButton);
        buttonPanel.add(refreshButton);
        keysPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Initial population of the table
        updateKeysTable();
    }

    /**
     * Creates the Licenses panel with buttons for creating and validating licenses.
     */
    private void createLicensesPanel() {
        // Use the LicenseEditor to create the licenses panel
        licensesPanel = licenseEditor.createLicensesPanel();
    }

    /**
     * Creates the Certificates panel with a table showing certificate information.
     */
    private void createCertificatesPanel() {
        certificatesPanel = new JPanel(new BorderLayout(10, 10));
        certificatesPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create table model with columns for certificate information
        String[] columnNames = {"Alias", "Subject", "Issuer", "Valid From", "Valid To"};
        certificatesTableModel = new javax.swing.table.DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // No columns are editable
                return false;
            }
        };

        // Create table
        certificatesTable = new javax.swing.JTable(certificatesTableModel);
        certificatesTable.setFillsViewportHeight(true);
        certificatesTable.setRowHeight(25);

        // Set column widths
        certificatesTable.getColumnModel().getColumn(0).setPreferredWidth(100); // Alias
        certificatesTable.getColumnModel().getColumn(1).setPreferredWidth(200); // Subject
        certificatesTable.getColumnModel().getColumn(2).setPreferredWidth(200); // Issuer
        certificatesTable.getColumnModel().getColumn(3).setPreferredWidth(100); // Valid From
        certificatesTable.getColumnModel().getColumn(4).setPreferredWidth(100); // Valid To

        // Add tooltips to show full text when it doesn't fit
        certificatesTable.addMouseMotionListener(new java.awt.event.MouseMotionAdapter() {
            @Override
            public void mouseMoved(java.awt.event.MouseEvent e) {
                int row = certificatesTable.rowAtPoint(e.getPoint());
                int col = certificatesTable.columnAtPoint(e.getPoint());
                if (row >= 0 && col >= 0) {
                    Object value = certificatesTable.getValueAt(row, col);
                    if (value != null) {
                        certificatesTable.setToolTipText(value.toString());
                    } else {
                        certificatesTable.setToolTipText(null);
                    }
                }
            }
        });

        // Add mouse listener for double-click to show certificate details
        certificatesTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = certificatesTable.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        String alias = (String) certificatesTable.getValueAt(row, 0);
                        new CertificateDetailsDialog(mainFrame, keystoreManager.getKeyStore(), alias, keystoreManager.getKeystorePath()).showDialog();
                    }
                }
            }
        });

        // Add table to scroll pane
        JScrollPane scrollPane = new JScrollPane(certificatesTable);
        certificatesPanel.add(scrollPane, BorderLayout.CENTER);

        // Add buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(new JButton(SwingUtil.createAction("New Certificate", this::newCertificate)));
        buttonPanel.add(new JButton(SwingUtil.createAction("Import from File", this::importCertificateFile)));
        buttonPanel.add(new JButton(SwingUtil.createAction("Import as Text", this::importCertificateFomText)));
        buttonPanel.add(new JButton(SwingUtil.createAction("Remove Certificate", this::removeCertificate)));
        buttonPanel.add(new JButton(SwingUtil.createAction("Refresh Certificates", this::updateCertificatesTable)));
        certificatesPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Initial population of the table
        updateCertificatesTable();
    }

    /**
     * Parses a subject Distinguished Name (DN) and extracts its components into the provided text fields.
     *
     * @param subjectDN  The subject DN to parse
     * @param cnField    The field for Common Name (CN)
     * @param oField     The field for Organization (O)
     * @param ouField    The field for Organizational Unit (OU)
     * @param cField     The field for Country (C)
     * @param stField    The field for State/Province (ST)
     * @param lField     The field for Locality (L)
     * @param emailField The field for Email Address
     */
    private void parseSubjectDN(String subjectDN, JTextField cnField, JTextField oField, JTextField ouField,
                                JTextField cField, JTextField stField, JTextField lField, JTextField emailField) {
        // Reset all fields
        cnField.setText("");
        oField.setText("");
        ouField.setText("");
        cField.setText("");
        stField.setText("");
        lField.setText("");
        emailField.setText("");

        // Split the DN into components
        String[] parts = subjectDN.split(",");
        for (String part : parts) {
            part = part.trim();
            int equalsIndex = part.indexOf('=');
            if (equalsIndex > 0) {
                String key = part.substring(0, equalsIndex).trim();
                String value = part.substring(equalsIndex + 1).trim();

                switch (key) {
                    case "CN" -> cnField.setText(value);
                    case "O" -> oField.setText(value);
                    case "OU" -> ouField.setText(value);
                    case "C" -> cField.setText(value);
                    case "ST" -> stField.setText(value);
                    case "L" -> lField.setText(value);
                    case "EMAILADDRESS" -> emailField.setText(value);
                    default -> LOG.warn("Unknown subject DN key: {}", key);
                }
            }
        }
    }

    /**
     * Adds a labeled combobox with an information icon that shows a tooltip with the combobox's description.
     *
     * @param panel       The panel to add the components to
     * @param labelText   The text for the label
     * @param description The description to show in the tooltip
     * @param comboBox    The combobox to add
     */
    private void addLabeledComboBoxWithTooltip(JPanel panel, String labelText, String description, JComboBox<?> comboBox) {
        // Create and add the label
        JLabel label = new JLabel(labelText);
        panel.add(label);

        // Add the label panel and combobox to the main panel
        panel.add(comboBox, "grow x");

        // Create the info icon with tooltip
        JLabel infoIcon = new JLabel(INFO_SYMBOL);
        infoIcon.setToolTipText(description);
        panel.add(infoIcon, "wrap");
    }

    /**
     * Adds a labeled field with an information icon that shows a tooltip with the field's description.
     *
     * @param panel       The panel to add the components to
     * @param labelText   The text for the label
     * @param description The description to show in the tooltip
     * @param field       The text field to add
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
        String fileName = String.valueOf(keystorePath.getFileName());
        int dotIndex = fileName.lastIndexOf('.');
        String baseName = (dotIndex > 0) ? fileName.substring(0, dotIndex) : fileName;
        String extension = (dotIndex > 0) ? fileName.substring(dotIndex) : "";
        Path backupPath = keystorePath.resolveSibling(baseName + "-" + timestamp + extension);

        // Copy the file
        Files.copy(keystorePath, backupPath);
        LOG.debug("Created keystore backup at: {}", backupPath);
    }

    private void updateKeyAliasComboBox() {
        KeyStore keyStore = keystoreManager.getKeyStore();

        LOG.debug("Updating key alias combo box");
        licenseKeyAliasComboBox.removeAllItems();

        try {
            keyStore.aliases().asIterator().forEachRemaining(alias -> {
                try {
                    // Include both key entries and certificate entries
                    if (keyStore.isKeyEntry(alias) || keyStore.isCertificateEntry(alias)) {
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

    private void deleteKey(String alias) throws GeneralSecurityException, IOException {
        KeyStore keyStore = keystoreManager.getKeyStore();

        keyStore.deleteEntry(alias);
        Path keystorePath = keystoreManager.getKeystorePath();
        backupKeystoreFile(keystorePath);
        KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, keystoreManager.getPassword());
        updateKeyAliasComboBox();
    }

    /**
     * Exports only the public key and certificate to a new keystore instance.
     *
     * @param alias the alias of the key to export
     * @throws GeneralSecurityException if there is an error accessing the keystore
     * @throws IOException              if there is an error saving the keystore
     */
    private void exportKeystore(String alias) throws GeneralSecurityException, IOException {
        KeyStore sourceKeyStore = keystoreManager.getKeyStore();

        // Get the certificate from the keystore
        Certificate cert = sourceKeyStore.getCertificate(alias);
        if (cert == null) {
            JOptionPane.showMessageDialog(mainFrame, "No certificate found for alias: " + alias, ERROR, JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Show a file save dialog with the current keystore directory as the initial directory
        Path initialDir = keystoreManager.getKeystorePath().getParent();
        Optional<Path> selectedPath = SwingUtil.showFileSaveDialog(
                mainFrame,
                initialDir,
                Pair.of("Java Keystore File", new String[]{"jks"})
        );

        // Check if a path was selected
        if (selectedPath.isEmpty()) {
            return;
        }

        Path path = selectedPath.get();

        // Show password dialog
        JPanel passwordPanel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[][]"));
        passwordPanel.add(new JLabel("New Keystore Password:"));
        JPasswordField passwordField = new JPasswordField(20);
        passwordPanel.add(passwordField, "growx, wrap");

        passwordPanel.add(new JLabel("Confirm Password:"));
        JPasswordField confirmPasswordField = new JPasswordField(20);
        passwordPanel.add(confirmPasswordField, "growx");

        int result = JOptionPane.showConfirmDialog(
                mainFrame,
                passwordPanel,
                "Create Keystore Password",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );

        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        // Verify passwords match
        char[] password = passwordField.getPassword();
        char[] confirmPassword = confirmPasswordField.getPassword();

        if (!java.util.Arrays.equals(password, confirmPassword)) {
            JOptionPane.showMessageDialog(mainFrame,
                    "Passwords do not match. Please try again.",
                    "Password Mismatch",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            // Create a new KeyStore instance
            KeyStore newKeyStore = KeyStore.getInstance("PKCS12");
            newKeyStore.load(null, password);

            // Add the certificate to the new keystore
            newKeyStore.setCertificateEntry(alias, cert);

            // Save the new keystore
            KeyStoreUtil.saveKeyStoreToFile(newKeyStore, path, password);

            JOptionPane.showMessageDialog(mainFrame,
                    "Public key and certificate exported successfully to:\n" + path,
                    "Export Successful", JOptionPane.INFORMATION_MESSAGE);
        } finally {
            // Clear passwords from memory
            java.util.Arrays.fill(password, '\0');
            java.util.Arrays.fill(confirmPassword, '\0');
        }
    }

    private void newCertificate() {
        KeyStore keyStore = keystoreManager.getKeyStore();

        // Show a dialog to get certificate information
        JTextField aliasField = new JTextField(20);
        JTextField cnField = new JTextField("Certificate", 20);
        JTextField oField = new JTextField("Your Organization", 20);
        JTextField ouField = new JTextField("", 20);
        JTextField cField = new JTextField("US", 2);
        JTextField stField = new JTextField("", 20);
        JTextField lField = new JTextField("", 20);
        JTextField emailField = new JTextField("", 20);
        JTextField validDaysField = new JTextField("3650", 5);
        JCheckBox enableCACheckbox = new JCheckBox("Allow signing other certificates");
        enableCACheckbox.setToolTipText("When checked, this certificate can be used to sign other certificates");

        // Create a combobox for parent certificate selection
        JComboBox<String> parentCertComboBox = new JComboBox<>();
        parentCertComboBox.addItem("standalone (no parent)");

        // Populate the combobox with CA certificates
        try {
            keyStore.aliases().asIterator().forEachRemaining(alias -> {
                try {
                    // Only process certificate entries
                    if (keyStore.isCertificateEntry(alias)) {
                        // Get certificate information
                        java.security.cert.Certificate cert = keyStore.getCertificate(alias);

                        if (cert instanceof java.security.cert.X509Certificate x509Cert) {
                            // Check if this is a CA certificate
                            boolean[] keyUsage = x509Cert.getKeyUsage();
                            boolean isCA = false;
                            if (keyUsage != null && keyUsage.length > 5) {
                                // Key usage bit 5 is for keyCertSign
                                isCA = keyUsage[5];
                            }

                            if (isCA) {
                                parentCertComboBox.addItem(alias);
                            }
                        }
                    }
                } catch (Exception e) {
                    // Skip this alias if there's an error
                    LOG.warn("Error processing certificate alias: {}", alias, e);
                }
            });
        } catch (Exception e) {
            LOG.warn("Error loading CA certificates", e);
        }

        // Create a panel for the dialog
        JPanel panel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]5[]5[]5[]5[]5[]5[]5[]5[]5[]5[]"));

        // Add field with label, info icon, and tooltip
        addLabeledFieldWithTooltip(panel, "Certificate Alias:",
                "A unique identifier for this certificate in the keystore", aliasField);

        // Add parent certificate combobox
        addLabeledComboBoxWithTooltip(panel, "Parent Certificate:",
                "Select a parent certificate or 'standalone (no parent)' for a self-signed certificate", parentCertComboBox);

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

        // Add CA checkbox
        JLabel caLabel = new JLabel("CA:");
        panel.add(caLabel);
        panel.add(enableCACheckbox, "span 2, wrap");

        int result = JOptionPane.showConfirmDialog(mainFrame, panel, "Create New Certificate", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

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
                JOptionPane.showMessageDialog(mainFrame, "Please specify a certificate alias.", ERROR, JOptionPane.ERROR_MESSAGE);
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
                // Get the selected parent certificate (for logging purposes only)
                Optional<String> parentCertificateAlias = switch (parentCertComboBox.getSelectedItem()) {
                    case String s when !s.equals("standalone (no parent)") -> Optional.of(s);
                    default -> Optional.empty();
                };
                X509Certificate[] parentCertificateChain = parentCertificateAlias
                        .map(alias1 -> {
                            try {
                                return keyStore.getCertificateChain(alias1);
                            } catch (KeyStoreException e) {
                                throw new IllegalStateException(e);
                            }
                        })
                        .map(X509Certificate[].class::cast)
                        .orElse(new X509Certificate[]{});

                // Generate certificate
                boolean enableCA = enableCACheckbox.isSelected();
                KeyPair keyPair = KeyUtil.generateKeyPair(AsymmetricAlgorithm.RSA, 2048);
                X509Certificate[] certificate;
                if (parentCertificateChain.length == 0) {
                    // self-signed
                    certificate = CertificateUtil.createSelfSignedX509Certificate(keyPair, subject, validDays, enableCA);
                } else {
                    // with parent
                    PrivateKey parentPrivateKey = (PrivateKey) keyStore.getKey(
                            parentCertificateAlias.orElseThrow() + PRIVATEKEY_SUFFIX,
                            keystoreManager.getPassword()
                    );
                    certificate = CertificateUtil.createX509Certificate(
                            keyPair,
                            subject,
                            validDays,
                            enableCA,
                            parentPrivateKey,
                            parentCertificateChain
                    );
                }

                keyStore.setKeyEntry(
                        alias + PRIVATEKEY_SUFFIX,
                        keyPair.getPrivate(),
                        keystoreManager.getPassword(),
                        certificate
                );
                keyStore.setCertificateEntry(alias, certificate[0]);

                // Backup the keystore file before saving
                Path keystorePath = keystoreManager.getKeystorePath();
                backupKeystoreFile(keystorePath);

                KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, keystoreManager.getPassword());

                // Update the certificates table
                updateCertificatesTable();

                JOptionPane.showMessageDialog(mainFrame, "Certificate generated and stored successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (GeneralSecurityException | IOException ex) {
                LOG.warn("Error generating certificate", ex);
                JOptionPane.showMessageDialog(mainFrame, "Error generating certificate: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void importCertificateFile() {
        KeyStore keyStore = keystoreManager.getKeyStore();

        // Show a file open dialog to select a certificate file
        Path initialDir = keystoreManager.getKeystorePath().getParent();
        Optional<Path> selectedPath = SwingUtil.showFileOpenDialog(
                mainFrame,
                initialDir,
                Pair.of("Certificate Files", new String[]{"cer", "crt", "pem", "der"})
        );

        if (selectedPath.isEmpty()) {
            return;
        }

        // Show a dialog to get the alias
        String alias = JOptionPane.showInputDialog(mainFrame, "Enter an alias for this certificate:", "Add Certificate", JOptionPane.PLAIN_MESSAGE);
        if (alias == null || alias.trim().isEmpty()) {
            return;
        }

        try {
            // Load the certificate
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            Certificate cert;

            try (java.io.FileInputStream fis = new java.io.FileInputStream(selectedPath.get().toFile())) {
                cert = cf.generateCertificate(fis);
            }

            // Add to keystore
            keyStore.setCertificateEntry(alias.trim(), cert);

            // Save keystore
            Path keystorePath = keystoreManager.getKeystorePath();
            backupKeystoreFile(keystorePath);
            KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, keystoreManager.getPassword());

            // Update the table
            updateCertificatesTable();

            JOptionPane.showMessageDialog(mainFrame, "Certificate added successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            LOG.warn("Error adding certificate", ex);
            JOptionPane.showMessageDialog(mainFrame, "Error adding certificate: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importCertificateFomText() {
        KeyStore keyStore = keystoreManager.getKeyStore();

        // Show a text input dialog for pasting certificate content
        JTextField aliasField = new JTextField(20);
        JTextField certificateField = new JTextField(40);

        JPanel panel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]5[]"));

        addLabeledFieldWithTooltip(panel, "Certificate Alias:",
                "A unique identifier for this certificate in the keystore", aliasField);

        addLabeledFieldWithTooltip(panel, "Certificate Content (Base64):",
                "The Base64-encoded certificate content", certificateField);

        int result = JOptionPane.showConfirmDialog(mainFrame, panel, "Import Certificate", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String alias = aliasField.getText().trim();
            String certificateContent = certificateField.getText().trim();

            if (alias.isEmpty()) {
                JOptionPane.showMessageDialog(mainFrame, "Please specify a certificate alias.", ERROR, JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (certificateContent.isEmpty()) {
                JOptionPane.showMessageDialog(mainFrame, "Please provide certificate content.", ERROR, JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                // Decode and import the certificate
                byte[] certBytes = Base64.getDecoder().decode(certificateContent);
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                Certificate cert = cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));

                // Add to keystore
                keyStore.setCertificateEntry(alias, cert);

                // Save keystore
                Path keystorePath = keystoreManager.getKeystorePath();
                backupKeystoreFile(keystorePath);
                KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, keystoreManager.getPassword());

                // Update the table
                updateCertificatesTable();

                JOptionPane.showMessageDialog(mainFrame, "Certificate imported successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                LOG.warn("Error importing certificate", ex);
                JOptionPane.showMessageDialog(mainFrame, "Error importing certificate: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void removeCertificate() {
        KeyStore keyStore = keystoreManager.getKeyStore();

        int row = certificatesTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(mainFrame, "Please select a certificate to remove.", ERROR, JOptionPane.ERROR_MESSAGE);
            return;
        }

        String alias = (String) certificatesTable.getValueAt(row, 0);

        // Confirm deletion
        int confirm = JOptionPane.showConfirmDialog(mainFrame,
                "Are you sure you want to remove the certificate with alias: " + alias + "?",
                "Confirm Removal", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            removeFromKeyStore(keyStore, alias);
        }
    }

    /**
     * Updates the certificates table with the current keystore information.
     */
    private void updateCertificatesTable() {
        KeyStore keyStore = keystoreManager.getKeyStore();

        // Clear the table
        certificatesTableModel.setRowCount(0);

        try {
            keyStore.aliases().asIterator().forEachRemaining(alias -> {
                try {
                    // Only process certificate entries
                    if (keyStore.isCertificateEntry(alias)) {
                        // Get certificate information
                        java.security.cert.Certificate cert = keyStore.getCertificate(alias);

                        if (cert instanceof java.security.cert.X509Certificate x509Cert) {
                            String subject = x509Cert.getSubjectX500Principal().getName();
                            String issuer = x509Cert.getIssuerX500Principal().getName();
                            String validFrom = x509Cert.getNotBefore().toString();
                            String validTo = x509Cert.getNotAfter().toString();

                            certificatesTableModel.addRow(new Object[]{
                                    alias, subject, issuer, validFrom, validTo
                            });
                        } else {
                            // Non-X509 certificate
                            certificatesTableModel.addRow(new Object[]{
                                    alias, "Non-X509 Certificate", "Unknown", "Unknown", "Unknown"
                            });
                        }
                    }
                } catch (Exception e) {
                    // Skip this alias if there's an error
                    LOG.warn("Error processing certificate alias: {}", alias, e);
                }
            });
        } catch (Exception e) {
            LOG.warn("Error loading certificate information", e);
            JOptionPane.showMessageDialog(mainFrame, "Error loading certificate information: " + e.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
        }
    }

    private void removeFromKeyStore(KeyStore keyStore, String alias) {
        try {
            // Remove from keystore
            keyStore.deleteEntry(alias);

            // Save keystore
            Path keystorePath = keystoreManager.getKeystorePath();
            backupKeystoreFile(keystorePath);
            KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, keystoreManager.getPassword());

            // Update the table
            updateCertificatesTable();

            JOptionPane.showMessageDialog(mainFrame, "Certificate removed successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            LOG.warn("Error removing certificate", ex);
            JOptionPane.showMessageDialog(mainFrame, "Error removing certificate: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Retrieves the path to the templates directory.
     *
     * @return the path to the directory named "templates" in the application data directory
     */
    public static Path getTemplatesDirectory() {
        try {
            return IoUtil.getApplicationDataDir(LicenseManager.class.getName()).resolve("templates");
        } catch (IOException e) {
            LOG.error("Failed to create application data directory", e);
            // Fall back to local templates directory
            return Paths.get("templates");
        }
    }

}
