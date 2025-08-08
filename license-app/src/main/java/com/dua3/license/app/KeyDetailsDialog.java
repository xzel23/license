package com.dua3.license.app;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.dua3.utility.crypt.PasswordUtil;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.Optional;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.data.Pair;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;

/**
 * Dialog for displaying key details including certificate information and public/private keys.
 */
public class KeyDetailsDialog {
    private static final Logger LOG = LogManager.getLogger(KeyDetailsDialog.class);
    private static final String ERROR = "Error";
    private static final String DIALOG = "Dialog";

    private final JFrame mainFrame;
    private final KeyStore keyStore;
    private final String alias;
    private final Path keystorePath;

    /**
     * Creates a new KeyDetailsDialog.
     *
     * @param mainFrame the parent frame
     * @param keyStore the keystore containing the key
     * @param alias the alias of the key to display
     * @param keystorePath the path to the keystore file
     */
    public KeyDetailsDialog(JFrame mainFrame, KeyStore keyStore, String alias, Path keystorePath) {
        this.mainFrame = mainFrame;
        this.keyStore = keyStore;
        this.alias = alias;
        this.keystorePath = keystorePath;
    }

    /**
     * Shows the key details dialog.
     */
    public void showDialog() {
        LOG.debug("Showing key details for alias: {}", alias);

        try {
            // Get certificate information
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            if (cert == null) {
                JOptionPane.showMessageDialog(mainFrame, "No certificate found for alias: " + alias, ERROR, JOptionPane.ERROR_MESSAGE);
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
            subjectHeadline.setFont(new java.awt.Font(DIALOG, java.awt.Font.BOLD, 14));
            subjectPanel.add(subjectHeadline, BorderLayout.NORTH);

            // Create table for subject fields
            String[] columnNames = {"Field", "Value"};
            javax.swing.table.DefaultTableModel tableModel = new javax.swing.table.DefaultTableModel(columnNames, 0);

            // Add subject fields to table if it's an X509Certificate
            if (cert instanceof java.security.cert.X509Certificate x509Cert) {
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
                if (publicKey instanceof java.security.interfaces.RSAKey k) {
                    keySize = k.getModulus().bitLength();
                } else if (publicKey instanceof java.security.interfaces.DSAKey k) {
                    keySize = k.getParams().getP().bitLength();
                } else if (publicKey instanceof java.security.interfaces.ECKey k) {
                    keySize = k.getParams().getCurve().getField().getFieldSize();
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
            publicKeyHeadline.setFont(new java.awt.Font(DIALOG, java.awt.Font.BOLD, 14));
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

            JButton exportCertButton = new JButton("Export Certificate");
            exportCertButton.addActionListener(e -> {
                try {
                    exportCertificate();
                } catch (Exception ex) {
                    LOG.warn("Error exporting certificate for alias: {}", alias, ex);
                    JOptionPane.showMessageDialog(mainFrame, "Error exporting certificate: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
                }
            });

            JButton exportForDistributionButton = new JButton("Export for Distribution");
            exportForDistributionButton.addActionListener(e -> {
                try {
                    exportForDistribution();
                } catch (Exception ex) {
                    LOG.warn("Error exporting keystore for distribution for alias: {}", alias, ex);
                    JOptionPane.showMessageDialog(mainFrame, "Error exporting keystore for distribution: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
                }
            });

            JPanel publicKeyButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            publicKeyButtonPanel.add(exportForDistributionButton);
            publicKeyButtonPanel.add(exportCertButton);
            publicKeyButtonPanel.add(copyPublicKeyButton);
            publicKeyPanel.add(publicKeyButtonPanel, BorderLayout.SOUTH);

            // Add public key panel to main panel
            panel.add(publicKeyPanel);

            // ===== SECTION 3: Private Key =====
            JPanel privateKeyPanel = new JPanel(new BorderLayout(5, 5));
            privateKeyPanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 0, 0, 0));

            // Add headline for private key
            JLabel privateKeyHeadline = new JLabel("Private Key");
            privateKeyHeadline.setFont(new java.awt.Font(DIALOG, java.awt.Font.BOLD, 14));
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
                    showPrivateKey(privateKeyTextArea);
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
            JOptionPane.showMessageDialog(mainFrame, "Error retrieving key details: " + e.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Shows the private key for the given alias after password verification.
     *
     * @param privateKeyTextArea the text area to display the private key in
     */
    private void showPrivateKey(JTextArea privateKeyTextArea) {
        LOG.debug("Attempting to show private key for alias: {}", alias);

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
                JOptionPane.showMessageDialog(mainFrame, "No private key found for alias: " + alias, ERROR, JOptionPane.ERROR_MESSAGE);
                return;
            }

            // Display the private key in the provided text area
            String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            privateKeyTextArea.setText(privateKeyString);
        } catch (GeneralSecurityException e) {
            LOG.warn("Error retrieving private key for alias: {}", alias, e);
            JOptionPane.showMessageDialog(mainFrame, "Error retrieving private key: " + e.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
        } finally {
            // Clear the password from memory
            java.util.Arrays.fill(enteredPassword, '\0');
        }
    }

    /**
     * Exports the certificate for the current key alias to a file.
     *
     * @throws GeneralSecurityException if there is an error accessing the certificate
     * @throws IOException if there is an error writing the certificate to a file
     */
    private void exportCertificate() throws GeneralSecurityException, IOException {
        LOG.debug("Exporting certificate for alias: {}", alias);

        // Get the certificate from the keystore
        Certificate cert = keyStore.getCertificate(alias);
        if (cert == null) {
            JOptionPane.showMessageDialog(mainFrame, "No certificate found for alias: " + alias, ERROR, JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Check if it's an X509Certificate
        if (!(cert instanceof X509Certificate)) {
            JOptionPane.showMessageDialog(mainFrame, "The certificate is not an X509 certificate.", ERROR, JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Create a file chooser with the current keystore directory as the initial directory
        JFileChooser fileChooser = new JFileChooser(Objects.requireNonNullElse(keystorePath.getParent(), Paths.get(".")).toString());
        fileChooser.setDialogTitle("Export Certificate");

        // Set default file name
        fileChooser.setSelectedFile(new java.io.File(alias + ".cer"));

        // Add file filters
        FileNameExtensionFilter derFilter = new FileNameExtensionFilter("DER Certificate (*.der)", "der");
        FileNameExtensionFilter pemFilter = new FileNameExtensionFilter("PEM Certificate (*.pem, *.crt, *.cer)", "pem", "crt", "cer");
        fileChooser.addChoosableFileFilter(derFilter);
        fileChooser.addChoosableFileFilter(pemFilter);
        fileChooser.setFileFilter(pemFilter); // Default to PEM format

        // Show save dialog
        int result = fileChooser.showSaveDialog(mainFrame);
        if (result != JFileChooser.APPROVE_OPTION) {
            return; // User cancelled
        }

        // Get selected file
        Path filePath = fileChooser.getSelectedFile().toPath();

        // Determine format based on selected filter or file extension
        boolean usePemFormat = true; // Default to PEM
        if (fileChooser.getFileFilter() == derFilter) {
            usePemFormat = false;
        } else if (!filePath.toString().toLowerCase().endsWith(".pem") &&
                !filePath.toString().toLowerCase().endsWith(".crt") &&
                !filePath.toString().toLowerCase().endsWith(".cer")) {
            // If PEM filter is selected but file doesn't have PEM extension, add .pem
            filePath = Path.of(filePath + ".pem");
        }

        // Export the certificate
        try (FileOutputStream fos = new FileOutputStream(filePath.toFile())) {
            if (usePemFormat) {
                // PEM format (Base64 encoded with header and footer)
                byte[] certBytes = cert.getEncoded();
                String encoded = Base64.getEncoder().encodeToString(certBytes);

                // Split the Base64 string into lines of 64 characters
                StringBuilder pemBuilder = new StringBuilder();
                pemBuilder.append("-----BEGIN CERTIFICATE-----\n");
                for (int i = 0; i < encoded.length(); i += 64) {
                    pemBuilder.append(encoded, i, Math.min(i + 64, encoded.length())).append('\n');
                }
                pemBuilder.append("-----END CERTIFICATE-----\n");

                fos.write(pemBuilder.toString().getBytes(StandardCharsets.UTF_8));
            } else {
                // DER format (binary)
                fos.write(cert.getEncoded());
            }
        }

        JOptionPane.showMessageDialog(mainFrame,
                "Certificate exported successfully to:\n" + filePath,
                "Export Successful", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * Exports only the public key and certificate to a new keystore instance for distribution.
     * This creates a keystore that can be used to verify licenses signed with this key.
     *
     * @throws GeneralSecurityException if there is an error accessing the keystore
     * @throws IOException if there is an error saving the keystore
     */
    private void exportForDistribution() throws GeneralSecurityException, IOException {
        LOG.debug("Exporting keystore for distribution with alias: {}", alias);

        // Get the certificate from the keystore
        Certificate cert = keyStore.getCertificate(alias);
        if (cert == null) {
            JOptionPane.showMessageDialog(mainFrame, "No certificate found for alias: " + alias, ERROR, JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Show a file save dialog with the current keystore directory as the initial directory
        Optional<Path> selectedPath = SwingUtil.showFileSaveDialog(
                mainFrame,
                keystorePath.getParent(),
                Pair.of("Java Keystore File", new String[]{"p12"})
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
}
