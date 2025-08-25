package com.dua3.license.app;

import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.crypt.PasswordUtil;
import com.dua3.utility.data.Pair;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

/**
 * Dialog for displaying certificate details including subject information and public key.
 */
public class CertificateDetailsDialog {
    private static final Logger LOG = LogManager.getLogger(CertificateDetailsDialog.class);
    private static final String ERROR = "Error";
    private static final String WARNING = "Warning";
    private static final String DIALOG = "Dialog";
    private static final String DUMMY_PASSWORD = "************************";

    private final JFrame mainFrame;
    private final KeyStore keyStore;
    private final String alias;
    private final Path keystorePath;

    /**
     * Creates a new CertificateDetailsDialog.
     *
     * @param mainFrame    the parent frame
     * @param keyStore     the keystore containing the certificate
     * @param alias        the alias of the certificate to display
     * @param keystorePath the path to the keystore file
     */
    public CertificateDetailsDialog(JFrame mainFrame, KeyStore keyStore, String alias, Path keystorePath) {
        this.mainFrame = mainFrame;
        this.keyStore = keyStore;
        this.alias = alias;
        this.keystorePath = keystorePath;
    }

    /**
     * Shows the certificate details dialog.
     */
    public void showDialog() {
        LOG.debug("Showing certificate details for alias: {}", alias);

        try {
            // Get certificate information
            Certificate cert = keyStore.getCertificate(alias);
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

            // Check if this certificate contains private keys or sensitive data
            boolean containsPrivateKey = keyStore.isKeyEntry(alias);
            if (containsPrivateKey) {
                // Create warning panel
                JPanel warningPanel = new JPanel(new BorderLayout(5, 5));
                warningPanel.setBorder(javax.swing.BorderFactory.createCompoundBorder(
                        javax.swing.BorderFactory.createLineBorder(java.awt.Color.RED, 1),
                        javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10)
                ));

                // Create warning icon and label
                JLabel warningIcon = new JLabel(javax.swing.UIManager.getIcon("OptionPane.warningIcon"));
                JLabel warningText = new JLabel("This certificate contains private keys or sensitive data that should not be distributed.");
                warningText.setForeground(java.awt.Color.RED);
                warningText.setFont(new java.awt.Font(DIALOG, java.awt.Font.BOLD, 12));

                // Add components to warning panel
                JPanel textPanel = new JPanel(new BorderLayout());
                textPanel.setOpaque(false);
                textPanel.add(warningText, BorderLayout.CENTER);

                warningPanel.add(warningIcon, BorderLayout.WEST);
                warningPanel.add(textPanel, BorderLayout.CENTER);

                // Add warning panel to main panel
                panel.add(warningPanel);
                panel.add(javax.swing.Box.createVerticalStrut(10)); // Add some space after the warning
            }

            // ===== SECTION 1: Certificate Fields =====
            JPanel certificatePanel = new JPanel(new BorderLayout(5, 5));
            certificatePanel.setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 0, 10, 0));

            // Add headline for certificate fields
            JLabel certificateHeadline = new JLabel("Certificate Fields");
            certificateHeadline.setFont(new java.awt.Font(DIALOG, java.awt.Font.BOLD, 14));
            certificatePanel.add(certificateHeadline, BorderLayout.NORTH);

            // Create table for certificate fields
            String[] columnNames = {"Field", "Value"};
            javax.swing.table.DefaultTableModel tableModel = new javax.swing.table.DefaultTableModel(columnNames, 0);

            // Add certificate fields to table if it's an X509Certificate
            if (cert instanceof X509Certificate x509Cert) {
                // Add subject information
                String subjectDN = x509Cert.getSubjectX500Principal().getName();
                tableModel.addRow(new Object[]{"Subject", subjectDN});

                // Parse the subject DN into individual fields
                String[] subjectParts = subjectDN.split(",");
                for (String part : subjectParts) {
                    String[] keyValue = part.trim().split("=", 2);
                    if (keyValue.length == 2) {
                        tableModel.addRow(new Object[]{"Subject " + keyValue[0], keyValue[1]});
                    }
                }

                // Add issuer information
                String issuerDN = x509Cert.getIssuerX500Principal().getName();
                tableModel.addRow(new Object[]{"Issuer", issuerDN});

                // Parse the issuer DN into individual fields
                String[] issuerParts = issuerDN.split(",");
                for (String part : issuerParts) {
                    String[] keyValue = part.trim().split("=", 2);
                    if (keyValue.length == 2) {
                        tableModel.addRow(new Object[]{"Issuer " + keyValue[0], keyValue[1]});
                    }
                }

                // Add additional certificate information
                tableModel.addRow(new Object[]{"Serial Number", x509Cert.getSerialNumber().toString()});
                tableModel.addRow(new Object[]{"Version", x509Cert.getVersion()});
                tableModel.addRow(new Object[]{"Signature Algorithm", x509Cert.getSigAlgName()});
                tableModel.addRow(new Object[]{"Valid From", x509Cert.getNotBefore()});
                tableModel.addRow(new Object[]{"Valid Until", x509Cert.getNotAfter()});

                // Check if this is a CA certificate
                boolean[] keyUsage = x509Cert.getKeyUsage();
                boolean isCA = false;
                if (keyUsage != null && keyUsage.length > 5) {
                    // Key usage bit 5 is for keyCertSign
                    isCA = keyUsage[5];
                }
                tableModel.addRow(new Object[]{"CA Certificate", isCA ? "Yes" : "No"});

                // Add key information
                tableModel.addRow(new Object[]{"Public Key Algorithm", publicKey.getAlgorithm()});

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
            } else {
                // Non-X509 certificate
                tableModel.addRow(new Object[]{"Certificate Type", cert.getType()});
                tableModel.addRow(new Object[]{"Public Key Algorithm", publicKey.getAlgorithm()});
            }

            // Create table and add to panel
            javax.swing.JTable detailsTable = new javax.swing.JTable(tableModel);
            detailsTable.setDefaultEditor(Object.class, null); // Make table non-editable
            JScrollPane tableScrollPane = new JScrollPane(detailsTable);
            tableScrollPane.setPreferredSize(new java.awt.Dimension(500, 200));
            certificatePanel.add(tableScrollPane, BorderLayout.CENTER);

            // Add certificate panel to main panel
            panel.add(certificatePanel);

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

            JButton copyPemButton = new JButton("Copy PEM to Clipboard");
            copyPemButton.addActionListener(e -> {
                try {
                    // Get the certificate from the keystore
                    Certificate certForPem = keyStore.getCertificate(alias);
                    if (certForPem == null) {
                        JOptionPane.showMessageDialog(mainFrame, "No certificate found for alias: " + alias, ERROR, JOptionPane.ERROR_MESSAGE);
                        return;
                    }

                    // Format certificate in PEM format
                    byte[] certBytes = certForPem.getEncoded();
                    String encoded = Base64.getEncoder().encodeToString(certBytes);

                    // Split the Base64 string into lines of 64 characters
                    StringBuilder pemBuilder = new StringBuilder();
                    pemBuilder.append("-----BEGIN CERTIFICATE-----\n");
                    for (int i = 0; i < encoded.length(); i += 64) {
                        pemBuilder.append(encoded, i, Math.min(i + 64, encoded.length())).append('\n');
                    }
                    pemBuilder.append("-----END CERTIFICATE-----\n");

                    // Copy to clipboard
                    java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                            new java.awt.datatransfer.StringSelection(pemBuilder.toString()), null);
                    JOptionPane.showMessageDialog(mainFrame, "Certificate PEM copied to clipboard.", "Success", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    LOG.warn("Error copying certificate PEM to clipboard for alias: {}", alias, ex);
                    JOptionPane.showMessageDialog(mainFrame, "Error copying certificate PEM: " + ex.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
                }
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
            publicKeyButtonPanel.add(copyPemButton);
            publicKeyButtonPanel.add(copyPublicKeyButton);
            publicKeyPanel.add(publicKeyButtonPanel, BorderLayout.SOUTH);

            // Add public key panel to main panel
            panel.add(publicKeyPanel);

            // Show dialog
            JOptionPane.showMessageDialog(mainFrame, panel, "Certificate Details for " + alias, JOptionPane.INFORMATION_MESSAGE);

        } catch (RuntimeException | KeyStoreException e) {
            LOG.warn("Error retrieving certificate details for alias: {}", alias, e);
            JOptionPane.showMessageDialog(mainFrame, "Error retrieving certificate details: " + e.getMessage(), ERROR, JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Exports the certificate for the current alias to a file.
     *
     * @throws GeneralSecurityException if there is an error accessing the certificate
     * @throws IOException              if there is an error writing the certificate to a file
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
     * Exports only the certificate to a new keystore instance for distribution.
     *
     * @throws GeneralSecurityException if there is an error accessing the keystore
     * @throws IOException              if there is an error saving the keystore
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
        passwordPanel.add(confirmPasswordField, "growx, wrap");

        // Add "Suggest Password" button
        final JPasswordField finalPasswordField = passwordField;
        final JPasswordField finalConfirmPasswordField = confirmPasswordField;
        JButton suggestPasswordButton = new JButton("Suggest Password");
        char[] generatedPassword = PasswordUtil.generatePassword(20);
        suggestPasswordButton.addActionListener(e -> {
            finalPasswordField.setText(DUMMY_PASSWORD);
            finalConfirmPasswordField.setText(DUMMY_PASSWORD);

            // Copy to clipboard
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                    new java.awt.datatransfer.StringSelection(new String(generatedPassword)), null);

            // Show information popup
            JOptionPane.showMessageDialog(mainFrame,
                    "A secure password has been copied to the clipboard.\n" +
                            "Please store it in a safe place.",
                    "Password Generated",
                    JOptionPane.INFORMATION_MESSAGE);
        });
        passwordPanel.add(suggestPasswordButton, "align right");

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
        if (Arrays.equals(password, DUMMY_PASSWORD.toCharArray())) {
            password = generatedPassword;
        }
        char[] confirmPassword = confirmPasswordField.getPassword();
        if (Arrays.equals(confirmPassword, DUMMY_PASSWORD.toCharArray())) {
            confirmPassword = generatedPassword;
        }

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
                    "Certificate exported successfully to:\n" + path,
                    "Export Successful", JOptionPane.INFORMATION_MESSAGE);
        } finally {
            // Clear passwords from memory
            java.util.Arrays.fill(password, '\0');
            java.util.Arrays.fill(confirmPassword, '\0');
        }
    }
}