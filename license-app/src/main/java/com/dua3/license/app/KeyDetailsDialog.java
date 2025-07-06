package com.dua3.license.app;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Dialog for displaying key details including certificate information and public/private keys.
 */
public class KeyDetailsDialog {
    private static final Logger LOG = LogManager.getLogger(KeyDetailsDialog.class);
    
    private final JFrame mainFrame;
    private final KeyStore keyStore;
    private final String alias;
    
    /**
     * Creates a new KeyDetailsDialog.
     *
     * @param mainFrame the parent frame
     * @param keyStore the keystore containing the key
     * @param alias the alias of the key to display
     */
    public KeyDetailsDialog(JFrame mainFrame, KeyStore keyStore, String alias) {
        this.mainFrame = mainFrame;
        this.keyStore = keyStore;
        this.alias = alias;
    }
    
    /**
     * Shows the key details dialog.
     */
    public void showDialog() {
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
            JOptionPane.showMessageDialog(mainFrame, "Error retrieving key details: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * Shows the private key for the given alias after password verification.
     *
     * @param privateKeyTextArea the text area to display the private key in
     */
    private void showPrivateKey(JTextArea privateKeyTextArea) {
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
}