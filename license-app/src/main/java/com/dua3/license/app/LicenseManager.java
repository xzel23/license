package com.dua3.license.app;

import com.dua3.license.DynamicEnum;
import com.dua3.license.License;
import com.dua3.utility.crypt.AsymmetricAlgorithm;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.swing.SwingUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
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
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LicenseManager {

    private static final String APP_NAME = LicenseManager.class.getSimpleName();
    private static final String APP_DESCRIPTION = "License Manager";

    private JFrame mainFrame;
    private JTabbedPane tabbedPane;
    private JPanel keyManagementPanel;
    private JPanel licenseGenerationPanel;
    private JPanel licenseVerificationPanel;

    private JTextField keystorePathField;
    private JPasswordField keystorePasswordField;
    private JTextField keyAliasField;
    private JTextField keySubjectField;
    private JTextField keyValidDaysField;

    private JComboBox<String> licenseKeyAliasComboBox;
    private JPanel licenseFieldsPanel;
    private List<JTextField[]> licenseFieldRows = new ArrayList<>();

    private JTextArea licenseOutputArea;
    private JTextArea verificationOutputArea;

    private KeyStore keyStore;
    private Path keystorePath;

    public static void main(String[] args) {
        SwingUtil.setNativeLookAndFeel(APP_NAME);
        SwingUtilities.invokeLater(() -> {
            LicenseManager app = new LicenseManager();
            app.createAndShowGUI();
        });
    }

    private void createAndShowGUI() {
        mainFrame = new JFrame(APP_NAME);
        mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        mainFrame.setSize(800, 600);

        tabbedPane = new JTabbedPane();

        // Create panels for each tab
        createKeyManagementPanel();
        createLicenseGenerationPanel();
        createLicenseVerificationPanel();

        tabbedPane.addTab("Key Management", keyManagementPanel);
        tabbedPane.addTab("License Generation", licenseGenerationPanel);
        tabbedPane.addTab("License Verification", licenseVerificationPanel);

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

    private void createKeyManagementPanel() {
        keyManagementPanel = new JPanel(new MigLayout("fill, insets 10", "[right][grow]", "[]10[]10[]10[]10[]10[]"));

        // Keystore path
        keyManagementPanel.add(new JLabel("Keystore Path:"));
        keystorePathField = new JTextField(20);
        keyManagementPanel.add(keystorePathField, "split 2, growx");
        JButton browseButton = new JButton("Browse...");
        browseButton.addActionListener(e -> browseForKeystore());
        keyManagementPanel.add(browseButton, "wrap");

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

    private void browseForKeystore() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Keystore File");
        fileChooser.setFileFilter(new FileNameExtensionFilter("Keystore Files (*.jks, *.keystore)", "jks", "keystore"));

        if (fileChooser.showOpenDialog(mainFrame) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            keystorePathField.setText(selectedFile.getAbsolutePath());
        }
    }

    private void loadKeystore() {
        String path = keystorePathField.getText().trim();
        if (path.isEmpty()) {
            JOptionPane.showMessageDialog(mainFrame, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        char[] password = keystorePasswordField.getPassword();
        if (password.length == 0) {
            JOptionPane.showMessageDialog(mainFrame, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            keystorePath = Path.of(path);
            keyStore = KeyStoreUtil.loadKeyStoreFromFile(keystorePath, password);
            updateKeyAliasComboBox();
            JOptionPane.showMessageDialog(mainFrame, "Keystore loaded successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (GeneralSecurityException | IOException e) {
            JOptionPane.showMessageDialog(mainFrame, "Error loading keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void createKeystore() {
        String path = keystorePathField.getText().trim();
        if (path.isEmpty()) {
            JOptionPane.showMessageDialog(mainFrame, "Please specify a keystore path.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        char[] password = keystorePasswordField.getPassword();
        if (password.length == 0) {
            JOptionPane.showMessageDialog(mainFrame, "Please enter the keystore password.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            keystorePath = Path.of(path);
            // Create a new KeyStore instance directly
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, password);
            KeyStoreUtil.saveKeyStoreToFile(keyStore, keystorePath, password);
            JOptionPane.showMessageDialog(mainFrame, "Keystore created successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (GeneralSecurityException | IOException e) {
            JOptionPane.showMessageDialog(mainFrame, "Error creating keystore: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void generateKeyPair() {
        if (keyStore == null) {
            JOptionPane.showMessageDialog(mainFrame, "Please load or create a keystore first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String alias = keyAliasField.getText().trim();
        if (alias.isEmpty()) {
            JOptionPane.showMessageDialog(mainFrame, "Please specify a key alias.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String subject = keySubjectField.getText().trim();
        if (subject.isEmpty()) {
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
            JOptionPane.showMessageDialog(mainFrame, "Please enter a valid number of days.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        char[] password = keystorePasswordField.getPassword();
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
        } catch (GeneralSecurityException | IOException e) {
            JOptionPane.showMessageDialog(mainFrame, "Error generating key pair: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateKeyAliasComboBox() {
        if (keyStore == null) {
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
                }
            });
        } catch (Exception e) {
            JOptionPane.showMessageDialog(mainFrame, "Error loading key aliases: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void generateLicense() {
        if (keyStore == null) {
            JOptionPane.showMessageDialog(mainFrame, "Please load a keystore first.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String alias = (String) licenseKeyAliasComboBox.getSelectedItem();
        if (alias == null || alias.isEmpty()) {
            JOptionPane.showMessageDialog(mainFrame, "Please select a key alias.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        char[] password = keystorePasswordField.getPassword();
        if (password.length == 0) {
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
}
