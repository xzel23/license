package com.dua3.license.app;

import com.dua3.license.DynamicEnum;
import com.dua3.license.License;
import com.dua3.utility.lang.Version;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.HeadlessException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.SequencedMap;
import java.util.prefs.Preferences;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jspecify.annotations.Nullable;

/**
 * Class responsible for license editing functionality.
 */
public class LicenseEditor {

    private static final Logger LOG = LogManager.getLogger(LicenseEditor.class);

    // file extensions and file filters
    private static final String DRAFT_FILE_EXTENSION = "license_draft";
    private static final String LICENSE_FILE_EXTENSION = "license";
    private static final FileNameExtensionFilter LICENSE_DRAFT_EXTENSION_FILTER = new FileNameExtensionFilter("License Draft Files (*.licensed)", DRAFT_FILE_EXTENSION);
    private static final FileNameExtensionFilter LICENSE_EXTENSION_FILTER = new FileNameExtensionFilter("License Files (*.license)", LICENSE_FILE_EXTENSION);

    // preferences paths
    private static final String PREF_LICENSE_DIRECTORY = "licenseDirectory";

    // placeholders for license field values
    private static final String SIGNING_KEY_PLACEHOLDER = "### SIGNING_KEY ###";
    private static final String SIGNATURE_PLACEHOLDER = "### SIGNATURE ###";

    // text constants
    private static final String HTML_OPEN = "<html>";
    private static final String HTML_CLOSE = "</html>";
    private static final String ERROR = "Error";
    private static final String SIGNING_KEY = "signingKey";
    private static final String SIGNATURE = "signature";
    private static final String GROWX = "growx";

    // placeholders for automatic fields
    /**
     * A placeholder variable representing the issue date of a license.
     */
    public static final String $ISSUE_DATE = "${license_issue_date}";
    /**
     * Represents the placeholder for the license expiry date within a template or configuration.
     */
    public static final String $EXPIRY_DATE = "${license_expiry_date}";
    /**
     * A placeholder variable representing the signing key used for cryptographic operations.
     */
    public static final String $SIGNING_KEY = "${signing_key}";
    /**
     * Represents a placeholder for the signature field in a license template.
     */
    public static final String $SIGNATURE = "${signature}";

    // instance data
    private final LocalDate today = LocalDate.now();
    private final JFrame parentFrame;
    private final KeystoreManager keystoreManager;

    /**
     * Represents a license draft that can be saved and loaded.
     */
    private static class LicenseDraft {
        private String templateName;
        private Map<String, String> fieldValues;

        // Default constructor for Jackson
        public LicenseDraft() {
            this.fieldValues = new LinkedHashMap<>();
        }

        public LicenseDraft(String templateName, Map<String, String> fieldValues) {
            this.templateName = templateName;
            this.fieldValues = new LinkedHashMap<>(fieldValues);
        }

        public String getTemplateName() {
            return templateName;
        }

        public void setTemplateName(String templateName) {
            this.templateName = templateName;
        }

        public Map<String, String> getFieldValues() {
            return fieldValues;
        }

        public void setFieldValues(Map<String, String> fieldValues) {
            this.fieldValues = fieldValues;
        }
    }

    /**
     * Constructs a LicenseEditor object with the provided parent frame and keystore manager.
     *
     * @param parentFrame the parent JFrame of this editor
     * @param keystoreManager the KeystoreManager instance to manage cryptographic operations
     */
    public LicenseEditor(JFrame parentFrame, KeystoreManager keystoreManager) {
        this.parentFrame = parentFrame;
        this.keystoreManager = keystoreManager;
    }

    /**
     * Gets the stored license directory from preferences or returns a default path if none is stored.
     *
     * @return the stored license directory or a default path
     */
    private Path getStoredLicenseDirectory() {
        Preferences prefs = Preferences.userNodeForPackage(LicenseEditor.class);
        String storedPath = prefs.get(PREF_LICENSE_DIRECTORY, null);
        return storedPath != null ? Paths.get(storedPath) : Paths.get(".");
    }

    /**
     * Saves the license directory to preferences.
     *
     * @param path the path to save
     */
    private void saveLicenseDirectory(Path path) {
        if (path != null) {
            Preferences prefs = Preferences.userNodeForPackage(LicenseEditor.class);
            prefs.put(PREF_LICENSE_DIRECTORY, path.toString());
        }
    }

    /**
     * Creates the Licenses panel with buttons for creating and validating licenses.
     *
     * @return the created licenses panel
     */
    public JPanel createLicensesPanel() {
        JPanel licensesPanel = new JPanel(new BorderLayout(10, 10));
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
        createLicenseButton.addActionListener(e -> showCreateLicenseDialog()); // Show dialog to create a license
        buttonPanel.add(createLicenseButton);

        // Validate License button
        JButton validateLicenseButton = new JButton("Validate License");
        validateLicenseButton.addActionListener(e -> validateLicense(null)); // Show dialog to validate a license
        buttonPanel.add(validateLicenseButton);

        // Manage Templates button
        JButton manageTemplatesButton = new JButton("Manage Templates");
        manageTemplatesButton.addActionListener(e -> {
            // Show the template editor dialog
            LicenseTemplateEditor editor = new LicenseTemplateEditor(parentFrame);
            editor.setVisible(true);
        });
        buttonPanel.add(manageTemplatesButton);

        contentPanel.add(buttonPanel, BorderLayout.CENTER);

        // Add the content panel to the licenses panel
        licensesPanel.add(contentPanel, BorderLayout.CENTER);

        return licensesPanel;
    }

    /**
     * Shows a dialog to create a license using a template.
     */
    public void showCreateLicenseDialog() {
        // Get available templates
        String[] templates = LicenseTemplateEditor.getAvailableTemplates();

        if (templates.length == 0) {
            JOptionPane.showMessageDialog(parentFrame,
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
                parentFrame,
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
                    Path jsonFile = LicenseManager.getTemplatesDirectory().resolve(selectedTemplate + ".json");
                    LicenseTemplate template = LicenseTemplate.loadTemplate(jsonFile);
                    // Show license creation form with the template
                    showLicenseCreationForm(template);
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(parentFrame,
                            "Failed to load the selected template.",
                            ERROR,
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    /**
     * Shows a form to create a license using the selected template.
     *
     * @param template the DynamicEnum template
     */
    public void showLicenseCreationForm(LicenseTemplate template) {
        // Create the dialog panel
        JPanel panel = new JPanel(new MigLayout("fillx", "[][grow][]", "[]10[]"));

        // Add a label for the template
        panel.add(new JLabel("Template:"));
        panel.add(new JLabel(template.getName()), "growx, span 2, wrap");

        // Add buttons for save/load draft
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveDraftButton = new JButton("Save Draft");
        JButton loadDraftButton = new JButton("Load Draft");
        buttonPanel.add(saveDraftButton);
        buttonPanel.add(loadDraftButton);
        panel.add(buttonPanel, "span 3, growx, wrap");

        // Create a map to store field values for saving/loading
        Map<String, String> fieldValues = new LinkedHashMap<>();

        // Create input fields for each template value
        List<LicenseTemplate.LicenseField> fields = template.getFields();
        Object[] valueComponents = new Object[fields.size()];
        Map<String, Integer> specialFieldIndices = new LinkedHashMap<>();

        for (int i = 0; i < fields.size(); i++) {
            LicenseTemplate.LicenseField field = fields.get(i);
            panel.add(new JLabel(field.name() + ":"));
            String defaultText = getDefaultText(field);

            if (SIGNING_KEY_PLACEHOLDER.equals(defaultText)) {
                // Create a dropdown for signing keys
                JComboBox<String> keyComboBox = new JComboBox<>();
                populateSigningKeyComboBox(keyComboBox);
                valueComponents[i] = keyComboBox;
                panel.add(keyComboBox, GROWX);
                specialFieldIndices.put(SIGNING_KEY, i);
            } else if (SIGNATURE_PLACEHOLDER.equals(defaultText)) {
                // Create a text field for the signature (will be filled later)
                JTextField textField = new JTextField(defaultText, 20);
                textField.setEditable(false);
                valueComponents[i] = textField;
                panel.add(textField, GROWX);
                specialFieldIndices.put(SIGNATURE, i);
            } else {
                // Create a text field for other values
                JTextField textField = new JTextField(defaultText, 20);
                valueComponents[i] = textField;
                panel.add(textField, GROWX);
            }

            // Add info icon with tooltip showing the description
            JLabel infoLabel = new JLabel(LicenseManager.INFO_SYMBOL);
            String description = field.description();
            infoLabel.setToolTipText(description);
            infoLabel.setForeground(Color.BLUE);
            panel.add(infoLabel, "wrap");
        }

        // Add action listener for save draft button
        saveDraftButton.addActionListener(e -> {
            // Collect current field values
            for (int i = 0; i < fields.size(); i++) {
                String fieldName = fields.get(i).name();

                if (valueComponents[i] instanceof JTextField textField) {
                    fieldValues.put(fieldName, textField.getText());
                } else if (valueComponents[i] instanceof JComboBox<?> comboBox
                        && comboBox.getSelectedItem() instanceof Object selectedItem) {
                    fieldValues.put(fieldName, selectedItem.toString());
                }
            }

            // Save the draft
            saveLicenseDraft(template, fieldValues);
        });

        // Add action listener for load draft button
        loadDraftButton.addActionListener(e -> {
            // Load the draft
            LicenseDraft draft = loadLicenseDraft();

            if (draft != null) {
                // Check if the template matches
                if (!template.getName().equals(draft.getTemplateName())) {
                    int confirm = JOptionPane.showConfirmDialog(
                            parentFrame,
                            "The loaded draft was created with template '" + draft.getTemplateName() + 
                            "', but the current template is '" + template.getName() + "'.\n" +
                            "Do you want to continue loading this draft?",
                            "Template Mismatch",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE
                    );

                    if (confirm != JOptionPane.YES_OPTION) {
                        return;
                    }
                }

                // Populate fields with loaded values
                Map<String, String> loadedValues = draft.getFieldValues();
                for (int i = 0; i < fields.size(); i++) {
                    String fieldName = fields.get(i).name();
                    String value = loadedValues.get(fieldName);

                    if (value != null) {
                        if (valueComponents[i] instanceof JTextField textField) {
                            textField.setText(value);
                        } else if (valueComponents[i] instanceof JComboBox<?> comboBox) {
                            for (int j = 0; j < comboBox.getItemCount(); j++) {
                                if (comboBox.getItemAt(j).equals(value)) {
                                    comboBox.setSelectedIndex(j);
                                    break;
                                }
                            }
                        }
                    }
                }

                JOptionPane.showMessageDialog(parentFrame,
                        "License draft loaded successfully.",
                        "Draft Loaded",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // Show the dialog
        int result = JOptionPane.showConfirmDialog(
                parentFrame,
                panel,
                "Create License with Template: " + template.getName(),
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );

        if (result == JOptionPane.OK_OPTION) {
            try {
                // Get the selected signing key
                if (!specialFieldIndices.containsKey(SIGNING_KEY)) {
                    JOptionPane.showMessageDialog(parentFrame,
                            "No signing key field found in the template.",
                            ERROR,
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                if (!specialFieldIndices.containsKey(SIGNATURE)) {
                    JOptionPane.showMessageDialog(parentFrame,
                            "No signature field found in the template.",
                            ERROR,
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Get the selected key alias
                int signingKeyIndex = specialFieldIndices.get(SIGNING_KEY);
                JComboBox<?> keyComboBox = (JComboBox<?>) valueComponents[signingKeyIndex];
                String keyAlias = (String) keyComboBox.getSelectedItem();

                if (keyAlias == null) {
                    JOptionPane.showMessageDialog(parentFrame,
                            "Please select a signing key.",
                            ERROR,
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Create a map of properties for the license
                Map<String, Object> properties = new LinkedHashMap<>();
                for (int i = 0; i < fields.size(); i++) {
                    String fieldName = fields.get(i).name();

                    if (i == signingKeyIndex) {
                        // Use the selected key alias
                        properties.put(fieldName, keyAlias);
                    } else if (i != specialFieldIndices.get(SIGNATURE)) {
                        // Get the value from the text field, but skip the signature field
                        JTextField textField = (JTextField) valueComponents[i];
                        properties.put(fieldName, textField.getText());
                    }
                }

                // Get the keystore
                KeyStore keyStore = keystoreManager.getKeyStore();
                if (keyStore == null) {
                    JOptionPane.showMessageDialog(parentFrame,
                            "No keystore loaded.",
                            ERROR,
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Create a file chooser
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Save License");
                fileChooser.setFileFilter(LICENSE_EXTENSION_FILTER);

                // Set current directory to the stored license directory
                Path storedDir = getStoredLicenseDirectory();
                if (Files.exists(storedDir) && Files.isDirectory(storedDir)) {
                    fileChooser.setCurrentDirectory(storedDir.toFile());
                }

                // Set default file name using LICENSE_ID if available
                String defaultFileName = "license";
                if (properties.containsKey("LICENSE_ID")) {
                    defaultFileName = properties.get("LICENSE_ID").toString();
                }
                fileChooser.setSelectedFile(new java.io.File(defaultFileName + "." + LICENSE_FILE_EXTENSION));

                // Show save dialog
                int userSelection = fileChooser.showSaveDialog(parentFrame);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    Path filePath = fileChooser.getSelectedFile().toPath();

                    // Add extension if not present
                    if (!filePath.toString().toLowerCase().endsWith("." + LICENSE_FILE_EXTENSION)) {
                        filePath = Paths.get(filePath.toString() + "." + LICENSE_FILE_EXTENSION);
                    }

                    try (OutputStream out = Files.newOutputStream(filePath)) {
                        // Get the dynamic enum from the template
                        DynamicEnum dynamicEnum = template.createDynamicEnum();

                        // Create the license using the dynamic enum
                        SequencedMap<String, Object> licenseData = License.createLicense(
                                dynamicEnum,
                                properties,
                                () -> keyStore,
                                () -> {
                                    try {
                                        return keystoreManager.getKeystorePassword();
                                    } catch (GeneralSecurityException e) {
                                        throw new RuntimeException("Failed to get keystore password", e);
                                    }
                                }
                        );

                        ObjectMapper mapper = new ObjectMapper();
                        mapper.writeValue(out, licenseData);

                        // Save the directory to preferences
                        saveLicenseDirectory(filePath.getParent());

                        // Get the signature from the properties
                        int signatureIndex = specialFieldIndices.get(SIGNATURE);
                        String signatureFieldName = fields.get(signatureIndex).name();
                        
                        // Load the license to get the signature
                        Properties licenseProps = new Properties();
                        try (InputStream in = Files.newInputStream(filePath)) {
                            licenseProps.load(in);
                        }
                        
                        String signatureBase64 = licenseProps.getProperty(signatureFieldName);
                        
                        // Update the signature field in the UI
                        JTextField signatureField = (JTextField) valueComponents[signatureIndex];
                        signatureField.setText(signatureBase64);
                        
                        // Update the properties with the signature
                        properties.put(signatureFieldName, signatureBase64);
                        
                        JOptionPane.showMessageDialog(parentFrame,
                                "License saved successfully to " + filePath,
                                "License Saved",
                                JOptionPane.INFORMATION_MESSAGE);
                    } catch (IOException | GeneralSecurityException e) {
                        LOG.error("Error creating license", e);
                        JOptionPane.showMessageDialog(parentFrame,
                                "Error creating license: " + e.getMessage(),
                                ERROR,
                                JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                } else {
                    // User cancelled the save dialog
                    return;
                }

                // Create a table to display license properties
                JPanel licenseDataPanel = new JPanel(new BorderLayout());
                licenseDataPanel.add(new JLabel("License created successfully with the following properties:"), BorderLayout.NORTH);

                // Create table data
                String[] columnNames = {"Property", "Value"};
                Object[][] data = new Object[properties.size()][2];

                int i = 0;
                for (Map.Entry<String, Object> entry : properties.entrySet()) {
                    data[i][0] = entry.getKey();

                    // Format value with line breaks for long text
                    String value = String.valueOf(entry.getValue());
                    if (value.length() > 80) {
                        StringBuilder sb = new StringBuilder();
                        int index = 0;
                        while (index < value.length()) {
                            int end = Math.min(index + 80, value.length());
                            if (end < value.length() && Character.isLetterOrDigit(value.charAt(end)) 
                                && Character.isLetterOrDigit(value.charAt(end - 1))) {
                                // Try to break at a non-alphanumeric character
                                int breakPoint = end - 1;
                                while (breakPoint > index && Character.isLetterOrDigit(value.charAt(breakPoint))) {
                                    breakPoint--;
                                }
                                if (breakPoint > index) {
                                    end = breakPoint + 1;
                                }
                            }
                            sb.append(value, index, end).append("<br>");
                            index = end;
                        }
                        value = HTML_OPEN + sb + HTML_CLOSE;
                    }
                    data[i][1] = value;
                    i++;
                }

                // Create table with custom renderer for line breaks
                javax.swing.JTable table = new javax.swing.JTable(data, columnNames);
                table.getColumnModel().getColumn(0).setPreferredWidth(150);
                table.getColumnModel().getColumn(1).setPreferredWidth(450);
                table.setRowHeight(25);

                // Make rows taller for wrapped content
                for (i = 0; i < table.getRowCount(); i++) {
                    Object value = table.getValueAt(i, 1);
                    if (value != null && value.toString().startsWith(HTML_OPEN)) {
                        // Count the number of <br> tags to estimate height
                        String text = value.toString();
                        int lineCount = (int) text.chars().filter(ch -> ch == '>').count() - 1;
                        table.setRowHeight(i, Math.max(25, lineCount * 20));
                    }
                }

                // Add table to a scroll pane
                javax.swing.JScrollPane scrollPane = new javax.swing.JScrollPane(table);
                scrollPane.setPreferredSize(new java.awt.Dimension(600, 400));
                licenseDataPanel.add(scrollPane, BorderLayout.CENTER);

                // Show the dialog with the table
                JOptionPane.showMessageDialog(parentFrame,
                        licenseDataPanel,
                        "License Creation",
                        JOptionPane.INFORMATION_MESSAGE);

            } catch (HeadlessException e) {
                LOG.error("Error creating license", e);
                JOptionPane.showMessageDialog(parentFrame,
                        "Error creating license: " + e.getMessage(),
                        ERROR,
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String getDefaultText(LicenseTemplate.LicenseField field) {
        String value = field.defaultValue();
        return switch (value) {
            case $ISSUE_DATE -> today.toString();
            case $EXPIRY_DATE -> today.plusYears(1).toString();
            case $SIGNING_KEY -> SIGNING_KEY_PLACEHOLDER;
            case $SIGNATURE -> SIGNATURE_PLACEHOLDER;
            default -> value;
        };
    }

    /**
     * Saves the current license draft to a file.
     * 
     * @param template the license template
     * @param fieldValues the map of field values
     */
    private void saveLicenseDraft(LicenseTemplate template, Map<String, String> fieldValues) {
        try {
            // Create a file chooser
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Save License Draft");
            fileChooser.setFileFilter(LICENSE_DRAFT_EXTENSION_FILTER);

            // Set current directory to the stored license directory
            Path storedDir = getStoredLicenseDirectory();
            if (Files.exists(storedDir) && Files.isDirectory(storedDir)) {
                fileChooser.setCurrentDirectory(storedDir.toFile());
            }

            // Set default file name
            fileChooser.setSelectedFile(new java.io.File("license_draft.json"));

            // Show save dialog
            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                Path filePath = fileChooser.getSelectedFile().toPath();

                // Add .json extension if not present
                if (!filePath.toString().toLowerCase().endsWith("." + DRAFT_FILE_EXTENSION)) {
                    filePath = Paths.get(filePath + "." + DRAFT_FILE_EXTENSION);
                }

                // Create license draft object
                LicenseDraft draft = new LicenseDraft(template.getName(), fieldValues);

                // Save to file
                ObjectMapper mapper = new ObjectMapper();
                mapper.writerWithDefaultPrettyPrinter().writeValue(filePath.toFile(), draft);

                // Save the directory to preferences
                saveLicenseDirectory(filePath.getParent());

                JOptionPane.showMessageDialog(parentFrame,
                        "License draft saved successfully to " + filePath,
                        "Draft Saved",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            LOG.error("Error saving license draft", e);
            JOptionPane.showMessageDialog(parentFrame,
                    "Error saving license draft: " + e.getMessage(),
                    ERROR,
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Saves the generated license to a file.
     * 
     * @param properties the license properties
     */
    private void saveLicense(Map<String, Object> properties) {
        try {
            // Create a file chooser
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Save License");
            fileChooser.setFileFilter(LICENSE_EXTENSION_FILTER);

            // Set current directory to the stored license directory
            Path storedDir = getStoredLicenseDirectory();
            if (Files.exists(storedDir) && Files.isDirectory(storedDir)) {
                fileChooser.setCurrentDirectory(storedDir.toFile());
            }

            // Set default file name using LICENSE_ID if available
            String defaultFileName = "license";
            if (properties.containsKey("LICENSE_ID")) {
                defaultFileName = properties.get("LICENSE_ID").toString();
            }
            fileChooser.setSelectedFile(new java.io.File(defaultFileName + "." + LICENSE_FILE_EXTENSION));

            // Show save dialog
            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                Path filePath = fileChooser.getSelectedFile().toPath();

                // Add extension if not present
                if (!filePath.toString().toLowerCase().endsWith("." + LICENSE_FILE_EXTENSION)) {
                    filePath = Paths.get(filePath.toString() + "." + LICENSE_FILE_EXTENSION);
                }

                // Save to file
                ObjectMapper mapper = new ObjectMapper();
                mapper.writerWithDefaultPrettyPrinter().writeValue(filePath.toFile(), properties);

                // Save the directory to preferences
                saveLicenseDirectory(filePath.getParent());

                JOptionPane.showMessageDialog(parentFrame,
                        "License saved successfully to " + filePath,
                        "License Saved",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            LOG.error("Error saving license", e);
            JOptionPane.showMessageDialog(parentFrame,
                    "Error saving license: " + e.getMessage(),
                    ERROR,
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Loads a license draft from a file.
     * 
     * @return the loaded license draft, or null if loading was cancelled or failed
     */
    private LicenseDraft loadLicenseDraft() {
        try {
            // Create a file chooser
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Load License Draft");
            fileChooser.setFileFilter(LICENSE_DRAFT_EXTENSION_FILTER);

            // Set current directory to the stored license directory
            Path storedDir = getStoredLicenseDirectory();
            if (Files.exists(storedDir) && Files.isDirectory(storedDir)) {
                fileChooser.setCurrentDirectory(storedDir.toFile());
            }

            // Show open dialog
            int userSelection = fileChooser.showOpenDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                Path filePath = fileChooser.getSelectedFile().toPath();

                // Load from file
                ObjectMapper mapper = new ObjectMapper();
                LicenseDraft draft = mapper.readValue(filePath.toFile(), LicenseDraft.class);

                // Save the directory to preferences
                saveLicenseDirectory(filePath.getParent());

                return draft;
            }
        } catch (Exception e) {
            LOG.error("Error loading license draft", e);
            JOptionPane.showMessageDialog(parentFrame,
                    "Error loading license draft: " + e.getMessage(),
                    ERROR,
                    JOptionPane.ERROR_MESSAGE);
        }

        return null;
    }

    /**
     * Validates a license file.
     * This method allows the user to select a license file, then validates its signature
     * and checks if the license has expired.
     */
    private void validateLicense(@Nullable Version currentVersion) {
        try {
            // Create a file chooser
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Select License File to Validate");
            fileChooser.setFileFilter(LICENSE_EXTENSION_FILTER);

            // Set current directory to the stored license directory
            Path storedDir = getStoredLicenseDirectory();
            if (Files.exists(storedDir) && Files.isDirectory(storedDir)) {
                fileChooser.setCurrentDirectory(storedDir.toFile());
            }

            // Show open dialog
            int userSelection = fileChooser.showOpenDialog(parentFrame);

            if (userSelection != JFileChooser.APPROVE_OPTION) {
                return; // User cancelled
            }

            Path filePath = fileChooser.getSelectedFile().toPath();

            // Save the directory to preferences
            saveLicenseDirectory(filePath.getParent());

            // Load the license file
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> licenseData = mapper.readValue(filePath.toFile(), Map.class);

            if (currentVersion == null) {
                currentVersion = (Version) licenseData.get(License.MAX_VERSION_LICENSE_FIELD);
            }

            // Validation results
            StringBuilder validationResults = new StringBuilder();

            // Use the License.validate method to validate the license data
            boolean isValid = false;
            try {
                KeyStore keyStore = keystoreManager.getKeyStore();
                char[] password = keystoreManager.getPassword();
                isValid = License.validate(licenseData, keyStore, currentVersion, validationResults);
            } catch (GeneralSecurityException e) {
                LOG.warn("Error validating license: {}", e.getMessage(), e);
                validationResults.append("❌ Error validating license: ").append(e.getMessage()).append("\n");
            }

            // Display the validation results
            String title = isValid ? "License is Valid" : "License Validation Failed";

            // Create a panel to display validation results and license data
            JPanel licenseDataPanel = new JPanel(new BorderLayout());

            // Add validation summary at the top
            JLabel validationLabel = new JLabel(isValid ? 
                    "✅ License is valid" : 
                    "❌ License validation failed");
            validationLabel.setFont(new java.awt.Font("Dialog", java.awt.Font.BOLD, 14));
            validationLabel.setForeground(isValid ? new Color(0, 128, 0) : Color.RED);
            licenseDataPanel.add(validationLabel, BorderLayout.NORTH);

            // Create a panel for detailed validation results
            JPanel validationPanel = new JPanel(new BorderLayout());
            validationPanel.setBorder(javax.swing.BorderFactory.createTitledBorder("Validation Results"));

            // Use JTextArea with JScrollPane instead of JLabel for scrollable text
            javax.swing.JTextArea validationDetailsArea = new javax.swing.JTextArea(validationResults.toString());
            validationDetailsArea.setEditable(false);
            validationDetailsArea.setLineWrap(true);
            validationDetailsArea.setWrapStyleWord(true);
            javax.swing.JScrollPane validationScrollPane = new javax.swing.JScrollPane(validationDetailsArea);
            validationScrollPane.setPreferredSize(new java.awt.Dimension(600, 150));

            validationPanel.add(validationScrollPane, BorderLayout.CENTER);

            // Create table data for license properties
            String[] columnNames = {"Property", "Value"};
            Object[][] data = new Object[licenseData.size() - 1][2];

            int i = 0;
            for (Map.Entry<String, Object> entry : licenseData.entrySet()) {
                if (entry.getKey().equals(License.SIGNATURE_LICENSE_FIELD)) {
                    continue; // Skip the signature
                }

                data[i][0] = entry.getKey();

                // Format value with line breaks for long text
                String value = String.valueOf(entry.getValue());
                if (value.length() > 80) {
                    StringBuilder sb = new StringBuilder();
                    int index = 0;
                    while (index < value.length()) {
                        int end = Math.min(index + 80, value.length());
                        if (end < value.length() && Character.isLetterOrDigit(value.charAt(end))
                                && Character.isLetterOrDigit(value.charAt(end - 1))) {
                            // Try to break at a non-alphanumeric character
                            int breakPoint = end - 1;
                            while (breakPoint > index && Character.isLetterOrDigit(value.charAt(breakPoint))) {
                                breakPoint--;
                            }
                            if (breakPoint > index) {
                                end = breakPoint + 1;
                            }
                        }
                        sb.append(value, index, end).append("<br>");
                        index = end;
                    }
                    value = HTML_OPEN + sb.toString() + HTML_CLOSE;
                }
                data[i][1] = value;
                i++;
            }

            // Create table with custom renderer for line breaks
            javax.swing.JTable table = new javax.swing.JTable(data, columnNames);
            table.getColumnModel().getColumn(0).setPreferredWidth(150);
            table.getColumnModel().getColumn(1).setPreferredWidth(450);
            table.setRowHeight(25);

            // Make rows taller for wrapped content
            for (i = 0; i < table.getRowCount(); i++) {
                Object value = table.getValueAt(i, 1);
                if (value != null && value.toString().startsWith(HTML_OPEN)) {
                    // Count the number of <br> tags to estimate height
                    String text = value.toString();
                    int lineCount = (int) text.chars().filter(ch -> ch == '>').count() - 1;
                    table.setRowHeight(i, Math.max(25, lineCount * 20));
                }
            }

            // Add table to a scroll pane
            javax.swing.JScrollPane scrollPane = new javax.swing.JScrollPane(table);
            scrollPane.setPreferredSize(new java.awt.Dimension(600, 300));

            // Create a split panel for validation results and license data
            javax.swing.JSplitPane splitPane = new javax.swing.JSplitPane(
                    javax.swing.JSplitPane.VERTICAL_SPLIT,
                    validationPanel,
                    scrollPane);
            splitPane.setDividerLocation(150);
            splitPane.setPreferredSize(new java.awt.Dimension(600, 500));

            licenseDataPanel.add(splitPane, BorderLayout.CENTER);

            // Create a resizable dialog instead of using JOptionPane
            javax.swing.JDialog dialog = new javax.swing.JDialog(parentFrame, title, true);
            dialog.setLayout(new BorderLayout());
            dialog.add(licenseDataPanel, BorderLayout.CENTER);

            // Add a close button at the bottom
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton closeButton = new JButton("Close");
            closeButton.addActionListener(e -> dialog.dispose());
            buttonPanel.add(closeButton);
            dialog.add(buttonPanel, BorderLayout.SOUTH);

            // Set dialog properties
            dialog.setSize(650, 600);
            dialog.setResizable(true);
            dialog.setLocationRelativeTo(parentFrame);

            // Show the dialog
            dialog.setVisible(true);
        } catch (IOException e) {
            LOG.error("Error validating license", e);
            JOptionPane.showMessageDialog(
                    parentFrame,
                    "Error validating license: " + e.getMessage(),
                    "Validation Error",
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }

    /**
     * Populates a combo box with non-expired signing keys from the keystore.
     *
     * @param comboBox the combo box to populate
     */
    private void populateSigningKeyComboBox(JComboBox<String> comboBox) {
        KeyStore keyStore = keystoreManager.getKeyStore();
        if (keyStore == null) {
            LOG.warn("No keystore loaded, cannot populate signing key combo box");
            return;
        }

        comboBox.removeAllItems();

        try {
            Date now = new Date();
            keyStore.aliases().asIterator().forEachRemaining(alias -> {
                try {
                    if (keyStore.isKeyEntry(alias)) {
                        Certificate cert = keyStore.getCertificate(alias);
                        if (cert instanceof X509Certificate x509Cert) {
                            // Check if the certificate has not expired
                            try {
                                x509Cert.checkValidity(now);
                                // Add the alias to the combo box
                                comboBox.addItem(alias);
                            } catch (GeneralSecurityException e) {
                                // Certificate has expired or is not yet valid, skip it
                                LOG.debug("Skipping expired or not yet valid certificate: {}", alias);
                            }
                        }
                    }
                } catch (Exception e) {
                    LOG.warn("Error processing key alias for combo box: {}", alias, e);
                }
            });
        } catch (Exception e) {
            LOG.warn("Error loading key aliases", e);
            JOptionPane.showMessageDialog(parentFrame,
                    "Error loading key aliases: " + e.getMessage(),
                    ERROR,
                    JOptionPane.ERROR_MESSAGE
            );
        }
    }
}
