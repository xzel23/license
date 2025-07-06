package com.dua3.license.app;

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
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class responsible for license editing functionality.
 */
public class LicenseEditor {

    private static final Logger LOG = LogManager.getLogger(LicenseEditor.class);

    private final LocalDate today = LocalDate.now();
    private final JFrame parentFrame;

    /**
     * Constructs a new LicenseEditor.
     *
     * @param parentFrame the parent frame for dialogs
     */
    public LicenseEditor(JFrame parentFrame) {
        this.parentFrame = parentFrame;
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
        createLicenseButton.addActionListener(e -> {
            // Show dialog to create a license
            showCreateLicenseDialog();
        });
        buttonPanel.add(createLicenseButton);

        // Validate License button
        JButton validateLicenseButton = new JButton("Validate License");
        validateLicenseButton.addActionListener(e -> {
            // Show dialog to validate a license
            JOptionPane.showMessageDialog(parentFrame,
                    "Validate License functionality will be implemented here.",
                    "Validate License",
                    JOptionPane.INFORMATION_MESSAGE);
        });
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
                            "Error",
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
        panel.add(new JLabel(template.getName()), "growx, wrap");

        // Create input fields for each template value
        List<LicenseTemplate.LicenseField> fields = template.getFields();
        JTextField[] valueFields = new JTextField[fields.size()];
        for (int i = 0; i < fields.size(); i++) {
            LicenseTemplate.LicenseField field = fields.get(i);
            panel.add(new JLabel(field.name() + ":"));
            String defaultText = getDefaultText(field);
            valueFields[i] = new JTextField(defaultText, 20);
            panel.add(valueFields[i], "growx");
            if (defaultText.strip().startsWith("### ") && defaultText.strip().endsWith(" ###")) {
                valueFields[i].setEditable(false);
            }

            // Add info icon with tooltip showing the description
            JLabel infoLabel = new JLabel(LicenseManager.INFO_SYMBOL);
            String description = field.description();
            infoLabel.setToolTipText(description);
            infoLabel.setForeground(Color.BLUE);
            panel.add(infoLabel, "wrap");
        }

        // Show the dialog
        int result = JOptionPane.showConfirmDialog(
                parentFrame,
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
            JOptionPane.showMessageDialog(parentFrame,
                    "License would be created with the following properties:\n" + properties,
                    "License Creation",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private String getDefaultText(LicenseTemplate.LicenseField field) {
        String value = field.defaultValue();
        return switch (value) {
            case "${license_issue_date}" -> today.toString();
            case "${license_expiry_date}" -> today.plusYears(1).toString();
            case "${signature}" -> "### SIGNATURE ###";
            default -> value;
        };
    }
}
