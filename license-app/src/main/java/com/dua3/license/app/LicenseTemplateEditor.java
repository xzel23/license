package com.dua3.license.app;

import com.dua3.license.DynamicEnum;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.util.Properties;
import java.util.Vector;

/**
 * A dialog for editing license templates.
 * This allows creating, editing, and saving license templates as DynamicEnum objects.
 */
public class LicenseTemplateEditor extends JDialog {
    private static final Logger LOG = LogManager.getLogger(LicenseTemplateEditor.class);
    private static final String TEMPLATES_DIRECTORY = "templates";

    private final JTextField templateNameField;
    private final JTable propertiesTable;
    private final DefaultTableModel tableModel;

    /**
     * Creates a new LicenseTemplateEditor dialog.
     *
     * @param parent the parent frame
     */
    public LicenseTemplateEditor(JFrame parent) {
        super(parent, "License Template Editor", true);

        // Create templates directory if it doesn't exist
        try {
            Files.createDirectories(Paths.get(TEMPLATES_DIRECTORY));
        } catch (IOException e) {
            LOG.error("Failed to create templates directory", e);
        }

        // Set up the dialog
        setLayout(new BorderLayout(10, 10));
        setSize(600, 400);
        setLocationRelativeTo(parent);

        // Create the main panel
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create the template name panel
        JPanel namePanel = new JPanel(new MigLayout("fillx", "[][grow]", "[]"));
        namePanel.add(new JLabel("Template Name:"));
        templateNameField = new JTextField(20);
        namePanel.add(templateNameField, "growx");
        mainPanel.add(namePanel, BorderLayout.NORTH);

        // Create the properties table
        String[] columnNames = {"Property Name", "Property Value"};
        tableModel = new DefaultTableModel(columnNames, 0);
        propertiesTable = new JTable(tableModel);
        propertiesTable.setFillsViewportHeight(true);
        JScrollPane tableScrollPane = new JScrollPane(propertiesTable);
        mainPanel.add(tableScrollPane, BorderLayout.CENTER);

        // Create the button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton addButton = new JButton("Add Property");
        addButton.addActionListener(e -> addProperty());

        JButton removeButton = new JButton("Remove Property");
        removeButton.addActionListener(e -> removeProperty());

        JButton loadButton = new JButton("Load Template");
        loadButton.addActionListener(e -> loadTemplate());

        JButton saveButton = new JButton("Save Template");
        saveButton.addActionListener(e -> saveTemplate());

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dispose());

        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(loadButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(closeButton);

        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add the main panel to the dialog
        add(mainPanel);
    }

    /**
     * Adds a new empty property to the table.
     */
    private void addProperty() {
        tableModel.addRow(new Object[]{"", ""});
    }

    /**
     * Removes the selected property from the table.
     */
    private void removeProperty() {
        int selectedRow = propertiesTable.getSelectedRow();
        if (selectedRow != -1) {
            tableModel.removeRow(selectedRow);
        } else {
            JOptionPane.showMessageDialog(this,
                    "Please select a property to remove.",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    /**
     * Loads a template from a file.
     */
    private void loadTemplate() {
        JFileChooser fileChooser = new JFileChooser(TEMPLATES_DIRECTORY);
        fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                "Properties Files", "properties"));

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            try (InputStream input = new FileInputStream(selectedFile)) {
                Properties properties = new Properties();
                properties.load(input);

                // Set the template name from the file name (without extension)
                String fileName = selectedFile.getName();
                if (fileName.endsWith(".properties")) {
                    fileName = fileName.substring(0, fileName.length() - 11);
                }
                templateNameField.setText(fileName);

                // Clear the table and add the properties
                tableModel.setRowCount(0);
                for (String key : properties.stringPropertyNames()) {
                    tableModel.addRow(new Object[]{key, properties.getProperty(key)});
                }

            } catch (IOException e) {
                LOG.error("Failed to load template", e);
                JOptionPane.showMessageDialog(this,
                        "Failed to load template: " + e.getMessage(),
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Saves the current template to a file.
     */
    private void saveTemplate() {
        String templateName = templateNameField.getText().trim();
        if (templateName.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please enter a template name.",
                    "Missing Name",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Create a Properties object from the table data
        Properties properties = new Properties();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String key = (String) tableModel.getValueAt(i, 0);
            String value = (String) tableModel.getValueAt(i, 1);

            if (key != null && !key.trim().isEmpty()) {
                properties.setProperty(key, value != null ? value : "");
            }
        }

        if (properties.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please add at least one property.",
                    "No Properties",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Save the properties to a file
        File file = new File(TEMPLATES_DIRECTORY, templateName + ".properties");
        try (OutputStream output = new FileOutputStream(file)) {
            properties.store(output, "License Template: " + templateName);
            JOptionPane.showMessageDialog(this,
                    "Template saved successfully.",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            LOG.error("Failed to save template", e);
            JOptionPane.showMessageDialog(this,
                    "Failed to save template: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Creates a DynamicEnum from the current template.
     *
     * @return a DynamicEnum representing the template, or null if the template is invalid
     */
    public DynamicEnum createDynamicEnum() {
        // Create a Properties object from the table data
        Properties properties = new Properties();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String key = (String) tableModel.getValueAt(i, 0);
            String value = (String) tableModel.getValueAt(i, 1);

            if (key != null && !key.trim().isEmpty()) {
                properties.setProperty(key, value != null ? value : "");
            }
        }

        if (properties.isEmpty()) {
            return null;
        }

        return DynamicEnum.fromPropertiesWithValues(properties);
    }

    /**
     * Gets all available template names.
     *
     * @return an array of template names
     */
    public static String[] getAvailableTemplates() {
        try {
            Path templatesDir = Paths.get(TEMPLATES_DIRECTORY);
            if (!Files.exists(templatesDir)) {
                Files.createDirectories(templatesDir);
                return new String[0];
            }

            return Files.list(templatesDir)
                    .filter(path -> path.toString().endsWith(".properties"))
                    .map(path -> {
                        String fileName = path.getFileName().toString();
                        return fileName.substring(0, fileName.length() - 11);
                    })
                    .toArray(String[]::new);
        } catch (IOException e) {
            LOG.error("Failed to get available templates", e);
            return new String[0];
        }
    }

    /**
     * Loads a template from a file.
     *
     * @param templateName the name of the template to load
     * @return a DynamicEnum representing the template, or null if the template could not be loaded
     */
    public static DynamicEnum loadDynamicEnum(String templateName) {
        File file = new File(TEMPLATES_DIRECTORY, templateName + ".properties");
        if (!file.exists()) {
            return null;
        }

        try (InputStream input = new FileInputStream(file)) {
            Properties properties = new Properties();
            properties.load(input);

            if (properties.isEmpty()) {
                return null;
            }

            return DynamicEnum.fromPropertiesWithValues(properties);
        } catch (IOException e) {
            LOG.error("Failed to load template", e);
            return null;
        }
    }
}