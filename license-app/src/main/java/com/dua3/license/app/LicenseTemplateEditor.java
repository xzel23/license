package com.dua3.license.app;

import com.dua3.license.DynamicEnum;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;

/**
 * A dialog for editing license templates.
 * This allows creating, editing, and saving license templates as DynamicEnum objects.
 */

/**
 * A model class for license template fields.
 */
class LicenseField {
    private String name;
    private String description;
    private String defaultValue;

    // Default constructor for Jackson
    public LicenseField() {
    }

    public LicenseField(String name, String description, String defaultValue) {
        this.name = name;
        this.description = description;
        this.defaultValue = defaultValue;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDefaultValue() {
        return defaultValue;
    }

    public void setDefaultValue(String defaultValue) {
        this.defaultValue = defaultValue;
    }
}

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
        setSize(1200, 400);
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
        String[] columnNames = {"Property Name", "Property Value", "Default Value"};
        tableModel = new DefaultTableModel(columnNames, 0);
        propertiesTable = new JTable(tableModel);
        propertiesTable.setFillsViewportHeight(true);
        propertiesTable.setDragEnabled(true);
        propertiesTable.setDropMode(DropMode.INSERT_ROWS);
        propertiesTable.setTransferHandler(new TableRowTransferHandler(propertiesTable));

        // Add a tooltip to indicate drag-and-drop functionality
        propertiesTable.setToolTipText("Drag and drop rows to reorder license fields");

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

        JButton generateEnumButton = new JButton("Generate enum");
        generateEnumButton.addActionListener(e -> generateEnum());

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dispose());

        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(loadButton);
        buttonPanel.add(saveButton);
        buttonPanel.add(generateEnumButton);
        buttonPanel.add(closeButton);

        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add the main panel to the dialog
        add(mainPanel);
    }

    /**
     * Adds a new empty property to the table.
     */
    private void addProperty() {
        tableModel.addRow(new Object[]{"", "", ""});
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
                "JSON Template Files", "json"));

        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String fileName = selectedFile.getName();

            // Set the template name from the file name (without extension)
            String templateName = fileName;
            if (fileName.endsWith(".json")) {
                templateName = fileName.substring(0, fileName.length() - 5);
                loadJsonTemplate(selectedFile, templateName);
            } else {
                JOptionPane.showMessageDialog(this,
                        "Unsupported file format. Please select a .json file.",
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }


    /**
     * Loads a template from a JSON file.
     * 
     * @param file the JSON file
     * @param templateName the name of the template
     */
    private void loadJsonTemplate(File file, String templateName) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            List<LicenseField> fields = mapper.readValue(file, new TypeReference<List<LicenseField>>() {});

            templateNameField.setText(templateName);

            // Clear the table and add the fields
            tableModel.setRowCount(0);
            for (LicenseField field : fields) {
                tableModel.addRow(new Object[]{field.getName(), field.getDescription(), field.getDefaultValue()});
            }

        } catch (IOException e) {
            LOG.error("Failed to load JSON template", e);
            JOptionPane.showMessageDialog(this,
                    "Failed to load template: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
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

        // Check if there are any properties
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this,
                    "Please add at least one property.",
                    "No Properties",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Always save as JSON
        saveAsJson(templateName);
    }

    /**
     * Saves the current template as a JSON file.
     * 
     * @param templateName the name of the template
     */
    private void saveAsJson(String templateName) {
        // Create a list of LicenseField objects from the table data
        List<LicenseField> fields = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String name = (String) tableModel.getValueAt(i, 0);
            String description = (String) tableModel.getValueAt(i, 1);
            String defaultValue = (String) tableModel.getValueAt(i, 2);

            if (name != null && !name.trim().isEmpty()) {
                fields.add(new LicenseField(
                        name,
                        description != null ? description : "",
                        defaultValue != null ? defaultValue : ""));
            }
        }

        if (fields.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Please add at least one property.",
                    "No Properties",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Save the fields to a JSON file
        File file = new File(TEMPLATES_DIRECTORY, templateName + ".json");
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.writerWithDefaultPrettyPrinter().writeValue(file, fields);
            JOptionPane.showMessageDialog(this,
                    "Template saved successfully as JSON.",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (IOException e) {
            LOG.error("Failed to save template as JSON", e);
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
            String defaultValue = (String) tableModel.getValueAt(i, 2);

            if (key != null && !key.trim().isEmpty()) {
                // Use default value if value is empty
                if ((value == null || value.trim().isEmpty()) && defaultValue != null && !defaultValue.trim().isEmpty()) {
                    properties.setProperty(key, defaultValue);
                } else {
                    properties.setProperty(key, value != null ? value : "");
                }
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

            // Get all template names from .json files only
            return Files.list(templatesDir)
                    .filter(path -> path.toString().endsWith(".json"))
                    .map(path -> {
                        String fileName = path.getFileName().toString();
                        return fileName.substring(0, fileName.length() - 5);
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
        // Only load from JSON
        File jsonFile = new File(TEMPLATES_DIRECTORY, templateName + ".json");
        if (jsonFile.exists()) {
            return loadDynamicEnumFromJson(jsonFile);
        }

        return null;
    }

    // Store field descriptions for templates
    private static final Map<String, Map<String, String>> templateDescriptions = new HashMap<>();

    /**
     * Loads a DynamicEnum from a JSON file.
     *
     * @param file the JSON file
     * @return a DynamicEnum representing the template, or null if the template could not be loaded
     */
    private static DynamicEnum loadDynamicEnumFromJson(File file) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            List<LicenseField> fields = mapper.readValue(file, new TypeReference<List<LicenseField>>() {});

            if (fields.isEmpty()) {
                return null;
            }

            Properties properties = new Properties();

            // Create a map to store descriptions for this template
            String templateName = file.getName();
            if (templateName.endsWith(".json")) {
                templateName = templateName.substring(0, templateName.length() - 5);
            }

            Map<String, String> descriptions = new HashMap<>();

            for (LicenseField field : fields) {
                // Use defaultValue as the primary value for the DynamicEnum
                String defaultValue = field.getDefaultValue();
                String description = field.getDescription();

                // Store the description for later use
                descriptions.put(field.getName(), description);

                // Use description only if defaultValue is empty
                properties.setProperty(field.getName(), defaultValue);
            }

            // Store the descriptions map for this template
            templateDescriptions.put(templateName, descriptions);

            return DynamicEnum.fromPropertiesWithValues(properties);
        } catch (IOException e) {
            LOG.error("Failed to load template from JSON", e);
            return null;
        }
    }

    /**
     * Gets the descriptions for a template.
     *
     * @param templateName the name of the template
     * @return a map of field names to descriptions, or an empty map if the template is not found
     */
    public static Map<String, String> getTemplateDescriptions(String templateName) {
        return templateDescriptions.getOrDefault(templateName, Collections.emptyMap());
    }

    /**
     * Generates a Java enum named "LicenseFields" from the current template.
     * The enum uses the key as name and contains a String description() method that returns the description.
     */
    private void generateEnum() {
        // Check if there are any properties
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this,
                    "Please add at least one property.",
                    "No Properties",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        StringBuilder enumCode = new StringBuilder();
        enumCode.append("public enum LicenseFields {\n");

        // Add enum constants
        boolean hasValidFields = false;
        List<String> validEnumEntries = new ArrayList<>();

        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String key = (String) tableModel.getValueAt(i, 0);
            String description = (String) tableModel.getValueAt(i, 1);

            if (key != null && !key.trim().isEmpty()) {
                hasValidFields = true;
                // Convert key to valid enum constant name (uppercase with underscores)
                String enumName = key.toUpperCase().replace('-', '_').replace(' ', '_');

                // Create enum constant with description
                String enumEntry = "    " + enumName + "(\"" + 
                      (description != null ? description.replace("\"", "\\\"") : "") + 
                      "\")";

                validEnumEntries.add(enumEntry);
            }
        }

        // Join all valid entries with commas
        enumCode.append(String.join(",\n", validEnumEntries));
        if (!validEnumEntries.isEmpty()) {
            enumCode.append("\n");
        }

        // If no valid fields were found, show an error message
        if (!hasValidFields) {
            JOptionPane.showMessageDialog(this,
                    "Please add at least one property with a valid name.",
                    "No Valid Properties",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Add private field and constructor
        enumCode.append("\n    private final String description;\n\n");
        enumCode.append("    LicenseFields(String description) {\n");
        enumCode.append("        this.description = description;\n");
        enumCode.append("    }\n\n");

        // Add description method
        enumCode.append("    public String description() {\n");
        enumCode.append("        return description;\n");
        enumCode.append("    }\n");

        // Close enum
        enumCode.append("}\n");

        // Create a dialog to display the generated enum
        JDialog dialog = new JDialog(this, "Generated Enum", true);
        dialog.setLayout(new BorderLayout(10, 10));
        dialog.setSize(600, 400);
        dialog.setLocationRelativeTo(this);

        JTextArea textArea = new JTextArea(enumCode.toString());
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(textArea);
        dialog.add(scrollPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton copyButton = new JButton("Copy to Clipboard");
        copyButton.addActionListener(e -> {
            StringSelection stringSelection = new StringSelection(textArea.getText());
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            JOptionPane.showMessageDialog(dialog,
                    "Enum code copied to clipboard.",
                    "Copy Successful",
                    JOptionPane.INFORMATION_MESSAGE);
        });
        buttonPanel.add(copyButton);

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> dialog.dispose());
        buttonPanel.add(closeButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    /**
     * A TransferHandler that handles drag and drop operations for table rows.
     */
    private static class TableRowTransferHandler extends TransferHandler {
        private final DataFlavor localObjectFlavor = new DataFlavor(Integer.class, "Integer Row Index");
        private final JTable table;
        private int[] rows = null;
        private int addIndex = -1; // Location where items were added
        private int addCount = 0;  // Number of items added

        public TableRowTransferHandler(JTable table) {
            this.table = table;
        }

        @Override
        protected Transferable createTransferable(JComponent c) {
            assert (c == table);
            rows = table.getSelectedRows();
            return new Transferable() {
                @Override
                public DataFlavor[] getTransferDataFlavors() {
                    return new DataFlavor[]{localObjectFlavor};
                }

                @Override
                public boolean isDataFlavorSupported(DataFlavor flavor) {
                    return localObjectFlavor.equals(flavor);
                }

                @Override
                public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
                    if (isDataFlavorSupported(flavor)) {
                        return rows[0];
                    }
                    throw new UnsupportedFlavorException(flavor);
                }
            };
        }

        @Override
        public boolean canImport(TransferSupport info) {
            // Check for drag-and-drop support
            if (!info.isDrop() || !info.isDataFlavorSupported(localObjectFlavor)) {
                return false;
            }

            // Get drop location info
            JTable.DropLocation dl = (JTable.DropLocation) info.getDropLocation();
            if (dl.getRow() == -1) {
                return false;
            }

            return true;
        }

        @Override
        public int getSourceActions(JComponent c) {
            return TransferHandler.MOVE;
        }

        @Override
        public boolean importData(TransferSupport info) {
            if (!canImport(info)) {
                return false;
            }

            JTable.DropLocation dl = (JTable.DropLocation) info.getDropLocation();
            int index = dl.getRow();
            int max = table.getModel().getRowCount();

            if (index < 0 || index > max) {
                index = max;
            }

            addIndex = index;

            try {
                Integer rowFrom = (Integer) info.getTransferable().getTransferData(localObjectFlavor);
                if (rowFrom != -1 && rowFrom != index) {
                    // Get the data from the source row
                    DefaultTableModel model = (DefaultTableModel) table.getModel();
                    Vector<Object> rowData = new Vector<>();
                    for (int i = 0; i < model.getColumnCount(); i++) {
                        rowData.add(model.getValueAt(rowFrom, i));
                    }

                    // Remove the source row
                    if (index > rowFrom) {
                        index--;
                    }
                    model.removeRow(rowFrom);

                    // Insert at the target location
                    model.insertRow(index, rowData);
                    addCount = 1;

                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            return false;
        }

        @Override
        protected void exportDone(JComponent c, Transferable t, int act) {
            if (act == TransferHandler.MOVE) {
                if (addCount > 0) {
                    // Select the newly added row(s)
                    table.setRowSelectionInterval(addIndex, addIndex + addCount - 1);
                }
            }

            rows = null;
            addIndex = -1;
            addCount = 0;
        }
    }
}
