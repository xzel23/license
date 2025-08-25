package com.dua3.license.app;

import com.dua3.license.DynamicEnum;
import com.dua3.license.License;
import com.dua3.utility.data.Pair;
import com.dua3.utility.swing.SwingUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.miginfocom.swing.MigLayout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.BorderFactory;
import javax.swing.DropMode;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.TransferHandler;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.stream.Stream;

import static com.dua3.license.License.LICENSE_ID_LICENSE_FIELD;

/**
 * A dialog for editing license templates.
 * This allows creating, editing, and saving license templates as DynamicEnum objects.
 */
public final class LicenseTemplateEditor extends JDialog {
    private static final Logger LOG = LogManager.getLogger(LicenseTemplateEditor.class);
    private static final String ADD_AT_LEAST_ONE_PROPERTY = "Please add at least one property.";
    private static final String NO_VALID_PROPERTIES = "No Valid Properties";
    private static final String NO_PROPERTIES = "No Properties";

    // Required fields that cannot be deleted but can be edited
    private static final List<String> REQUIRED_EDITABLE_FIELDS = List.of(
            LICENSE_ID_LICENSE_FIELD
    );

    private final JTextField templateNameField;
    private final JTable propertiesTable;
    private final DefaultTableModel tableModel;
    private final JButton removeButton;

    /**
     * Creates a new LicenseTemplateEditor dialog.
     *
     * @param parent the parent frame
     */
    public LicenseTemplateEditor(JFrame parent) {
        super(parent, "License Template Editor", true);

        // Create templates directory if it doesn't exist
        try {
            Files.createDirectories(LicenseManager.getTemplatesDirectory());
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
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // Check if this is a required field
                if (row < getRowCount()) {
                    String propertyName = (String) getValueAt(row, 0);
                    if (License.REQUIRED_LICENSE_FIELDS.contains(propertyName)) {
                        return false; // Required fields are not editable
                    }
                    // REQUIRED_EDITABLE_FIELDS can be edited
                    if (REQUIRED_EDITABLE_FIELDS.contains(propertyName)) {
                        return true; // Required but editable fields
                    }
                }
                return true; // Other fields are editable
            }
        };
        propertiesTable = new JTable(tableModel);
        propertiesTable.setFillsViewportHeight(true);
        propertiesTable.setDragEnabled(true);
        propertiesTable.setDropMode(DropMode.INSERT_ROWS);
        propertiesTable.setTransferHandler(new TableRowTransferHandler(propertiesTable));
        propertiesTable.getTableHeader().setReorderingAllowed(false);

        // Add a tooltip to indicate drag-and-drop functionality
        propertiesTable.setToolTipText("Drag and drop rows to reorder license fields");

        // Add a selection listener to update the Remove button state
        propertiesTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updateRemoveButtonState();
            }
        });

        JScrollPane tableScrollPane = new JScrollPane(propertiesTable);
        mainPanel.add(tableScrollPane, BorderLayout.CENTER);

        // Create the button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        JButton addButton = new JButton("Add Property");
        addButton.addActionListener(e -> addProperty());

        removeButton = new JButton("Remove Property");
        removeButton.addActionListener(e -> removeProperty());

        JButton loadButton = new JButton("Load Template");
        loadButton.addActionListener(e -> loadTemplate(parent));

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

        // Automatically add the required fields
        addRequiredFields();

        // Set initial state of the Remove button
        updateRemoveButtonState();
    }

    /**
     * Updates the enabled state of the Remove Property button based on the current selection.
     * The button is disabled if a required field is selected.
     */
    private void updateRemoveButtonState() {
        int selectedRow = propertiesTable.getSelectedRow();
        if (selectedRow != -1) {
            String propertyName = (String) tableModel.getValueAt(selectedRow, 0);
            removeButton.setEnabled(!License.REQUIRED_LICENSE_FIELDS.contains(propertyName) && !REQUIRED_EDITABLE_FIELDS.contains(propertyName));
        } else {
            removeButton.setEnabled(false); // Disable if no row is selected
        }
    }

    /**
     * Adds a new empty property to the table.
     * Selects the new row and starts editing the first cell.
     */
    private void addProperty() {
        tableModel.addRow(new Object[]{"", "", ""});
        int newRowIndex = tableModel.getRowCount() - 1;

        // Select the newly added row
        propertiesTable.setRowSelectionInterval(newRowIndex, newRowIndex);

        // Start editing the first cell of the new row
        propertiesTable.editCellAt(newRowIndex, 0);
        propertiesTable.getEditorComponent().requestFocus();
    }

    /**
     * Removes the selected property from the table.
     * Required fields cannot be removed.
     */
    private void removeProperty() {
        int selectedRow = propertiesTable.getSelectedRow();
        if (selectedRow != -1) {
            // Check if this is a required field
            String propertyName = (String) tableModel.getValueAt(selectedRow, 0);
            if (License.REQUIRED_LICENSE_FIELDS.contains(propertyName) || REQUIRED_EDITABLE_FIELDS.contains(propertyName)) {
                JOptionPane.showMessageDialog(this,
                        "The field '" + propertyName + "' is required and cannot be removed.",
                        "Required Field",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
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
    private void loadTemplate(Component parent) {
        SwingUtil.showFileOpenDialog(
                parent,
                LicenseManager.getTemplatesDirectory(),
                Pair.of("JSON files", new String[]{"json"})
        ).ifPresent(this::loadJsonTemplate);
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
                    ADD_AT_LEAST_ONE_PROPERTY,
                    NO_PROPERTIES,
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Always save as JSON
        saveAsJson(templateName);
    }

    /**
     * Generates a Java enum named "LicenseFields" from the current template.
     * The enum uses the key as name and contains a String description() method that returns the description.
     */
    private void generateEnum() {
        // Check if there are any properties
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(this,
                    ADD_AT_LEAST_ONE_PROPERTY,
                    NO_PROPERTIES,
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        StringBuilder enumCode = new StringBuilder();
        enumCode.append("public enum LicenseFields {\n");

        // Add enum constants
        boolean hasInvalidFields = true;
        List<String> validEnumEntries = new ArrayList<>();

        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String key = (String) tableModel.getValueAt(i, 0);
            String description = (String) tableModel.getValueAt(i, 1);

            if (key != null && !key.trim().isEmpty()) {
                hasInvalidFields = false;
                // Convert key to valid enum constant name (uppercase with underscores)
                String enumName = key.toUpperCase(Locale.ROOT)
                        .replace('-', '_')
                        .replace(' ', '_');

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
            enumCode.append(";\n");
        }

        // If no valid fields were found, show an error message
        if (hasInvalidFields) {
            JOptionPane.showMessageDialog(this,
                    ADD_AT_LEAST_ONE_PROPERTY,
                    NO_VALID_PROPERTIES,
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
     * Adds the required license fields to the table if they don't already exist.
     * These fields cannot be modified or deleted, but can be reordered.
     * Additionally, adds fields that cannot be deleted but can be modified.
     */
    private void addRequiredFields() {
        // Check for existing fields
        Set<String> existingFields = new HashSet<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String fieldName = (String) tableModel.getValueAt(i, 0);
            existingFields.add(fieldName);
        }

        // Add LICENSE_ID field if it doesn't exist (can be edited but not deleted)
        if (!existingFields.contains("LICENSE_ID")) {
            tableModel.addRow(new Object[]{
                    "LICENSE_ID",
                    "Unique identifier for the license",
                    ""
            });
        }

        // Add ISSUE_DATE field if it doesn't exist
        if (!existingFields.contains("ISSUE_DATE")) {
            tableModel.addRow(new Object[]{
                    "ISSUE_DATE",
                    "Issue date of the license",
                    LicenseEditor.$ISSUE_DATE
            });
        }

        // Add EXPIRY_DATE field if it doesn't exist
        if (!existingFields.contains("EXPIRY_DATE")) {
            tableModel.addRow(new Object[]{
                    "EXPIRY_DATE",
                    "Expiry date of the license",
                    LicenseEditor.$EXPIRY_DATE
            });
        }

        // Add SIGNING_KEY field if it doesn't exist
        if (!existingFields.contains("SIGNING_KEY")) {
            tableModel.addRow(new Object[]{
                    "SIGNING_KEY",
                    "Key used to sign the license",
                    LicenseEditor.$SIGNING_KEY
            });
        }

        // Add SIGNATURE field if it doesn't exist
        if (!existingFields.contains("SIGNATURE")) {
            tableModel.addRow(new Object[]{
                    "SIGNATURE",
                    "Digital signature of the license",
                    LicenseEditor.$SIGNATURE
            });
        }
    }

    /**
     * Loads a template from a JSON file.
     *
     * @param file the JSON file
     */
    private void loadJsonTemplate(Path file) {
        try {
            LicenseTemplate template = LicenseTemplate.loadTemplate(file);
            templateNameField.setText(template.getName());

            // Clear the table and add the fields
            tableModel.setRowCount(0);
            template.getFields().forEach(field ->
                    tableModel.addRow(new Object[]{field.name(), field.description(), field.defaultValue()})
            );

            // Make sure required fields are present
            addRequiredFields();

        } catch (IOException e) {
            LOG.error("Failed to load JSON template", e);
            JOptionPane.showMessageDialog(this,
                    "Failed to load template: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Saves the current template as a JSON file.
     *
     * @param templateName the name of the template
     */
    private void saveAsJson(String templateName) {
        // Create a list of LicenseField objects from the table data
        List<LicenseTemplate.LicenseField> fields = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String name = (String) tableModel.getValueAt(i, 0);
            String description = (String) tableModel.getValueAt(i, 1);
            String defaultValue = (String) tableModel.getValueAt(i, 2);

            if (name != null && !name.trim().isEmpty()) {
                fields.add(new LicenseTemplate.LicenseField(
                        name,
                        description != null ? description : "",
                        defaultValue != null ? defaultValue : ""));
            }
        }

        if (fields.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    ADD_AT_LEAST_ONE_PROPERTY,
                    NO_PROPERTIES,
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Save the fields to a JSON file
        Path file = LicenseManager.getTemplatesDirectory().resolve(templateName + ".json");
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), fields);
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
     * Gets all available template names.
     *
     * @return an array of template names
     */
    public static String[] getAvailableTemplates() {
        try {
            Path templatesDir = LicenseManager.getTemplatesDirectory();
            if (!Files.exists(templatesDir)) {
                Files.createDirectories(templatesDir);
                return new String[0];
            }

            // Get all template names from .json files only
            try (Stream<Path> paths = Files.list(templatesDir)) {
                return paths
                        .filter(path -> path.toString().endsWith(".json"))
                        .map(path -> {
                            String fileName = path.getFileName().toString();
                            return fileName.substring(0, fileName.length() - 5);
                        })
                        .toArray(String[]::new);
            }
        } catch (IOException e) {
            LOG.error("Failed to get available templates", e);
            return new String[0];
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

        return DynamicEnum.fromPropertiesWithValues(properties);
    }

    /**
     * A TransferHandler that handles drag and drop operations for table rows.
     */
    private static final class TableRowTransferHandler extends TransferHandler {
        private final DataFlavor localObjectFlavor = new DataFlavor(Integer.class, "Integer Row Index");
        private final JTable table;
        private int[] rows;
        private int addIndex = -1; // Location where items were added
        private int addCount = 0;  // Number of items added

        public TableRowTransferHandler(JTable table) {
            this.table = table;
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
                int rowFrom = (Integer) info.getTransferable().getTransferData(localObjectFlavor);
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
            } catch (IOException e) {
                throw new UncheckedIOException("Unable to get transfer data", e);
            } catch (UnsupportedFlavorException e) {
                throw new IllegalStateException("Unsupported data", e);
            }

            return false;
        }

        @Override
        public boolean canImport(TransferSupport info) {
            // Check for drag-and-drop support
            if (!info.isDrop() || !info.isDataFlavorSupported(localObjectFlavor)) {
                return false;
            }

            // Get drop location info
            JTable.DropLocation dl = (JTable.DropLocation) info.getDropLocation();
            return dl.getRow() != -1;
        }

        @Override
        public int getSourceActions(JComponent c) {
            return MOVE;
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
        protected void exportDone(JComponent c, Transferable t, int action) {
            if (action == MOVE && addCount > 0) {
                // Select the newly added row(s)
                table.setRowSelectionInterval(addIndex, addIndex + addCount - 1);
            }

            rows = null;
            addIndex = -1;
            addCount = 0;
        }
    }
}
