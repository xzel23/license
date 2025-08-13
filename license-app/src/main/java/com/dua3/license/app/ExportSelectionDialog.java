package com.dua3.license.app;

import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Frame;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.dua3.utility.crypt.PasswordUtil;

/**
 * Dialog to select which items to export to a new keystore.
 * It lists all aliases and provides two checkboxes per alias: export public key/certificate and export private key.
 * It also provides password and confirm password fields. If any private key is selected, a non-empty matching password is required.
 */
public class ExportSelectionDialog extends JDialog {

    public static class Selection {
        public final String alias;
        public boolean exportPublic;
        public boolean exportPrivate;
        public Selection(String alias) {
            this.alias = alias;
        }
    }

    private final List<Selection> selections = new ArrayList<>();
    private final JTextField passwordField = new JTextField(20);
    private final JTextField confirmPasswordField = new JTextField(20);
    private boolean approved = false;

    private final JTable table;
    private final JButton okButton = new JButton("OK");

    public ExportSelectionDialog(Frame owner, KeyStore keyStore) {
        super(owner, "Select Items to Export", true);

        // Collect aliases
        try {
            var aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                // include both key and cert entries in list; selection determines content
                selections.add(new Selection(alias));
            }
        } catch (Exception e) {
            // if error, leave selections empty
        }

        // Table model
        var model = new AbstractTableModel() {
            private final String[] cols = new String[]{"Alias", "Export public key", "Export private key"};
            @Override public int getRowCount() { return selections.size(); }
            @Override public int getColumnCount() { return 3; }
            @Override public String getColumnName(int column) { return cols[column]; }
            @Override public Class<?> getColumnClass(int columnIndex) {
                return switch (columnIndex) {
                    case 0 -> String.class;
                    default -> Boolean.class;
                };
            }
            @Override public boolean isCellEditable(int rowIndex, int columnIndex) { return columnIndex > 0; }
            @Override public Object getValueAt(int rowIndex, int columnIndex) {
                Selection s = selections.get(rowIndex);
                return switch (columnIndex) {
                    case 0 -> s.alias;
                    case 1 -> s.exportPublic;
                    case 2 -> s.exportPrivate;
                    default -> null;
                };
            }
            @Override public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
                Selection s = selections.get(rowIndex);
                if (columnIndex == 1) {
                    s.exportPublic = (Boolean) aValue;
                } else if (columnIndex == 2) {
                    s.exportPrivate = (Boolean) aValue;
                }
                fireTableRowsUpdated(rowIndex, rowIndex);
                updateOkEnabled();
            }
        };

        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);

        JPanel center = new JPanel(new BorderLayout());
        center.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel south = new JPanel(new MigLayout("insets 10, fillx", "[right][grow][]", "[][][]"));
        south.add(new JLabel("Password:"));
        south.add(passwordField, "growx");
        JButton generateBtn = new JButton("Generate password");
        generateBtn.addActionListener(e -> fillWithGeneratedStrongPassword());
        south.add(generateBtn, "span 2, gap unrelated, wrap");
        south.add(new JLabel("Repeat Password:"));
        south.add(confirmPasswordField, "growx");

        JPanel buttons = new JPanel();
        JButton cancel = new JButton("Cancel");
        cancel.addActionListener(e -> {
            approved = false;
            setVisible(false);
        });
        okButton.addActionListener(e -> {
            approved = true;
            setVisible(false);
        });
        buttons.add(cancel);
        buttons.add(okButton);
        // Add buttons to the same south panel so they are shown together with the password fields
        south.add(buttons, "span, align right, gaptop 10");

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(center, BorderLayout.CENTER);
        getContentPane().add(south, BorderLayout.SOUTH);

        setSize(600, 400);
        setLocationRelativeTo(owner);

        updateOkEnabled();

        // add live validation
        var listener = (Runnable) this::updateOkEnabled;
        passwordField.getDocument().addDocumentListener(new SimpleDocListener(listener));
        confirmPasswordField.getDocument().addDocumentListener(new SimpleDocListener(listener));
    }

    private void updateOkEnabled() {
        boolean anyPrivate = selections.stream().anyMatch(s -> s.exportPrivate);
        boolean anySelected = selections.stream().anyMatch(s -> s.exportPrivate || s.exportPublic);
        if (!anyPrivate) {
            okButton.setEnabled(anySelected);
            return;
        }
        char[] pw = passwordField.getText().toCharArray();
        char[] pw2 = confirmPasswordField.getText().toCharArray();
        boolean nonEmpty = pw.length > 0;
        boolean match = Arrays.equals(pw, pw2);
        boolean strong = nonEmpty && match && PasswordUtil.evaluatePasswordStrength(pw).isSecure();
        okButton.setEnabled(anySelected && strong);
    }

    private void fillWithGeneratedStrongPassword() {
        char[] pw = PasswordUtil.generatePassword();
        String s = new String(pw);
        passwordField.setText(s);
        confirmPasswordField.setText(s);
        // best effort wipe local
        Arrays.fill(pw, '\0');
    }

    public boolean showDialog() {
        setVisible(true);
        return approved;
    }

    public List<Selection> getSelections() { return selections; }

    public char[] getPassword() { return passwordField.getText().toCharArray(); }

    // Simple document listener adapter
    private static class SimpleDocListener implements javax.swing.event.DocumentListener {
        private final Runnable r;
        SimpleDocListener(Runnable r) { this.r = r; }
        @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
        @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
        @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { r.run(); }
    }
}
