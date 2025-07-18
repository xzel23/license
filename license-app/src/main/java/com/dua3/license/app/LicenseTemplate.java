package com.dua3.license.app;

import com.dua3.license.DynamicEnum;
import com.dua3.utility.io.IoUtil;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static com.dua3.license.License.REQUIRED_LICENSE_FIELDS;

/**
 * Represents a license template that consists of a name, a file path,
 * and a collection of fields. Each field provides metadata and default values
 * for generating license structures.
 */
public class LicenseTemplate {

    /**
     * Represents a field within a license template.
     * A license field contains a name, description, and a default value.
     *
     * @param name the name of the license field
     * @param description the description of the license field
     * @param defaultValue the default value for the license field
     */
    record LicenseField(String name, String description, String defaultValue) {}

    /**
     * A model class for license template fields.
     */
    record LicenseFieldData(String description, String defaultValue) {}

    private final Path path;
    private String name;
    private final LinkedHashMap<String, LicenseFieldData> fields;

    /**
     * Constructs a new LicenseTemplate with the specified path, template name, and fields.
     *
     * @param path the path associated with the license template
     * @param templateName the name of the license template
     * @param fields the list of fields within the license template
     */
    private LicenseTemplate(Path path, String templateName, List<LicenseField> fields) {
        this.path = path;
        this.name = templateName;
        this.fields = new LinkedHashMap<>();
        fields.forEach(field -> this.fields.put(field.name(), new LicenseFieldData(field.description(), field.defaultValue())));
    }

    /**
     * Loads a DynamicEnum from a JSON file.
     *
     * @param path the JSON file
     * @return a DynamicEnum representing the template
     * @throws IOException if the template could not be loaded
     */
    public static LicenseTemplate loadTemplate(Path path) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        List<LicenseField> fields = mapper.readValue(path.toFile(), new TypeReference<List<LicenseField>>() {});

        // Validate that all required fields are present
        for (String requiredField : REQUIRED_LICENSE_FIELDS) {
            boolean found = false;
            for (LicenseField field : fields) {
                if (requiredField.equals(field.name())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new IOException("Required field '" + requiredField + "' is missing in the license template");
            }
        }

        String templateName = IoUtil.stripExtension(String.valueOf(path.getFileName()));

        return new LicenseTemplate(path, templateName, fields);
    }

    /**
     * Creates a new DynamicEnum instance using the fields defined in the LicenseTemplate.
     * Each field's name and description are used as the names and values for the DynamicEnum entries.
     *
     * @return a DynamicEnum constructed with names and descriptions of the template fields
     */
    public DynamicEnum createDynamicEnum() {
        int n = fields.size();
        String[] names = new String[n];
        String[] descriptions = new String[n];
        AtomicInteger idx = new AtomicInteger();
        fields.forEach((key, value) -> {
            int i = idx.getAndIncrement();
            names[i] = key;
            descriptions[i] = value.description();
        });
        return DynamicEnum.ofNamesAndValues(names, descriptions);
    }

    /**
     * Retrieves the LicenseFieldData associated with the specified field name.
     *
     * @param name the name of the field for which data is to be retrieved
     * @return the LicenseFieldData associated with the given field name, or null if no such field exists
     */
    public LicenseFieldData getFieldData(String name) {
        return fields.get(name);
    }

    /**
     * Retrieves the name associated with this LicenseTemplate.
     *
     * @return the name of the LicenseTemplate
     */
    public String getName() {
        return name;
    }

    /**
     * Retrieves a list of license fields associated with this license template.
     * Each field includes its name, description, and default value.
     *
     * @return a list of LicenseField objects representing the fields in the license template
     */
    public List<LicenseField> getFields() {
        return fields.entrySet().stream()
                .map(e -> new LicenseField(e.getKey(), e.getValue().description(), e.getValue().defaultValue()))
                .toList();
    }

}
