package com.dua3.license;

import com.dua3.utility.crypt.AsymmetricAlgorithm;
import com.dua3.utility.crypt.KeyStoreUtil;
import com.dua3.utility.crypt.KeyUtil;
import com.dua3.utility.options.ArgumentsParser;
import com.dua3.utility.options.Option;
import com.dua3.utility.options.Repetitions;
import org.jspecify.annotations.Nullable;

import java.io.Console;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

public class LicenseManager {

    public static final String APP_NAME = LicenseManager.class.getSimpleName();
    public static final String APP_DESCRIPTION = "custom license key tool";

    record KeyData(String alias, String subject, int validDays) {}
    record TextField(String name, String value) {}

    private static final @Nullable Console console = System.console();
    private static final @Nullable Scanner scanner = console != null ? null : new Scanner(System.in, Charset.defaultCharset());

    public static void main(String[] args) {
        if (console == null) {
            System.err.format("NO CONSOLE AVAILABLE, PASSWORD WILL BE SHOWN ON SCRREN! CTRL-C TO CANCEL!%n");
        }

        var apb = ArgumentsParser.builder()
                .name(APP_NAME)
                .description(APP_DESCRIPTION);

        Option<Boolean> help = apb.addFlag(
                "Help",
                "Show program help then exit.",
                "-h", "--help"
        );

        Option<Path> keyStore = apb.addPathOption(
                "Keystore File",
                "The location of the keystore file containing the license keys.",
                Repetitions.ZERO_OR_ONE,
                "keystore",
                () -> null,
                "--keystore", "-ks"
        );

        Option<KeyData> genKey = apb.addRecordOption(
                "Key Data",
                "The key data.",
                Repetitions.ZERO_OR_ONE,
                () -> null,
                KeyData.class,
                "--gen-key", "-gk"
        );

        Option<Boolean> genLicense = apb.addFlag(
                "Generate new License",
                        "Generate a new license.",
                "--generate-license", "-gl"
        );

        Option<String> context = apb.addStringOption(
                "Encryption Context",
                "The context string used for encryption/decryption, an arbitrary string.",
                Repetitions.ZERO_OR_ONE,
                "context",
                () -> null,
                "--context", "-c"
        );

        Option<TextField> addTextField = apb.addRecordOption(
                "Add Text",
                "Add a custom text to the license.",
                Repetitions.ZERO_OR_MORE,
                () -> null,
                TextField.class,
                "--add-text-field", "-t"
        );

        var ap = apb.build();
        var arguments = ap.parse(args);

        if (arguments.isEmpty() || arguments.isSet(help)) {
            System.out.format("%s%n", ap.help());
            System.exit(0);
        }

        arguments.get(genKey).ifPresent(keyData -> {
            Path keyStorePath = arguments.getOrThrow(keyStore);
            String ctx = arguments.getOrThrow(context);

            int rc = -1;
            try {
                KeyPair keyPair = KeyUtil.generateKeyPair(AsymmetricAlgorithm.RSA, 2048);

                console.format("private: %s%n", "*".repeat(40));
                console.format("public:  %s%n", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
                console.format("%n");

                boolean storeInKeyStore = false;
                boolean done = false;
                do {
                    switch (readLine("Store key pair in %s? [y/n]: ", keyStorePath)) {
                        case "y", "Y", "yes", "YES" -> {
                            storeInKeyStore = true;
                            done = true;
                        }
                        case "n", "N", "no", "NO" -> {
                            storeInKeyStore = false;
                            done = true;
                        }
                        default -> {
                            System.err.println("invalid input");
                        }
                    }
                } while (!done);

                if (storeInKeyStore) {
                    KeyStore ks = openKeyStore(keyStorePath);
                    KeyStoreUtil.generateAndStoreKeyPairWithX509Certificate(
                            ks,
                            keyData.alias,
                            AsymmetricAlgorithm.RSA,
                            2048,
                            console.readPassword("passphrase for key store access: "),
                            keyData.subject(),
                            keyData.validDays()
                    );
                }

                rc = 0;
            } catch (Throwable e) {
                System.err.println("could not generate a key pair: " + e.getMessage());
            } finally {
                System.exit(rc);
            }
        });

        if (arguments.isSet(genLicense)) {
            Map<String, Object> map = new LinkedHashMap<>();
            arguments.stream(addTextField).forEach(tf -> map.put(tf.name(), tf.value()));
            //DynamicEnum keyEnum = DynamicEnum.of(map.keySet().toArray(String[]::new));

//            KeyPair keyPair =
        }
    }

    private static KeyStore openKeyStore(Path keyStorePath) throws GeneralSecurityException, IOException {
        return KeyStoreUtil.loadKeyStoreFromFile(keyStorePath, readPassPhrase());
    }

    private static char[] readPassword(String fmtPrompt, Object... args) {
        if (console != null) {
            return console.readPassword(fmtPrompt, args);
        } else {
            System.out.format(fmtPrompt, args);
            return scanner.nextLine().toCharArray();
        }
    }

    private static String readLine(String fmtPrompt, Object... args) {
        if (console != null) {
            return console.readLine(fmtPrompt, args);
        } else {
            System.out.format(fmtPrompt, args);
            return scanner.nextLine();
        }
    }

    private static char[] readPassPhrase() {
        char[] chars = readPassword("Enter passphrase:  ");
        char[] chars2 = readPassword("Verify passphrase: ");

        if (!Arrays.equals(chars, chars2)) {
            throw new IllegalArgumentException("passphrase does not match");
        }

        Arrays.fill(chars, '\0');

        return chars;
    }

}
