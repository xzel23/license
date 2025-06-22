package com.dua3.license;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyGen {
    public static final String ALGORITHM = "RSA";
    public static final int KEYSIZE = 4096;

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEYSIZE);
        return keyGen.generateKeyPair();
    }
}
