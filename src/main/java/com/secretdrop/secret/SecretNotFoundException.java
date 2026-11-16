package com.secretdrop.secret;

public class SecretNotFoundException extends RuntimeException {

    public SecretNotFoundException() {
        super("Secret not found");
    }
}