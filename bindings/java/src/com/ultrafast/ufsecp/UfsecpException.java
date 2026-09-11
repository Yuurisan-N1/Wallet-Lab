/**
 * UltrafastSecp256k1 — Exception class for Java binding.
 */
package com.ultrafast.ufsecp;

public class UfsecpException extends RuntimeException {
    public UfsecpException(String message) {
        super(message);
    }
}
