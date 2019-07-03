package com.temtum.sdk;

public class TemtumSdkException extends Exception {
    public TemtumSdkException() {
    }

    public TemtumSdkException(String message) {
        super(message);
    }

    public TemtumSdkException(String message, Throwable cause) {
        super(message, cause);
    }

    public TemtumSdkException(Throwable cause) {
        super(cause);
    }

    public TemtumSdkException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
