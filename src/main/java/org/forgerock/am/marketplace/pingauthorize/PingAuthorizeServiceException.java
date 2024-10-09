package org.forgerock.am.marketplace.pingauthorize;

/**
 * PingAuthorize Exception.
 */
public class PingAuthorizeServiceException extends Exception {

    /**
     * Exception constructor with error message.
     *
     * @param message The error message.
     */
    public PingAuthorizeServiceException(String message) {
        super(message);
    }
}