package org.forgerock.am.marketplace.pingoneauthorize;

/**
 * PingOne Authorize Exception.
 */
public class PingOneAuthorizeServiceException extends Exception {

    /**
     * Exception constructor with error message.
     *
     * @param message The error message.
     */
    public PingOneAuthorizeServiceException(String message) {
        super(message);
    }
}