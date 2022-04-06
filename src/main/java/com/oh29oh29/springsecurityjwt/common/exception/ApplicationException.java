package com.oh29oh29.springsecurityjwt.common.exception;

import com.oh29oh29.springsecurityjwt.common.response.ResponseCode;

public class ApplicationException extends RuntimeException {
    private final ResponseCode responseCode;

    public ApplicationException(ResponseCode responseCode, String message, Throwable cause) {
        super(message, cause);
        this.responseCode = responseCode;
    }

    public ApplicationException(ResponseCode responseCode, String message) {
        super(message);
        this.responseCode = responseCode;
    }

    public ApplicationException(ResponseCode responseCode, Throwable cause) {
        super(responseCode.getMessage(), cause);
        this.responseCode = responseCode;
    }

    public ApplicationException(ResponseCode responseCode) {
        super(responseCode.getMessage());
        this.responseCode = responseCode;
    }

    public ResponseCode getResponseCode() {
        return responseCode;
    }
}
