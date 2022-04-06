package com.oh29oh29.springsecurityjwt.common.response;

public class ErrorResponse {
    private final String name;
    private final String code;
    private final String message;

    public ErrorResponse(ResponseCode responseCode) {
        this.name = responseCode.name();
        this.code = responseCode.getCode();
        this.message = responseCode.getMessage();
    }

    public ErrorResponse(ResponseCode responseCode, String message) {
        this.name = responseCode.name();
        this.code = responseCode.getCode();
        this.message = message;
    }

    public String getName() {
        return name;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "ErrorResponse{" +
                "name='" + name + '\'' +
                ", code='" + code + '\'' +
                ", message='" + message + '\'' +
                '}';
    }
}
