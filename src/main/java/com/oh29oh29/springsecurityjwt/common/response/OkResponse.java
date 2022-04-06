package com.oh29oh29.springsecurityjwt.common.response;

public class OkResponse<T> {

    private final String name = ResponseCode.SUCCESS.name();
    private final String code = ResponseCode.SUCCESS.getCode();
    private final String message = ResponseCode.SUCCESS.getMessage();
    private final T result;

    public OkResponse(T result) {
        this.result = result;
    }

    public OkResponse() {
        this.result = null;
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

    public T getResult() {
        return result;
    }

    @Override
    public String toString() {
        return "OkResponse{" +
                "name='" + name + '\'' +
                ", code='" + code + '\'' +
                ", message='" + message + '\'' +
                ", result=" + result +
                '}';
    }
}
