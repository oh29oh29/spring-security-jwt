package com.oh29oh29.springsecurityjwt.common.response;

public enum ResponseCode {

    SUCCESS("0000", "성공하였습니다."),
    BAD_REQUEST("1001", "잘못된 요청입니다."),
    NOT_EXIST_MEMBER("2000", "존재하지 않는 사용자 입니다."),
    BAD_CREDENTIALS("2001", "계정 비밀번호가 일치하지 않습니다."),
    INVALID_AUTHENTICATION_INFO("2002", "인증 정보가 유효하지 않습니다."),
    ACCESS_DENIED_AUTHENTICATION("2003", "접근 권한이 없는 사용자입니다.")
    ;

    private final String code;
    private final String message;

    ResponseCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "ResponseCode{" +
                "code='" + code + '\'' +
                ", message='" + message + '\'' +
                '}';
    }
}
