package com.oh29oh29.springsecurityjwt.member.data;

public class Response {

    public static class Login {
        private final String accessToken;

        public Login(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getAccessToken() {
            return accessToken;
        }
    }
}
