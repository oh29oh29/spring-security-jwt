package com.oh29oh29.springsecurityjwt.member.data;

import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.List;

public class Request {

    public static class Login {
        @NotBlank
        private String memberId;
        @NotBlank
        private String password;

        public String getMemberId() {
            return memberId;
        }

        public String getPassword() {
            return password;
        }
    }

    public static class Join {
        @NotBlank
        private String memberId;
        @NotBlank
        private String password;
        private String name;
        private String email;
        private String phone;
        private List<String> roles = new ArrayList<>();

        public String getMemberId() {
            return memberId;
        }

        public String getPassword() {
            return password;
        }

        public String getName() {
            return name;
        }

        public String getEmail() {
            return email;
        }

        public String getPhone() {
            return phone;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }
    }
}
