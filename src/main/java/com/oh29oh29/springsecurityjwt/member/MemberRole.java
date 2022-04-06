package com.oh29oh29.springsecurityjwt.member;

import com.oh29oh29.springsecurityjwt.common.exception.ApplicationException;
import com.oh29oh29.springsecurityjwt.common.response.ResponseCode;

import javax.persistence.*;
import java.util.Arrays;
import java.util.Objects;

@Entity
public class MemberRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "MEMBER_ID")
    private Member member;

    @Enumerated(EnumType.STRING)
    private Name name;

    public MemberRole() {
    }

    public MemberRole(Name roleName) {
        this.name = roleName;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Member getMember() {
        return member;
    }

    public void setMember(Member member) {
        this.member = member;
    }

    public Name getName() {
        return name;
    }

    public void setName(Name name) {
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MemberRole that = (MemberRole) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "MemberRole{" +
                "id=" + id +
                ", memberId=" + member.getMemberId() +
                ", name=" + name +
                '}';
    }

    public enum Name {
        USER("ROLE_USER"),
        MANAGER("ROLE_MANAGER"),
        ADMIN("ROLE_ADMIN");

        private final String value;

        Name(String value) {
            this.value = value;
        }

        public static Name of(String value) {
            return Arrays.stream(values())
                    .filter(name -> name.value.equals(value))
                    .findFirst()
                    .orElseThrow(() ->
                            new ApplicationException(
                                    ResponseCode.BAD_REQUEST,
                                    String.format("올바른 MemberRole 이 아닙니다. value: %s", value)
                            )
                    );
        }

        public String getValue() {
            return value;
        }
    }
}
