package com.oh29oh29.springsecurityjwt.member;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Entity
public class Member implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "MEMBER_ID", nullable = false)
    private String memberId;

    @Column(nullable = false)
    private String password;

    @Column
    private String name;

    @Column
    private String email;

    @Column
    private String phone;

    @Column
    @OneToMany(mappedBy = "member", fetch = FetchType.EAGER)
    private List<MemberRole> roles = new ArrayList<>();

    @Column
    private LocalDateTime lastAccessDateTime;

    @Column(nullable = false)
    private LocalDateTime regDateTime;

    /**
     * getter / setter
     */

    public Long getId() {
        return id;
    }

    public String getMemberId() {
        return memberId;
    }

    public void setMemberId(String memberId) {
        this.memberId = memberId;
    }

    public void setPassword(PasswordEncoder passwordEncoder, String password) {
        this.password = passwordEncoder.encode(password);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public List<String> getRoles() {
        return roles
                .stream()
                .map(role -> role.getName().getValue())
                .collect(Collectors.toList());
    }

    public void setRoles(List<MemberRole> roles) {
        this.roles = roles;
    }

    public void addRole(MemberRole role) {
        role.setMember(this);
        this.roles.add(role);
    }

    public LocalDateTime getLastAccessDateTime() {
        return lastAccessDateTime;
    }

    public void setLastAccessDateTime(LocalDateTime lastAccessDateTime) {
        this.lastAccessDateTime = lastAccessDateTime;
    }

    public LocalDateTime getRegDateTime() {
        return regDateTime;
    }

    public void setRegDateTime(LocalDateTime regDateTime) {
        this.regDateTime = regDateTime;
    }

    /**
     * UserDetails implements
     */

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.getRoles()
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.memberId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    /**
     * equals / hashCode / toString
     */

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Member member = (Member) o;
        return id.equals(member.id) && memberId.equals(member.memberId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, memberId);
    }

    @Override
    public String toString() {
        return "Member{" +
                "id=" + id +
                ", memberId='" + memberId + '\'' +
                ", password='" + password + '\'' +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", phone='" + phone + '\'' +
                ", roles=" + roles +
                ", lastAccessDateTime=" + lastAccessDateTime +
                ", regDateTime=" + regDateTime +
                '}';
    }
}
