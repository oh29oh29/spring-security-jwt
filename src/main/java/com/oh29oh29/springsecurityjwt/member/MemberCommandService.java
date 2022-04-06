package com.oh29oh29.springsecurityjwt.member;

import com.oh29oh29.springsecurityjwt.common.exception.ApplicationException;
import com.oh29oh29.springsecurityjwt.common.response.ResponseCode;
import com.oh29oh29.springsecurityjwt.member.data.Request;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class MemberCommandService {
    private final MemberRepository memberRepository;
    private final MemberRoleRepository memberRoleRepository;
    private final PasswordEncoder passwordEncoder;

    public MemberCommandService(MemberRepository memberRepository, MemberRoleRepository memberRoleRepository, PasswordEncoder passwordEncoder) {
        this.memberRepository = memberRepository;
        this.memberRoleRepository = memberRoleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 회원가입
     */
    public void join(Request.Join request) {
        final LocalDateTime now = LocalDateTime.now();

        final Member member = new Member();
        member.setMemberId(request.getMemberId());
        member.setPassword(passwordEncoder, request.getPassword());
        member.setName(request.getName());
        member.setEmail(request.getEmail());
        member.setPhone(request.getPhone());
        member.setLastAccessDateTime(now);
        member.setRegDateTime(now);

        final List<MemberRole> roles = new ArrayList<>();
        for (String roleName : request.getRoles()) {
            final MemberRole role = new MemberRole(MemberRole.Name.valueOf(roleName));
            member.addRole(role);
            roles.add(role);
        }

        memberRepository.save(member);
        memberRoleRepository.saveAll(roles);
    }

    /**
     * 로그아웃
     */
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            throw new ApplicationException(ResponseCode.BAD_REQUEST);
        }

        // TODO: 레디스에 jwt 토큰을 저장하여 로그아웃 표시 / 매 요청마다 레디스에 로그아웃 여부 확인 필요

        new SecurityContextLogoutHandler().logout(request, response, authentication);
    }
}
