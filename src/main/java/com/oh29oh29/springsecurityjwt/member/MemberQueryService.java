package com.oh29oh29.springsecurityjwt.member;

import com.oh29oh29.springsecurityjwt.common.exception.ApplicationException;
import com.oh29oh29.springsecurityjwt.common.response.ResponseCode;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MemberQueryService implements UserDetailsService {

    private final MemberRepository memberRepository;

    public MemberQueryService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        final Member member = memberRepository.findByMemberId(id);

        if (member == null) {
            throw new ApplicationException(ResponseCode.NOT_EXIST_MEMBER);
        }

        return member;
    }
}
