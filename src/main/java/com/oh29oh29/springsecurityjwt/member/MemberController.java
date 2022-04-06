package com.oh29oh29.springsecurityjwt.member;

import com.oh29oh29.springsecurityjwt.common.response.OkResponse;
import com.oh29oh29.springsecurityjwt.member.data.Request;
import org.springframework.util.CollectionUtils;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/member")
public class MemberController {

    private final MemberCommandService memberCommandService;

    public MemberController(MemberCommandService memberCommandService) {
        this.memberCommandService = memberCommandService;
    }

    /**
     * 회원 가입
     */
    @PostMapping("/join")
    public OkResponse<Void> join(@Validated @RequestBody Request.Join request) {
        if (CollectionUtils.isEmpty(request.getRoles())) {
            request.setRoles(List.of("USER"));
        }
        memberCommandService.join(request);
        return new OkResponse<>();
    }

    /**
     * 권한에 따른 API 호출 결과 확인용
     * */
    @PostMapping("/forbidden")
    public OkResponse<Void> login() {
        return new OkResponse<>();
    }

    @PostMapping("/success")
    public OkResponse<Void> success() {
        return new OkResponse<>();
    }
}
