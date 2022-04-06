package com.oh29oh29.springsecurityjwt.config;

import com.google.gson.Gson;
import com.oh29oh29.springsecurityjwt.common.exception.ApplicationException;
import com.oh29oh29.springsecurityjwt.common.response.ErrorResponse;
import com.oh29oh29.springsecurityjwt.common.response.OkResponse;
import com.oh29oh29.springsecurityjwt.common.response.ResponseCode;
import com.oh29oh29.springsecurityjwt.member.Member;
import com.oh29oh29.springsecurityjwt.member.MemberQueryService;
import com.oh29oh29.springsecurityjwt.member.MemberRole;
import com.oh29oh29.springsecurityjwt.member.data.Request;
import com.oh29oh29.springsecurityjwt.member.data.Response;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final MemberQueryService memberQueryService;
    private final Gson gson;

    private static final String WILDCARD_API_URL = "/api/**";
    private static final String JOIN_API_URL = "/api/v*/member/join";
    private static final String LOGIN_API_URL = "/api/v*/member/login";

    public SecurityConfig(MemberQueryService memberQueryService, Gson gson) {
        this.memberQueryService = memberQueryService;
        this.gson = gson;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // static 자원에 대한 Security 설정을 적용하지 않음
        web
                .ignoring()
                .requestMatchers(
                        PathRequest
                                .toStaticResources()
                                .atCommonLocations()
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers().frameOptions().sameOrigin();
        http.csrf().disable();

        // 페이지 권한 설정
        http.authorizeRequests()
                .antMatchers(JOIN_API_URL, LOGIN_API_URL).permitAll()
                .antMatchers("/", "/h2-console/**").permitAll()
                .antMatchers("/api/v1/member/forbidden").hasRole("MANAGER")
                .antMatchers("/api/v1/member/success").hasRole("USER")
                .anyRequest().authenticated();

        http.formLogin().disable();
        http.httpBasic().disable();

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.logout()
                .logoutUrl("/api/v*/member/logout")
                .logoutSuccessUrl("/");

        http.exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint(gson))   // 인증이 안된 사용자가 특정 권한이 필요한 자원에 접근하려고 할 때 호출
                .accessDeniedHandler(new JwtAccessDeniedHandler(gson));                 // 인증이 된 사용자가 갖고있지 않은 특정 권한이 필요한 자원에 접근하려고 할 때 호출

        http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(loginAuthenticationFilter(), JwtAuthenticationFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    /**
     * Bean
     */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new JwtAuthenticationProvider(memberQueryService, passwordEncoder(), new JwtTokenUtil());
    }

    @Bean
    public LoginAuthenticationFilter loginAuthenticationFilter() throws Exception {
        final LoginAuthenticationFilter loginAuthenticationFilter = new LoginAuthenticationFilter(LOGIN_API_URL, gson);
        loginAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        loginAuthenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        return loginAuthenticationFilter;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        final JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(WILDCARD_API_URL, JOIN_API_URL);
        jwtAuthenticationFilter.setAuthenticationManager(authenticationManagerBean());
        jwtAuthenticationFilter.setAuthenticationSuccessHandler(jwtAuthenticationSuccessHandler());
        return jwtAuthenticationFilter;
    }

    @Bean
    public AuthenticationSuccessHandler loginSuccessHandler() {
        return (request, response, authentication) -> {
            final JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken) authentication;
            final String responseBody = gson.toJson(new OkResponse<>(new Response.Login(jwtAuthentication.accessToken)));

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
            response.getWriter().println(responseBody);
        };
    }

    @Bean
    public AuthenticationSuccessHandler jwtAuthenticationSuccessHandler() {
        return (request, response, authentication) -> {

        };
    }

    /**
     * AbstractAuthenticationProcessingFilter implement
     */
    public static class LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
        private final Gson gson;

        private LoginAuthenticationFilter(String defaultFilterProcessesUrl, Gson gson) {
            super(new AntPathRequestMatcher(defaultFilterProcessesUrl));
            this.gson = gson;
        }

        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
            if (!isValidLoginRequest(request)) {
                throw new ApplicationException(ResponseCode.BAD_REQUEST, "Authentication is not supported");
            }

            final Request.Login loginRequest = gson.fromJson(request.getReader(), Request.Login.class);

            return getAuthenticationManager().authenticate(new JwtAuthenticationToken(loginRequest.getMemberId(), loginRequest.getPassword()));
        }

        private boolean isValidLoginRequest(HttpServletRequest request) {
            return request.getMethod().equals(RequestMethod.POST.name());
        }
    }

    private static class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
        private final AntPathRequestMatcher joinRequestMatcher;
        private static final String AUTHORIZATION_HEADER = "Authorization";
        private static final String AUTHORIZATION_HEADER_JWT_SCHEMA = "Bearer";

        private JwtAuthenticationFilter(String defaultFilterProcessesUrl, String joinProcessesUrl) {
            super(defaultFilterProcessesUrl);
            this.joinRequestMatcher = new AntPathRequestMatcher(joinProcessesUrl);
        }

        @Override
        protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
            if (joinRequestMatcher.matches(request)) {
                return false;
            }

            return super.requiresAuthentication(request, response);
        }

        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
            final String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);

            if (!isJwtAuthentication(authorizationHeader)) {
                return null;
            }

            final String accessToken = authorizationHeader.substring(7);
            return getAuthenticationManager().authenticate(new JwtAuthenticationToken(accessToken));
        }

        private boolean isJwtAuthentication(String authorizationHeader) {
            if (!StringUtils.hasText(authorizationHeader)) {
                return false;
            }

            return authorizationHeader.startsWith(AUTHORIZATION_HEADER_JWT_SCHEMA);
        }

        @Override
        protected void successfulAuthentication(
                HttpServletRequest request,
                HttpServletResponse response,
                FilterChain chain,
                Authentication authResult
        ) throws IOException, ServletException {
            super.successfulAuthentication(request, response, chain, authResult);

            // As this authentication is in HTTP header, after success we need to continue the request normally
            // and return the response as if the resource was not secured at all
            chain.doFilter(request, response);
        }
    }

    /**
     * AuthenticationProvider implement
     */

    private static class JwtAuthenticationProvider implements AuthenticationProvider {
        private final UserDetailsService userDetailsService;
        private final PasswordEncoder passwordEncoder;
        private final JwtTokenUtil jwtTokenUtil;

        public JwtAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder, JwtTokenUtil jwtTokenUtil) {
            this.userDetailsService = userDetailsService;
            this.passwordEncoder = passwordEncoder;
            this.jwtTokenUtil = jwtTokenUtil;
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            final JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;

            final String accessToken = jwtAuthenticationToken.getAccessToken();

            // 로그인 완료 사용자
            if (StringUtils.hasText(accessToken)) {
                final Member member = jwtTokenUtil.parseToken(accessToken);
                final List<GrantedAuthority> authorityList = List.copyOf(member.getAuthorities());

                return new JwtAuthenticationToken(member.getMemberId(), authorityList, accessToken);
            }

            // 로그인 시도 사용자
            final String id = authentication.getName();
            final String password = (String) authentication.getCredentials();

            final Member member = (Member) userDetailsService.loadUserByUsername(id);

            if (!passwordEncoder.matches(password, member.getPassword())) {
                throw new ApplicationException(ResponseCode.BAD_CREDENTIALS);
            }

            return new JwtAuthenticationToken(member, member.getAuthorities(), jwtTokenUtil.issueToken(member));
        }

        @Override
        public boolean supports(Class<?> authentication) {
            return JwtAuthenticationToken.class.isAssignableFrom(authentication);
        }
    }

    /**
     * AbstractAuthenticationToken implement
     */

    private static class JwtAuthenticationToken extends AbstractAuthenticationToken {
        private Object principal;
        private Object credentials;
        private String accessToken;

        public JwtAuthenticationToken(String accessToken) {
            super(null);
            this.accessToken = accessToken;
        }

        public JwtAuthenticationToken(Object principal, Object credentials) {
            super(null);
            this.principal = principal;
            this.credentials = credentials;
            super.setAuthenticated(false);
        }

        public JwtAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities, String accessToken) {
            super(authorities);
            this.principal = principal;
            this.accessToken = accessToken;
            super.setAuthenticated(true);
        }

        @Override
        public Object getCredentials() {
            return this.credentials;
        }

        @Override
        public Object getPrincipal() {
            return this.principal;
        }

        public String getAccessToken() {
            return this.accessToken;
        }
    }

    private static class JwtTokenUtil {
        private static final String SECRET_KEY = "christmas";
        private static final Long TOKEN_EXPIRATION = 15 * 60_000L;

        public Member parseToken(String accessToken) {
            try {
                final String secretKey = twistSecretKey();

                final Claims body = Jwts
                        .parserBuilder()
                        .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                        .build()
                        .parseClaimsJws(accessToken)
                        .getBody();

                final Member member = new Member();
                final String userId = body.getSubject();
                member.setMemberId(userId);

                final String roles = (String) body.get("roles");
                final List<MemberRole> memberRoles = new ArrayList<>();
                for (String role : roles.split(",")) {
                    memberRoles.add(new MemberRole(MemberRole.Name.of(role)));
                }
                member.setRoles(memberRoles);

                return member;
            } catch (JwtException e) {
                throw new AuthenticationCredentialsNotFoundException(ResponseCode.INVALID_AUTHENTICATION_INFO.getMessage(), e);
            }
        }

        public String issueToken(Member member) {
            final Date now = new Date();
            final Claims claims = Jwts.claims();

            claims.setSubject(member.getMemberId());
            claims.put(
                    "roles",
                    String.join(",", member.getRoles())
            );

            final String secretKey = twistSecretKey();

            return Jwts
                    .builder()
                    .setClaims(claims)
                    .setIssuedAt(now)
                    .setExpiration(new Date(now.getTime() + TOKEN_EXPIRATION))
                    .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                    .compact();
        }

        private String twistSecretKey() {
            String secretKey = SECRET_KEY;
            for (int i = 0; i < 5; i++) {
                secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
            }

            return secretKey;
        }
    }

    private static class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {
        private final Gson gson;
        private static final ErrorResponse RESPONSE_BODY = new ErrorResponse(ResponseCode.INVALID_AUTHENTICATION_INFO);

        public RestAuthenticationEntryPoint(Gson gson) {
            this.gson = gson;
        }

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
            // This is invoked when user tries to access a secured REST resource without supplying any credentials
            // We should just send a 401 Unauthorized response because there is no 'login page' to redirect to

            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
            response.getWriter().println(gson.toJson(RESPONSE_BODY));
        }
    }

    private static class JwtAccessDeniedHandler implements AccessDeniedHandler {
        private final Gson gson;
        private static final ErrorResponse RESPONSE_BODY = new ErrorResponse(ResponseCode.ACCESS_DENIED_AUTHENTICATION);

        public JwtAccessDeniedHandler(Gson gson) {
            this.gson = gson;
        }

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
            response.getWriter().println(gson.toJson(RESPONSE_BODY));
        }
    }
}
