package com.acme.nfe.core.security.authorization_server;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.Arrays;

@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception{
        OAuth2AuthorizationServerConfigurer auth2AuthorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

        auth2AuthorizationServerConfigurer.authorizationEndpoint(customizer -> customizer.consentPage("/oauth2/consent"));

        RequestMatcher endpointMatcher = auth2AuthorizationServerConfigurer.getEndpointsMatcher();

        http.securityMatcher(endpointMatcher)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointMatcher))
                .apply(auth2AuthorizationServerConfigurer);
        return http.build();
    }

    @Bean
    public AuthorizationServerSettings providerSettings(AcmeSecurityProperties properties){
        return AuthorizationServerSettings.builder()
                .issuer(properties.getProviderUrl())
                .build();
    }

    @Setter
    @Getter
    @Validated
    @Component
    @ConfigurationProperties("acme-api.credentials")
    static class UserProperties1 {
        @NotNull
        private String clientId;
        @NotNull
        private String clientSecret;
    }
    @Setter
    @Getter
    @Validated
    @Component
    @ConfigurationProperties("spring.security.oauth2.resourceserver.opaquetoken")
    static class UserProperties2 {
        @NotNull
        private String clientId;
        @NotNull
        private String clientSecret;
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder, UserProperties1 userProperties1, UserProperties2 userProperties2){
        RegisteredClient userMic = RegisteredClient
                .withId("1")
                .clientId(userProperties1.getClientId())
                .clientSecret(passwordEncoder.encode(userProperties1.getClientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofMinutes(300))
                        .build())
                .build();

        RegisteredClient resourceServerUSer = RegisteredClient
                .withId("2")
                .clientId(userProperties2.getClientId())
                .clientSecret(passwordEncoder.encode(userProperties2.getClientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .accessTokenTimeToLive(Duration.ofMinutes(300))
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(Arrays.asList(userMic, resourceServerUSer));
    }
}
