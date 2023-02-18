package com.acme.nfe.core.security.authorization_server;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@Getter
@Setter
@Validated
@ConfigurationProperties("acme-api.auth")
public class AcmeSecurityProperties {
    @NotBlank
    public String providerUrl;
}
