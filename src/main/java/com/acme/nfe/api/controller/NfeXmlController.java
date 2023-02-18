package com.acme.nfe.api.controller;

import com.acme.nfe.core.security.CheckSecurity;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

@RestController
@RequestMapping("/v1/nfe/xml")
public class NfeXmlController {

    public static final String XML_FOLDER = "./xmls";

    @CheckSecurity
    @PostMapping(consumes =MediaType.MULTIPART_FORM_DATA_VALUE)
    public void uploadXml(@RequestParam @NotNull MultipartFile xml){
        var xmlFilename = UUID.randomUUID() + "_" + xml.getOriginalFilename();
        var xmlFolder = Path.of(XML_FOLDER);
        try {
            Files.createDirectories(xmlFolder);
            Path xmlFile = Path.of(XML_FOLDER, xmlFilename);
            xml.transferTo(xmlFile);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
