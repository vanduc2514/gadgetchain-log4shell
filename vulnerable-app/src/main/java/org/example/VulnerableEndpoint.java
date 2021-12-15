package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnerableEndpoint {

    private static final Logger LOGGER = LogManager.getLogger(VulnerableEndpoint.class);

    @GetMapping("/")
    public String vulnerable(@RequestBody(required = false) String payloadBody,
                             @RequestHeader(required = false, value = "X-Api-Version") String payloadHeader) {
        LOGGER.info("Received Request with body " + payloadBody);
        LOGGER.error("Received Request with header  " + payloadHeader);
        return "You have accessed a vulnerable Endpoint!!!";
    }

}
