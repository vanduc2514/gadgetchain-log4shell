package org.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.text.MessageFormat;

@RestController
public class VulnerableEndpoint {

    private static final Logger LOGGER = LogManager.getLogger(VulnerableEndpoint.class);

    @GetMapping("/")
    public String loggerVulnerable(@RequestBody(required = false) String payloadBody,
                             @RequestHeader(required = false, value = "X-Api-Version") String payloadHeader) {
        LOGGER.info("Received Request with body " + payloadBody);
        LOGGER.error("Received Request with header  " + payloadHeader);
        return "You have accessed a vulnerable Endpoint!!!";
    }

    @GetMapping("/thread-context")
    public String threadContextVulnerable(@RequestBody(required = false) String payloadBody) {
        ThreadContext.put("payloadbody", payloadBody);
        LOGGER.info("Received request for thread context vulnerable");
        return "You have accessed a vulnerable Endpoint!!!";
    }
}
