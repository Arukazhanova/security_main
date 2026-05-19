package com.trendprice.securitysite.auth;

import com.trendprice.securitysite.dto.auth.LocalMailMessageResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/local-mail")
public class LocalMailController {

    private final LocalMailMessageRepository repository;
    private final boolean localMailboxEnabled;

    public LocalMailController(
            LocalMailMessageRepository repository,
            @Value("${app.local-mailbox.enabled:true}") boolean localMailboxEnabled
    ) {
        this.repository = repository;
        this.localMailboxEnabled = localMailboxEnabled;
    }

    @GetMapping
    public List<LocalMailMessageResponse> listMessages(@RequestParam(required = false) String email) {
        if (!localMailboxEnabled) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Local mailbox is disabled");
        }

        List<LocalMailMessage> messages = (email == null || email.isBlank())
                ? repository.findTop50ByOrderByCreatedAtDesc()
                : repository.findTop20ByRecipientIgnoreCaseOrderByCreatedAtDesc(email.trim());

        return messages.stream()
                .map(LocalMailMessageResponse::from)
                .toList();
    }
}