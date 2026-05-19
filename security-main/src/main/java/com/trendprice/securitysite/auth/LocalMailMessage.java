package com.trendprice.securitysite.auth;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "local_mail_messages", indexes = {
        @Index(name = "idx_local_mail_recipient", columnList = "recipient"),
        @Index(name = "idx_local_mail_created_at", columnList = "created_at")
})
public class LocalMailMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 120)
    private String recipient;

    @Column(nullable = false, length = 200)
    private String subject;

    @Column(nullable = false, length = 4000)
    private String body;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected LocalMailMessage() {
    }

    public LocalMailMessage(String recipient, String subject, String body) {
        this.recipient = recipient;
        this.subject = subject;
        this.body = body;
    }

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public String getRecipient() {
        return recipient;
    }

    public String getSubject() {
        return subject;
    }

    public String getBody() {
        return body;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}