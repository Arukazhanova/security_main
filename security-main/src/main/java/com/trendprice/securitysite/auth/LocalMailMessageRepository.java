package com.trendprice.securitysite.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LocalMailMessageRepository extends JpaRepository<LocalMailMessage, Long> {

    List<LocalMailMessage> findTop20ByRecipientIgnoreCaseOrderByCreatedAtDesc(String recipient);

    List<LocalMailMessage> findTop50ByOrderByCreatedAtDesc();
}