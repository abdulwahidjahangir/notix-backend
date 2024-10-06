package com.secure.Notix.models;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private  Long id;

    private String action;
    private String username;
    private Long noteId;
    private String noteContent;
    private LocalDateTime timestamp;
}
