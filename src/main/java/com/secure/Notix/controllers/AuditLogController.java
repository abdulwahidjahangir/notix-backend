package com.secure.Notix.controllers;

import com.secure.Notix.models.AuditLog;
import com.secure.Notix.services.AuditLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditLogController {

    @Autowired
    private AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<AuditLog> getAuditLogs() {
        return auditLogService.getAllAuditLogs();
    }

    @GetMapping("/note/{id}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public List<AuditLog> getNoteAuditLogs(@PathVariable("id") Long noteId) {
        return auditLogService.getAuditLogsForNoteId(noteId);
    }
}
