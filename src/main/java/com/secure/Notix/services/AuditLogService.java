package com.secure.Notix.services;

import com.secure.Notix.models.AuditLog;
import com.secure.Notix.models.Note;

import java.util.List;

public interface AuditLogService {

     void logNoteCreation(String username, Note note);

     void logNoteUpdate(String username, Note note);

     void logNoteDeletion(String username, Long noteId);

     List<AuditLog> getAllAuditLogs();

     List<AuditLog> getAuditLogsForNoteId(Long noteId);
}
