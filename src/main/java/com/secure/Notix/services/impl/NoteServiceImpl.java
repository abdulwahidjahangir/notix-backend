package com.secure.Notix.services.impl;

import com.secure.Notix.models.Note;
import com.secure.Notix.respositories.NoteRepository;
import com.secure.Notix.services.AuditLogService;
import com.secure.Notix.services.NoteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class NoteServiceImpl implements NoteService {

    @Autowired
    private NoteRepository noteRepository;

    @Autowired
    private AuditLogService auditLogService;

    @Override
    public Note createNoteForUser(String username, String content) {
        Note note = new Note();
        note.setContent(content);
        note.setOwnerUsername(username);
        Note savedNote = noteRepository.save(note);
        auditLogService.logNoteCreation(username, note);
        return savedNote;
    }

    @Override
    public Note updateNoteForUser(Long noteId, String username, String content) {
        Note note = noteRepository.findById(noteId).orElseThrow(
                () -> new RuntimeException("Note not found")
        );
        note.setContent(content);
        Note updateNote = noteRepository.save(note);
        auditLogService.logNoteUpdate(username, note);
        return updateNote;
    }

    @Override
    public void deleteNoteForUser(Long noteId, String username) {
        Note note = noteRepository.findById(noteId).orElseThrow(() ->
                new RuntimeException("Note note found")
        );
        noteRepository.delete(note);
        auditLogService.logNoteDeletion(username, noteId);
    }

    @Override
    public List<Note> getNotesForUser(String username) {
        List<Note> personalNotes = noteRepository.findByOwnerUsername(username);
        return personalNotes;
    }
}
