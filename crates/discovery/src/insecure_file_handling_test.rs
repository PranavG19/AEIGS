use super::insecure_file_handling::*;

const SOURCE_PATH_TRAVERSAL: &str = r#"
app.post('/upload', (req, res) => {
    const filename = req.body.filename;
    const dest = path.join('/uploads', filename);
    fs.writeFile(dest, req.body.data, (err) => {
        res.send('uploaded');
    });
});
"#;

const SOURCE_ZIP_EXTRACTION: &str = r#"
const extract = require('extract-zip');
async function handleZip(zipPath, destDir) {
    await extract(zipPath, { dir: destDir });
    const entries = zip.getEntries();
    for (const entry of entries) {
        const outPath = destDir + '/' + entry.name;
        fs.writeFileSync(outPath, entry.getData());
    }
}
"#;

const SOURCE_SYMLINK_NO_CHECK: &str = r#"
app.get('/download', (req, res) => {
    const filePath = req.query.path;
    fs.readFile(filePath, (err, data) => {
        res.send(data);
    });
});
"#;

const SOURCE_TOCTOU: &str = r#"
function processFile(filepath) {
    if (fs.existsSync(filepath)) {
        const data = fs.readFile(filepath, 'utf8', (err, content) => {
            return content;
        });
    }
}
"#;

const SOURCE_UNRESTRICTED_UPLOAD: &str = r#"
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), (req, res) => {
    const file = req.file;
    fs.rename(file.path, 'uploads/' + file.originalname, (err) => {
        res.json({ success: true });
    });
});
"#;

const SOURCE_MIMETYPE_ONLY: &str = r#"
const upload = multer({
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
            cb(null, true);
        } else {
            cb(new Error('Invalid type'));
        }
    }
});
"#;

const SOURCE_PREDICTABLE_PATH: &str = r#"
app.post('/upload', (req, res) => {
    const filename = Date.now() + '_' + file.name;
    const uploadPath = 'uploads/' + filename;
});
"#;

const SOURCE_SAFE_FILE_HANDLING: &str = r#"
const path = require('path');
const crypto = require('crypto');

app.post('/upload', upload.single('file'), (req, res) => {
    const ext = path.extname(req.file.originalname).replace(/[^a-zA-Z0-9.]/g, '');
    const allowedExtensions = ['.jpg', '.png', '.gif', '.pdf'];
    if (!allowedExtensions.includes(ext.toLowerCase())) {
        return res.status(400).send('Invalid file type');
    }
    const safeName = crypto.randomUUID() + ext;
    const destPath = path.resolve('/uploads', safeName);
    if (!destPath.startsWith('/uploads')) {
        return res.status(400).send('Invalid path');
    }
});
"#;

const SOURCE_UNSANITIZED_FILENAME: &str = r#"
app.post('/upload', (req, res) => {
    const name = req.file.originalname;
    fs.writeFileSync('/uploads/' + name, req.file.buffer);
});
"#;

#[test]
fn detects_path_traversal_in_upload() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/upload");
    let analysis = analyze_file_handling(SOURCE_PATH_TRAVERSAL, &config);

    let traversal_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.vuln_type == FileHandlingVulnType::PathTraversalUpload)
        .collect();

    assert!(
        !traversal_findings.is_empty(),
        "should detect path traversal in file upload"
    );

    assert!(
        traversal_findings
            .iter()
            .any(|f| f.severity == FileHandlingSeverity::Critical),
        "path traversal upload should be critical"
    );
}

#[test]
fn detects_zip_slip() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/extract");
    let analysis = analyze_file_handling(SOURCE_ZIP_EXTRACTION, &config);

    let zip_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.vuln_type == FileHandlingVulnType::ZipSlip)
        .collect();

    assert!(
        !zip_findings.is_empty(),
        "should detect zip slip vulnerability"
    );
}

#[test]
fn detects_symlink_attack() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/download");
    let analysis = analyze_file_handling(SOURCE_SYMLINK_NO_CHECK, &config);

    let symlink_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.vuln_type == FileHandlingVulnType::SymlinkAttack)
        .collect();

    assert!(
        !symlink_findings.is_empty(),
        "should detect symlink attack vulnerability"
    );
}

#[test]
fn detects_toctou_race() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/process");
    let analysis = analyze_file_handling(SOURCE_TOCTOU, &config);

    let toctou_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.vuln_type == FileHandlingVulnType::Toctou)
        .collect();

    assert!(
        !toctou_findings.is_empty(),
        "should detect TOCTOU race condition"
    );
}

#[test]
fn detects_unrestricted_file_type() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/upload");
    let analysis = analyze_file_handling(SOURCE_UNRESTRICTED_UPLOAD, &config);

    let type_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.vuln_type == FileHandlingVulnType::UnrestrictedFileType)
        .collect();

    assert!(
        !type_findings.is_empty(),
        "should detect unrestricted file type upload"
    );
}

#[test]
fn detects_unsanitized_filename() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/upload");
    let analysis = analyze_file_handling(SOURCE_UNSANITIZED_FILENAME, &config);

    let unsan = analysis.findings.iter().any(|f| {
        f.vuln_type == FileHandlingVulnType::UnsanitizedFilename
            || f.vuln_type == FileHandlingVulnType::PathTraversalUpload
    });

    assert!(unsan, "should detect unsanitized filename usage");
}

#[test]
fn detects_predictable_storage_path() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/upload");
    let analysis = analyze_file_handling(SOURCE_PREDICTABLE_PATH, &config);

    let predictable_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.vuln_type == FileHandlingVulnType::PredictableStoragePath)
        .collect();

    assert!(
        !predictable_findings.is_empty(),
        "should detect predictable file storage path"
    );
}

#[test]
fn safe_file_handling_produces_minimal_findings() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/upload");
    let analysis = analyze_file_handling(SOURCE_SAFE_FILE_HANDLING, &config);

    let critical_findings: Vec<_> = analysis
        .findings
        .iter()
        .filter(|f| f.severity == FileHandlingSeverity::Critical)
        .collect();

    assert_eq!(
        critical_findings.len(),
        0,
        "safe file handling should produce no critical findings"
    );
}

#[test]
fn generates_path_traversal_payloads() {
    let payloads = generate_path_traversal_payloads();

    assert!(
        payloads.len() >= 10,
        "should generate at least 10 traversal payloads"
    );
    assert!(
        payloads.iter().any(|p| p.contains("../")),
        "should include unix traversal"
    );
    assert!(
        payloads.iter().any(|p| p.contains("..\\")),
        "should include windows traversal"
    );
    assert!(
        payloads.iter().any(|p| p.contains("%2f")),
        "should include URL-encoded traversal"
    );
    assert!(
        payloads.iter().any(|p| p.contains("%252f")),
        "should include double-encoded traversal"
    );
}

#[test]
fn generates_zip_slip_payloads() {
    let payloads = generate_zip_slip_payloads();

    assert!(
        payloads.len() >= 5,
        "should generate at least 5 zip slip payloads"
    );
    assert!(
        payloads.iter().any(|(p, _)| p.contains("../")),
        "should include unix-style zip slip"
    );
    assert!(
        payloads.iter().any(|(p, _)| p.contains("..\\")),
        "should include windows-style zip slip"
    );
}

#[test]
fn generates_dangerous_filenames() {
    let filenames = generate_dangerous_filenames();

    assert!(
        filenames.len() >= 40,
        "should generate at least 40 dangerous filenames"
    );

    let has_php = filenames.iter().any(|(f, _)| f.ends_with(".php"));
    let has_exe = filenames.iter().any(|(f, _)| f.ends_with(".exe"));
    let has_polyglot = filenames.iter().any(|(f, _)| f.contains(".jpg.php"));
    let has_traversal = filenames.iter().any(|(f, _)| f.contains("../"));
    let has_htaccess = filenames.iter().any(|(f, _)| f.contains(".htaccess"));

    assert!(has_php, "should include PHP extension");
    assert!(has_exe, "should include EXE extension");
    assert!(has_polyglot, "should include polyglot extension");
    assert!(has_traversal, "should include path traversal filename");
    assert!(has_htaccess, "should include .htaccess");
}

#[test]
fn summary_counts_correct() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000/upload");
    let analysis = analyze_file_handling(SOURCE_PATH_TRAVERSAL, &config);

    assert_eq!(
        analysis.summary.total_findings,
        analysis.findings.len(),
        "summary total should match findings vec"
    );

    let actual_critical = analysis
        .findings
        .iter()
        .filter(|f| f.severity == FileHandlingSeverity::Critical)
        .count();
    assert_eq!(analysis.summary.critical_count, actual_critical);
}

#[test]
fn findings_sorted_by_severity() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_file_handling(SOURCE_UNRESTRICTED_UPLOAD, &config);

    for pair in analysis.findings.windows(2) {
        assert!(
            pair[0].severity >= pair[1].severity,
            "findings should be sorted by severity descending"
        );
    }
}

#[test]
fn findings_include_remediation() {
    let config = FileHandlingConfig::default().with_target("http://localhost:3000");
    let analysis = analyze_file_handling(SOURCE_PATH_TRAVERSAL, &config);

    for f in &analysis.findings {
        assert!(
            !f.remediation.is_empty(),
            "every finding should include remediation guidance"
        );
    }
}

#[test]
fn vuln_type_display_formatting() {
    assert_eq!(
        format!("{}", FileHandlingVulnType::PathTraversalUpload),
        "path-traversal-upload"
    );
    assert_eq!(format!("{}", FileHandlingVulnType::ZipSlip), "zip-slip");
    assert_eq!(
        format!("{}", FileHandlingVulnType::SymlinkAttack),
        "symlink-attack"
    );
    assert_eq!(format!("{}", FileHandlingVulnType::Toctou), "toctou");
    assert_eq!(
        format!("{}", FileHandlingVulnType::UnrestrictedFileType),
        "unrestricted-file-type"
    );
}

#[test]
fn severity_display_formatting() {
    assert_eq!(format!("{}", FileHandlingSeverity::Critical), "critical");
    assert_eq!(format!("{}", FileHandlingSeverity::High), "high");
    assert_eq!(format!("{}", FileHandlingSeverity::Medium), "medium");
    assert_eq!(format!("{}", FileHandlingSeverity::Low), "low");
    assert_eq!(format!("{}", FileHandlingSeverity::Info), "info");
}

#[test]
fn config_builder_pattern() {
    let config = FileHandlingConfig::default()
        .with_target("http://test.com")
        .with_payloads(false)
        .with_upload_endpoints(vec!["/api/upload".to_string()])
        .with_download_endpoints(vec!["/api/download".to_string()]);

    assert_eq!(config.target_url, "http://test.com");
    assert!(!config.generate_payloads);
    assert_eq!(config.check_upload_endpoints.len(), 1);
    assert_eq!(config.check_download_endpoints.len(), 1);
}

#[test]
fn disabled_payload_generation() {
    let config = FileHandlingConfig::default()
        .with_target("http://localhost:3000")
        .with_payloads(false);

    let analysis = analyze_file_handling(SOURCE_PATH_TRAVERSAL, &config);

    for f in &analysis.findings {
        assert!(
            f.payload.is_none(),
            "should not generate payloads when disabled"
        );
    }
}
