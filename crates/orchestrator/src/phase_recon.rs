use std::collections::HashSet;
use std::path::{Path, PathBuf};

use aegis_exploiter::{
    AmassWrapper, ExploitContext, ExploitResult, GauWrapper, ToolWrapper, TrufflehogWrapper,
    spawn_with_timeout,
};
use aegis_passive_recon::dependency_parser::{ParsedDependency, parse_lock_file};
use aegis_passive_recon::filesystem_walker::{FileClassification, walk_directory};
use aegis_passive_recon::vuln_database::VulnDatabase;
use aegis_protocol::finding::VulnerabilityClass;
use aegis_protocol::node::NodeType;
use aegis_protocol::operation::{GraphOperation, ModuleIdentifier, OperationLogEntry};

use crate::phase_error::PhaseError;
use crate::pipeline::{PhaseResult, ScanContext};
use crate::util::{extract_path_from_url, timestamp_ms};

pub fn run_recon(ctx: &mut ScanContext) -> Result<PhaseResult, PhaseError> {
    let mut entries = Vec::new();
    let mut sequence = 0u64;
    let mut findings_count = 0u64;

    let target = ctx.config.target.clone();
    let gau_target = target.clone();
    let amass_target = target.clone();
    let crtsh_target = target.clone();
    let s3_target = target.clone();
    let st_target = target;
    let gau_handle = std::thread::spawn(move || harvest_urls(&gau_target));
    let amass_handle = std::thread::spawn(move || enumerate_subdomains(&amass_target));
    let crtsh_handle = std::thread::spawn(move || query_crtsh(&crtsh_target));
    let st_handle = std::thread::spawn(move || query_securitytrails(&st_target));
    let s3_handle = std::thread::spawn(move || crate::s3_scanner::scan_s3_buckets(&s3_target));
    let shodan_target = ctx.config.target.clone();
    let shodan_handle =
        std::thread::spawn(move || crate::shodan_lookup::shodan_lookup(&shodan_target));
    let tls_target = ctx.config.target.clone();
    let tls_handle = std::thread::spawn(move || crate::tls_scanner::scan_tls(&tls_target));
    let hdr_target = ctx.config.target.clone();
    let hdr_handle =
        std::thread::spawn(move || crate::header_audit::audit_security_headers(&hdr_target));
    let robots_target = ctx.config.target.clone();
    let robots_handle =
        std::thread::spawn(move || crate::robots_parser::fetch_robots_txt(&robots_target));
    let sitemap_target = ctx.config.target.clone();
    let sitemap_handle =
        std::thread::spawn(move || crate::robots_parser::fetch_sitemap(&sitemap_target));
    let dns_target = ctx.config.target.clone();
    let dns_handle = std::thread::spawn(move || crate::dns_enumerator::enumerate_dns(&dns_target));
    let cors_target = ctx.config.target.clone();
    let cors_handle = std::thread::spawn(move || crate::cors_scanner::scan_cors(&cors_target));
    let cookie_target = ctx.config.target.clone();
    let cookie_handle =
        std::thread::spawn(move || crate::cookie_audit::audit_cookies(&cookie_target));
    let method_target = ctx.config.target.clone();
    let method_handle =
        std::thread::spawn(move || crate::method_scanner::scan_methods(&method_target));
    let redirect_target = ctx.config.target.clone();
    let redirect_handle =
        std::thread::spawn(move || crate::redirect_scanner::scan_redirects(&redirect_target));
    let info_target = ctx.config.target.clone();
    let info_handle =
        std::thread::spawn(move || crate::info_disclosure::scan_info_disclosure(&info_target));
    let email_target = ctx.config.target.clone();
    let email_handle =
        std::thread::spawn(move || crate::email_security::check_email_security(&email_target));
    let csp_target = ctx.config.target.clone();
    let csp_handle = std::thread::spawn(move || crate::csp_analyzer::analyze_csp(&csp_target));
    let hsts_target = ctx.config.target.clone();
    let hsts_handle =
        std::thread::spawn(move || crate::hsts_preload::check_hsts_preload(&hsts_target));
    let version_target = ctx.config.target.clone();
    let version_handle =
        std::thread::spawn(move || crate::http_version::detect_http_version(&version_target));
    let waf_target = ctx.config.target.clone();
    let waf_handle = std::thread::spawn(move || crate::waf_detector::detect_waf(&waf_target));
    let rl_target = ctx.config.target.clone();
    let rl_handle =
        std::thread::spawn(move || crate::rate_limit_detector::detect_rate_limits(&rl_target));
    let sectxt_target = ctx.config.target.clone();
    let sectxt_handle =
        std::thread::spawn(move || crate::security_txt::fetch_security_txt(&sectxt_target));
    let tech_target = ctx.config.target.clone();
    let tech_handle =
        std::thread::spawn(move || crate::tech_detector::detect_technologies(&tech_target));
    let pp_target = ctx.config.target.clone();
    let pp_handle =
        std::thread::spawn(move || crate::permissions_policy::check_permissions_policy(&pp_target));
    let cache_target = ctx.config.target.clone();
    let cache_handle =
        std::thread::spawn(move || crate::cache_audit::audit_cache_headers(&cache_target));
    let jslib_target = ctx.config.target.clone();
    let jslib_handle =
        std::thread::spawn(move || crate::js_library_scanner::scan_js_libraries(&jslib_target));
    let sri_target = ctx.config.target.clone();
    let sri_handle = std::thread::spawn(move || crate::sri_checker::check_sri(&sri_target));
    let mc_target = ctx.config.target.clone();
    let mc_handle =
        std::thread::spawn(move || crate::mixed_content::check_mixed_content(&mc_target));
    let form_target = ctx.config.target.clone();
    let form_handle =
        std::thread::spawn(move || crate::form_audit::audit_forms(&form_target));
    let comment_target = ctx.config.target.clone();
    let comment_handle =
        std::thread::spawn(move || crate::comment_leak::scan_comment_leaks(&comment_target));
    let smap_target = ctx.config.target.clone();
    let smap_handle =
        std::thread::spawn(move || crate::sourcemap_detector::detect_sourcemaps(&smap_target));
    let meta_target = ctx.config.target.clone();
    let meta_handle =
        std::thread::spawn(move || crate::meta_tag_audit::audit_meta_tags(&meta_target));
    let iframe_target = ctx.config.target.clone();
    let iframe_handle =
        std::thread::spawn(move || crate::iframe_audit::audit_iframes(&iframe_target));
    let base_target = ctx.config.target.clone();
    let base_handle =
        std::thread::spawn(move || crate::base_tag_audit::audit_base_tags(&base_target));
    let opener_target = ctx.config.target.clone();
    let opener_handle =
        std::thread::spawn(move || crate::opener_audit::audit_opener(&opener_target));
    let handler_target = ctx.config.target.clone();
    let handler_handle = std::thread::spawn(move || {
        crate::inline_handler_audit::audit_inline_handlers(&handler_target)
    });
    let djs_target = ctx.config.target.clone();
    let djs_handle = std::thread::spawn(move || {
        crate::dangerous_js_audit::audit_dangerous_js(&djs_target)
    });
    let precon_target = ctx.config.target.clone();
    let precon_handle = std::thread::spawn(move || {
        crate::preconnect_audit::audit_preconnects(&precon_target)
    });
    let errpage_target = ctx.config.target.clone();
    let errpage_handle = std::thread::spawn(move || {
        crate::error_page_audit::audit_error_pages(&errpage_target)
    });
    let referrer_target = ctx.config.target.clone();
    let referrer_handle = std::thread::spawn(move || {
        crate::referrer_audit::audit_referrer_policy(&referrer_target)
    });
    let xfo_target = ctx.config.target.clone();
    let xfo_handle =
        std::thread::spawn(move || crate::xfo_audit::audit_xfo(&xfo_target));
    let coop_target = ctx.config.target.clone();
    let coop_handle =
        std::thread::spawn(move || crate::coop_coep_audit::audit_coop_coep(&coop_target));
    let corp_target = ctx.config.target.clone();
    let corp_handle =
        std::thread::spawn(move || crate::corp_audit::audit_corp(&corp_target));
    let ctype_target = ctx.config.target.clone();
    let ctype_handle =
        std::thread::spawn(move || crate::content_type_audit::audit_content_type(&ctype_target));
    let stiming_target = ctx.config.target.clone();
    let stiming_handle = std::thread::spawn(move || {
        crate::server_timing_audit::audit_server_timing(&stiming_target)
    });
    let dephdr_target = ctx.config.target.clone();
    let dephdr_handle = std::thread::spawn(move || {
        crate::deprecated_header_audit::audit_deprecated_headers(&dephdr_target)
    });
    let exphdr_target = ctx.config.target.clone();
    let exphdr_handle = std::thread::spawn(move || {
        crate::expose_headers_audit::audit_expose_headers(&exphdr_target)
    });
    let docdomain_target = ctx.config.target.clone();
    let docdomain_handle = std::thread::spawn(move || {
        crate::document_domain_audit::audit_document_domain(&docdomain_target)
    });
    let nel_target = ctx.config.target.clone();
    let nel_handle =
        std::thread::spawn(move || crate::nel_audit::audit_nel(&nel_target));
    let linkhdr_target = ctx.config.target.clone();
    let linkhdr_handle =
        std::thread::spawn(move || crate::link_header_audit::audit_link_header(&linkhdr_target));
    let repep_target = ctx.config.target.clone();
    let repep_handle = std::thread::spawn(move || {
        crate::reporting_endpoints_audit::audit_reporting_endpoints(&repep_target)
    });
    let tao_target = ctx.config.target.clone();
    let tao_handle = std::thread::spawn(move || {
        crate::timing_allow_origin_audit::audit_timing_allow_origin(&tao_target)
    });
    let csd_target = ctx.config.target.clone();
    let csd_handle = std::thread::spawn(move || {
        crate::clear_site_data_audit::audit_clear_site_data(&csd_target)
    });
    let smhdr_target = ctx.config.target.clone();
    let smhdr_handle = std::thread::spawn(move || {
        crate::sourcemap_header_audit::audit_sourcemap_header(&smhdr_target)
    });
    let etag_target = ctx.config.target.clone();
    let etag_handle =
        std::thread::spawn(move || crate::etag_audit::audit_etag(&etag_target));
    let wwwauth_target = ctx.config.target.clone();
    let wwwauth_handle = std::thread::spawn(move || {
        crate::www_authenticate_audit::audit_www_authenticate(&wwwauth_target)
    });
    let proxyhdr_target = ctx.config.target.clone();
    let proxyhdr_handle = std::thread::spawn(move || {
        crate::proxy_header_audit::audit_proxy_headers(&proxyhdr_target)
    });
    let dnspf_target = ctx.config.target.clone();
    let dnspf_handle = std::thread::spawn(move || {
        crate::dns_prefetch_control_audit::audit_dns_prefetch_control(&dnspf_target)
    });
    let jsonp_target = ctx.config.target.clone();
    let jsonp_handle =
        std::thread::spawn(move || crate::jsonp_audit::audit_jsonp(&jsonp_target));
    let hidinput_target = ctx.config.target.clone();
    let hidinput_handle = std::thread::spawn(move || {
        crate::hidden_input_audit::audit_hidden_inputs(&hidinput_target)
    });
    let trufflehog_handle = ctx.config.source_dir.as_ref().map(|dir| {
        let dir = dir.clone();
        std::thread::spawn(move || scan_secrets(&dir))
    });
    let github_org_handle = ctx.config.github_org.as_ref().map(|org| {
        let org = org.clone();
        std::thread::spawn(move || scan_github_org(&org))
    });

    if let Some(source_dir) = &ctx.config.source_dir {
        let walk =
            walk_directory(source_dir).map_err(|e| PhaseError::FilesystemWalk(e.to_string()))?;
        let lock_files: Vec<_> = walk
            .files
            .iter()
            .filter(|f| f.classification == FileClassification::LockFile)
            .collect();

        let mut all_deps: Vec<ParsedDependency> = Vec::new();
        for lock_file in &lock_files {
            if let Ok(deps) = parse_lock_file(&lock_file.path) {
                all_deps.extend(deps);
            }
        }

        entries.extend(deps_to_operations(&all_deps, &mut sequence));
        entries.extend(vuln_lookup(
            &all_deps,
            &mut sequence,
            ctx.config.scope.vuln_db.as_deref(),
        ));
        entries.extend(walk_to_operations(&walk.files, &mut sequence));
    }

    if let Some(handle) = trufflehog_handle {
        let secrets = handle.join().unwrap_or_default();
        let secret_ops = secret_findings_to_operations(&secrets, &mut sequence);
        findings_count += secret_ops.len() as u64;
        entries.extend(secret_ops);
    }

    if let Some(handle) = github_org_handle {
        let secrets = handle.join().unwrap_or_default();
        let org_ops = secret_findings_to_operations(&secrets, &mut sequence);
        findings_count += org_ops.len() as u64;
        entries.extend(org_ops);
    }

    let gau_urls = gau_handle.join().unwrap_or_default();
    entries.extend(harvested_urls_to_operations(&gau_urls, &mut sequence));

    let subdomains = amass_handle.join().unwrap_or_default();
    entries.extend(subdomains_to_operations(&subdomains, &mut sequence));

    let ct_subdomains = crtsh_handle.join().unwrap_or_default();
    entries.extend(crtsh_to_operations(&ct_subdomains, &mut sequence));

    let st_subdomains = st_handle.join().unwrap_or_default();
    entries.extend(securitytrails_to_operations(&st_subdomains, &mut sequence));

    let mut all_subdomains = Vec::new();
    all_subdomains.extend(subdomains.iter().cloned());
    all_subdomains.extend(ct_subdomains.iter().cloned());
    all_subdomains.extend(st_subdomains.iter().cloned());
    all_subdomains.sort();
    all_subdomains.dedup();
    if !all_subdomains.is_empty() {
        let takeover_candidates =
            crate::subdomain_takeover::check_subdomain_takeover(&all_subdomains);
        let takeover_ops = crate::subdomain_takeover::takeover_findings_to_operations(
            &takeover_candidates,
            &mut sequence,
        );
        findings_count += takeover_ops.len() as u64;
        entries.extend(takeover_ops);
    }

    let s3_findings = s3_handle.join().unwrap_or_default();
    let s3_ops = crate::s3_scanner::s3_findings_to_operations(&s3_findings, &mut sequence);
    findings_count += s3_ops
        .iter()
        .filter(|op| matches!(op.operation, GraphOperation::AddFinding { .. }))
        .count() as u64;
    entries.extend(s3_ops);

    if let Some(shodan_result) = shodan_handle.join().ok().flatten() {
        let shodan_ops = crate::shodan_lookup::shodan_to_operations(&shodan_result, &mut sequence);
        findings_count += shodan_ops
            .iter()
            .filter(|op| matches!(op.operation, GraphOperation::AddFinding { .. }))
            .count() as u64;
        entries.extend(shodan_ops);
    }

    let tls_findings = tls_handle.join().unwrap_or_default();
    let tls_ops = crate::tls_scanner::tls_findings_to_operations(&tls_findings, &mut sequence);
    findings_count += tls_ops.len() as u64;
    entries.extend(tls_ops);

    let hdr_findings = hdr_handle.join().unwrap_or_default();
    let hdr_ops = crate::header_audit::header_findings_to_operations(&hdr_findings, &mut sequence);
    findings_count += hdr_ops.len() as u64;
    entries.extend(hdr_ops);

    let robots_paths = robots_handle.join().unwrap_or_default();
    entries.extend(crate::robots_parser::discovered_paths_to_operations(
        &robots_paths,
        "robots.txt",
        &mut sequence,
    ));

    let sitemap_urls = sitemap_handle.join().unwrap_or_default();
    entries.extend(crate::robots_parser::discovered_paths_to_operations(
        &sitemap_urls,
        "sitemap.xml",
        &mut sequence,
    ));

    let dns_records = dns_handle.join().unwrap_or_default();
    entries.extend(crate::dns_enumerator::dns_to_operations(
        &dns_records,
        &mut sequence,
    ));

    let cors_findings = cors_handle.join().unwrap_or_default();
    let cors_ops = crate::cors_scanner::cors_findings_to_operations(&cors_findings, &mut sequence);
    findings_count += cors_ops.len() as u64;
    entries.extend(cors_ops);

    let cookie_findings = cookie_handle.join().unwrap_or_default();
    let cookie_ops =
        crate::cookie_audit::cookie_findings_to_operations(&cookie_findings, &mut sequence);
    findings_count += cookie_ops.len() as u64;
    entries.extend(cookie_ops);

    if let Some(method_result) = method_handle.join().ok().flatten() {
        let method_ops =
            crate::method_scanner::method_findings_to_operations(&method_result, &mut sequence);
        findings_count += method_ops.len() as u64;
        entries.extend(method_ops);
    }

    let redirect_findings = redirect_handle.join().unwrap_or_default();
    let redirect_ops =
        crate::redirect_scanner::redirect_findings_to_operations(&redirect_findings, &mut sequence);
    findings_count += redirect_ops.len() as u64;
    entries.extend(redirect_ops);

    let info_findings = info_handle.join().unwrap_or_default();
    let info_ops =
        crate::info_disclosure::disclosure_findings_to_operations(&info_findings, &mut sequence);
    findings_count += info_ops.len() as u64;
    entries.extend(info_ops);

    let email_issues = email_handle.join().unwrap_or_default();
    let email_ops =
        crate::email_security::email_findings_to_operations(&email_issues, &mut sequence);
    findings_count += email_ops.len() as u64;
    entries.extend(email_ops);

    let csp_issues = csp_handle.join().unwrap_or_default();
    let csp_ops = crate::csp_analyzer::csp_findings_to_operations(&csp_issues, &mut sequence);
    findings_count += csp_ops.len() as u64;
    entries.extend(csp_ops);

    let hsts_issues = hsts_handle.join().unwrap_or_default();
    let hsts_ops = crate::hsts_preload::hsts_findings_to_operations(&hsts_issues, &mut sequence);
    findings_count += hsts_ops.len() as u64;
    entries.extend(hsts_ops);

    if let Some(version_info) = version_handle.join().ok().flatten() {
        entries.extend(crate::http_version::version_to_operations(
            &version_info,
            &mut sequence,
        ));
    }

    let waf_detections = waf_handle.join().unwrap_or_default();
    entries.extend(crate::waf_detector::waf_to_operations(
        &waf_detections,
        &mut sequence,
    ));

    if let Some(rl_info) = rl_handle.join().ok().flatten() {
        entries.extend(crate::rate_limit_detector::rate_limit_to_operations(
            &rl_info,
            &mut sequence,
        ));
    }

    if let Some(sectxt_info) = sectxt_handle.join().ok().flatten() {
        entries.extend(crate::security_txt::security_txt_to_operations(
            &sectxt_info,
            &mut sequence,
        ));
    }

    let tech_detections = tech_handle.join().unwrap_or_default();
    entries.extend(crate::tech_detector::tech_to_operations(
        &tech_detections,
        &mut sequence,
    ));

    let pp_issues = pp_handle.join().unwrap_or_default();
    let pp_ops =
        crate::permissions_policy::policy_findings_to_operations(&pp_issues, &mut sequence);
    findings_count += pp_ops.len() as u64;
    entries.extend(pp_ops);

    let cache_issues = cache_handle.join().unwrap_or_default();
    let cache_ops = crate::cache_audit::cache_findings_to_operations(&cache_issues, &mut sequence);
    findings_count += cache_ops.len() as u64;
    entries.extend(cache_ops);

    let jslib_findings = jslib_handle.join().unwrap_or_default();
    let jslib_ops = crate::js_library_scanner::js_library_findings_to_operations(
        &jslib_findings,
        &mut sequence,
    );
    findings_count += jslib_ops.len() as u64;
    entries.extend(jslib_ops);

    let sri_issues = sri_handle.join().unwrap_or_default();
    let sri_ops = crate::sri_checker::sri_findings_to_operations(&sri_issues, &mut sequence);
    findings_count += sri_ops.len() as u64;
    entries.extend(sri_ops);

    let mc_issues = mc_handle.join().unwrap_or_default();
    let mc_ops =
        crate::mixed_content::mixed_content_to_operations(&mc_issues, &mut sequence);
    findings_count += mc_ops.len() as u64;
    entries.extend(mc_ops);

    let form_findings = form_handle.join().unwrap_or_default();
    let form_ops =
        crate::form_audit::form_findings_to_operations(&form_findings, &mut sequence);
    findings_count += form_ops.len() as u64;
    entries.extend(form_ops);

    let comment_leaks = comment_handle.join().unwrap_or_default();
    let comment_ops =
        crate::comment_leak::comment_leak_to_operations(&comment_leaks, &mut sequence);
    findings_count += comment_ops.len() as u64;
    entries.extend(comment_ops);

    let smap_leaks = smap_handle.join().unwrap_or_default();
    let smap_ops =
        crate::sourcemap_detector::sourcemap_to_operations(&smap_leaks, &mut sequence);
    findings_count += smap_ops.len() as u64;
    entries.extend(smap_ops);

    let meta_issues = meta_handle.join().unwrap_or_default();
    let meta_ops =
        crate::meta_tag_audit::meta_findings_to_operations(&meta_issues, &mut sequence);
    findings_count += meta_ops.len() as u64;
    entries.extend(meta_ops);

    let iframe_findings = iframe_handle.join().unwrap_or_default();
    let iframe_ops =
        crate::iframe_audit::iframe_findings_to_operations(&iframe_findings, &mut sequence);
    findings_count += iframe_ops.len() as u64;
    entries.extend(iframe_ops);

    let base_findings = base_handle.join().unwrap_or_default();
    let base_ops =
        crate::base_tag_audit::base_tag_to_operations(&base_findings, &mut sequence);
    findings_count += base_ops.len() as u64;
    entries.extend(base_ops);

    let opener_issues = opener_handle.join().unwrap_or_default();
    let opener_ops =
        crate::opener_audit::opener_to_operations(&opener_issues, &mut sequence);
    findings_count += opener_ops.len() as u64;
    entries.extend(opener_ops);

    let handler_issues = handler_handle.join().unwrap_or_default();
    let handler_ops =
        crate::inline_handler_audit::inline_handler_to_operations(&handler_issues, &mut sequence);
    findings_count += handler_ops.len() as u64;
    entries.extend(handler_ops);

    let djs_issues = djs_handle.join().unwrap_or_default();
    let djs_ops =
        crate::dangerous_js_audit::dangerous_js_to_operations(&djs_issues, &mut sequence);
    findings_count += djs_ops.len() as u64;
    entries.extend(djs_ops);

    let precon_issues = precon_handle.join().unwrap_or_default();
    let precon_ops =
        crate::preconnect_audit::preconnect_to_operations(&precon_issues, &mut sequence);
    findings_count += precon_ops.len() as u64;
    entries.extend(precon_ops);

    let errpage_leaks = errpage_handle.join().unwrap_or_default();
    let errpage_ops =
        crate::error_page_audit::error_page_to_operations(&errpage_leaks, &mut sequence);
    findings_count += errpage_ops.len() as u64;
    entries.extend(errpage_ops);

    let referrer_issues = referrer_handle.join().unwrap_or_default();
    let referrer_ops =
        crate::referrer_audit::referrer_to_operations(&referrer_issues, &mut sequence);
    findings_count += referrer_ops.len() as u64;
    entries.extend(referrer_ops);

    let xfo_issues = xfo_handle.join().unwrap_or_default();
    let xfo_ops = crate::xfo_audit::xfo_to_operations(&xfo_issues, &mut sequence);
    findings_count += xfo_ops.len() as u64;
    entries.extend(xfo_ops);

    let coop_issues = coop_handle.join().unwrap_or_default();
    let coop_ops =
        crate::coop_coep_audit::coop_coep_to_operations(&coop_issues, &mut sequence);
    findings_count += coop_ops.len() as u64;
    entries.extend(coop_ops);

    let corp_issues = corp_handle.join().unwrap_or_default();
    let corp_ops = crate::corp_audit::corp_to_operations(&corp_issues, &mut sequence);
    findings_count += corp_ops.len() as u64;
    entries.extend(corp_ops);

    let ctype_issues = ctype_handle.join().unwrap_or_default();
    let ctype_ops =
        crate::content_type_audit::content_type_to_operations(&ctype_issues, &mut sequence);
    findings_count += ctype_ops.len() as u64;
    entries.extend(ctype_ops);

    let stiming_leaks = stiming_handle.join().unwrap_or_default();
    let stiming_ops =
        crate::server_timing_audit::server_timing_to_operations(&stiming_leaks, &mut sequence);
    findings_count += stiming_ops.len() as u64;
    entries.extend(stiming_ops);

    let dephdr_issues = dephdr_handle.join().unwrap_or_default();
    let dephdr_ops = crate::deprecated_header_audit::deprecated_header_to_operations(
        &dephdr_issues,
        &mut sequence,
    );
    findings_count += dephdr_ops.len() as u64;
    entries.extend(dephdr_ops);

    let exphdr_issues = exphdr_handle.join().unwrap_or_default();
    let exphdr_ops =
        crate::expose_headers_audit::expose_headers_to_operations(&exphdr_issues, &mut sequence);
    findings_count += exphdr_ops.len() as u64;
    entries.extend(exphdr_ops);

    let docdomain_issues = docdomain_handle.join().unwrap_or_default();
    let docdomain_ops = crate::document_domain_audit::document_domain_to_operations(
        &docdomain_issues,
        &mut sequence,
    );
    findings_count += docdomain_ops.len() as u64;
    entries.extend(docdomain_ops);

    let nel_issues = nel_handle.join().unwrap_or_default();
    let nel_ops = crate::nel_audit::nel_to_operations(&nel_issues, &mut sequence);
    findings_count += nel_ops.len() as u64;
    entries.extend(nel_ops);

    let linkhdr_issues = linkhdr_handle.join().unwrap_or_default();
    let linkhdr_ops =
        crate::link_header_audit::link_header_to_operations(&linkhdr_issues, &mut sequence);
    findings_count += linkhdr_ops.len() as u64;
    entries.extend(linkhdr_ops);

    let repep_issues = repep_handle.join().unwrap_or_default();
    let repep_ops = crate::reporting_endpoints_audit::reporting_endpoints_to_operations(
        &repep_issues,
        &mut sequence,
    );
    findings_count += repep_ops.len() as u64;
    entries.extend(repep_ops);

    let tao_issues = tao_handle.join().unwrap_or_default();
    let tao_ops = crate::timing_allow_origin_audit::timing_allow_origin_to_operations(
        &tao_issues,
        &mut sequence,
    );
    findings_count += tao_ops.len() as u64;
    entries.extend(tao_ops);

    let csd_issues = csd_handle.join().unwrap_or_default();
    let csd_ops = crate::clear_site_data_audit::clear_site_data_to_operations(
        &csd_issues,
        &mut sequence,
    );
    findings_count += csd_ops.len() as u64;
    entries.extend(csd_ops);

    let smhdr_issues = smhdr_handle.join().unwrap_or_default();
    let smhdr_ops = crate::sourcemap_header_audit::sourcemap_header_to_operations(
        &smhdr_issues,
        &mut sequence,
    );
    findings_count += smhdr_ops.len() as u64;
    entries.extend(smhdr_ops);

    let etag_issues = etag_handle.join().unwrap_or_default();
    let etag_ops = crate::etag_audit::etag_to_operations(&etag_issues, &mut sequence);
    findings_count += etag_ops.len() as u64;
    entries.extend(etag_ops);

    let wwwauth_issues = wwwauth_handle.join().unwrap_or_default();
    let wwwauth_ops = crate::www_authenticate_audit::www_authenticate_to_operations(
        &wwwauth_issues,
        &mut sequence,
    );
    findings_count += wwwauth_ops.len() as u64;
    entries.extend(wwwauth_ops);

    let proxyhdr_issues = proxyhdr_handle.join().unwrap_or_default();
    let proxyhdr_ops =
        crate::proxy_header_audit::proxy_header_to_operations(&proxyhdr_issues, &mut sequence);
    findings_count += proxyhdr_ops.len() as u64;
    entries.extend(proxyhdr_ops);

    let dnspf_issues = dnspf_handle.join().unwrap_or_default();
    let dnspf_ops = crate::dns_prefetch_control_audit::dns_prefetch_control_to_operations(
        &dnspf_issues,
        &mut sequence,
    );
    findings_count += dnspf_ops.len() as u64;
    entries.extend(dnspf_ops);

    let jsonp_issues = jsonp_handle.join().unwrap_or_default();
    let jsonp_ops = crate::jsonp_audit::jsonp_to_operations(&jsonp_issues, &mut sequence);
    findings_count += jsonp_ops.len() as u64;
    entries.extend(jsonp_ops);

    let hidinput_issues = hidinput_handle.join().unwrap_or_default();
    let hidinput_ops =
        crate::hidden_input_audit::hidden_input_to_operations(&hidinput_issues, &mut sequence);
    findings_count += hidinput_ops.len() as u64;
    entries.extend(hidinput_ops);

    let ops_count = entries.len() as u64;
    if !entries.is_empty() {
        ctx.graph.apply_operations(&entries)?;
    }

    Ok(PhaseResult {
        operations_applied: ops_count,
        findings_count,
    })
}

pub(crate) fn deps_to_operations(
    deps: &[ParsedDependency],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    deps.iter()
        .map(|dep| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Dependency,
                    properties: vec![
                        ("name".to_string(), dep.name.clone()),
                        ("version".to_string(), dep.version.clone()),
                        ("ecosystem".to_string(), format!("{:?}", dep.ecosystem)),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub(crate) fn vuln_lookup(
    deps: &[ParsedDependency],
    seq: &mut u64,
    vuln_db_path: Option<&Path>,
) -> Vec<OperationLogEntry> {
    let db = match vuln_db_path {
        Some(path) if path.exists() => VulnDatabase::open(path).ok(),
        _ => {
            let default = crate::update_db::default_db_path();
            if default.exists() {
                VulnDatabase::open(&default).ok()
            } else {
                None
            }
        }
    };
    let Some(db) = db else {
        return Vec::new();
    };
    let Ok(matches) = db.check_all_dependencies(deps) else {
        return Vec::new();
    };
    matches
        .iter()
        .map(|m| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class:
                        aegis_protocol::finding::VulnerabilityClass::KnownVulnerableDependency,
                    severity: m.severity,
                    confidence: aegis_protocol::finding::Confidence::new(0.9).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub(crate) fn walk_to_operations(
    files: &[aegis_passive_recon::filesystem_walker::ClassifiedFile],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    files
        .iter()
        .filter(|f| f.classification == FileClassification::ConfigFile)
        .map(|f| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Config,
                    properties: vec![("path".to_string(), f.path.to_string_lossy().to_string())],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

pub fn run_recon_standalone(
    source_dir: &Option<PathBuf>,
    vuln_db_path: Option<&Path>,
) -> Result<Vec<OperationLogEntry>, PhaseError> {
    let Some(source_dir) = source_dir else {
        return Ok(Vec::new());
    };

    let walk = walk_directory(source_dir).map_err(|e| PhaseError::FilesystemWalk(e.to_string()))?;
    let lock_files: Vec<_> = walk
        .files
        .iter()
        .filter(|f| f.classification == FileClassification::LockFile)
        .collect();

    let mut all_deps = Vec::new();
    for lock_file in &lock_files {
        if let Ok(deps) = parse_lock_file(&lock_file.path) {
            all_deps.extend(deps);
        }
    }

    let mut sequence = 0u64;
    let mut entries = Vec::new();
    entries.extend(deps_to_operations(&all_deps, &mut sequence));
    entries.extend(vuln_lookup(&all_deps, &mut sequence, vuln_db_path));
    entries.extend(walk_to_operations(&walk.files, &mut sequence));
    Ok(entries)
}

/// Runs gau to harvest historical URLs from web archives.
pub fn harvest_urls(target: &str) -> Vec<String> {
    let wrapper = GauWrapper;
    if !wrapper.is_available() {
        tracing::debug!("gau not installed, skipping URL harvest");
        return Vec::new();
    }
    let context = ExploitContext::new(
        target.to_string(),
        String::new(),
        VulnerabilityClass::InformationDisclosure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "gau") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "gau URL harvest failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    let mut urls: Vec<String> = results
        .iter()
        .filter_map(|r| r.extracted_data.clone())
        .collect();
    urls.sort();
    urls.dedup();
    if !urls.is_empty() {
        tracing::info!(count = urls.len(), "gau harvested historical URLs");
    }
    urls
}

/// Converts harvested URLs into Endpoint node operations, deduplicating by path.
pub(crate) fn harvested_urls_to_operations(
    urls: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    let mut seen_paths = HashSet::new();
    urls.iter()
        .filter_map(|url| extract_path_from_url(url))
        .filter(|path| seen_paths.insert(path.clone()))
        .map(|path| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Endpoint,
                    properties: vec![
                        ("path".to_string(), path),
                        ("method".to_string(), "GET".to_string()),
                        ("source".to_string(), "gau".to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

/// Runs amass for passive subdomain enumeration.
pub fn enumerate_subdomains(target: &str) -> Vec<String> {
    let wrapper = AmassWrapper;
    if !wrapper.is_available() {
        tracing::debug!("amass not installed, skipping subdomain enumeration");
        return Vec::new();
    }
    let context = ExploitContext::new(
        target.to_string(),
        String::new(),
        VulnerabilityClass::InformationDisclosure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "amass") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "amass subdomain enumeration failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    let mut subdomains: Vec<String> = results
        .iter()
        .filter_map(|r| r.extracted_data.clone())
        .collect();
    subdomains.sort();
    subdomains.dedup();
    if !subdomains.is_empty() {
        tracing::info!(count = subdomains.len(), "amass found subdomains");
    }
    subdomains
}

/// Converts discovered subdomains into Service node operations.
pub(crate) fn subdomains_to_operations(
    subdomains: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "amass", seq)
}

pub(crate) fn subdomains_to_operations_with_source(
    subdomains: &[String],
    source: &str,
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains
        .iter()
        .map(|subdomain| {
            *seq += 1;
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddNode {
                    node_type: NodeType::Service,
                    properties: vec![
                        ("hostname".to_string(), subdomain.clone()),
                        ("source".to_string(), source.to_string()),
                    ],
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}

/// Runs trufflehog to scan source directory for leaked secrets.
pub fn scan_secrets(source_dir: &Path) -> Vec<ExploitResult> {
    let wrapper = TrufflehogWrapper;
    if !wrapper.is_available() {
        tracing::debug!("trufflehog not installed, skipping secret scan");
        return Vec::new();
    }
    let context = ExploitContext::new(
        String::new(),
        source_dir.to_string_lossy().to_string(),
        VulnerabilityClass::SensitiveDataExposure,
    );
    let command = wrapper.build_command(&context);
    let (stdout, stderr) = match spawn_with_timeout(command, wrapper.timeout(), "trufflehog") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(error = %e, "trufflehog secret scan failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    if !results.is_empty() {
        tracing::info!(count = results.len(), "trufflehog found potential secrets");
    }
    results
}

/// Runs trufflehog in GitHub org mode to scan an organization's repositories.
///
/// Requires trufflehog installed and GITHUB_TOKEN env var for API access.
/// Uses the same output parser as filesystem mode since the JSON format
/// is identical.
pub fn scan_github_org(org: &str) -> Vec<ExploitResult> {
    let wrapper = TrufflehogWrapper;
    if !wrapper.is_available() {
        tracing::debug!("trufflehog not installed, skipping GitHub org scan");
        return Vec::new();
    }
    if std::env::var("GITHUB_TOKEN").is_err() {
        tracing::debug!("GITHUB_TOKEN not set, skipping GitHub org scan");
        return Vec::new();
    }
    let mut command = std::process::Command::new("trufflehog");
    command.args([
        "github",
        "--org",
        org,
        "--json",
        "--results=verified,unknown",
        "--no-update",
    ]);
    // GitHub org scanning is slower than filesystem — double the wrapper's base timeout
    let timeout = wrapper.timeout().saturating_mul(2);
    let (stdout, stderr) = match spawn_with_timeout(command, timeout, "trufflehog-github") {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!(org = %org, error = %e, "trufflehog GitHub org scan failed");
            return Vec::new();
        }
    };
    let results = wrapper.parse_output(&stdout, &stderr);
    if !results.is_empty() {
        tracing::info!(
            org = %org,
            count = results.len(),
            "trufflehog found secrets in GitHub org"
        );
    }
    results
}

/// Queries crt.sh Certificate Transparency logs for subdomains of the target.
///
/// Uses the free crt.sh HTTPS API (no API key needed). Returns deduplicated
/// subdomain names. Returns an empty vec on any network/parse error.
pub fn query_crtsh(target: &str) -> Vec<String> {
    let Some(domain) = crate::recon_client::validated_domain(target) else {
        tracing::debug!("could not extract domain from target for crt.sh query");
        return Vec::new();
    };
    let url = format!("https://crt.sh/?q=%.{domain}&output=json");
    let client = match crate::recon_client::build_client(std::time::Duration::from_secs(30)) {
        Some(c) => c,
        None => {
            tracing::warn!("failed to build HTTP client for crt.sh");
            return Vec::new();
        }
    };
    let response = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "crt.sh query failed");
            return Vec::new();
        }
    };
    let body = match response.text() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read crt.sh response body");
            return Vec::new();
        }
    };
    let subdomains = parse_crtsh_response(&body);
    if !subdomains.is_empty() {
        tracing::info!(
            count = subdomains.len(),
            "crt.sh found subdomains via CT logs"
        );
    }
    subdomains
}

/// Parses crt.sh JSON response into a deduplicated list of subdomain names.
pub(crate) fn parse_crtsh_response(body: &str) -> Vec<String> {
    let entries: Vec<CrtshEntry> = match serde_json::from_str(body) {
        Ok(e) => e,
        Err(_) => {
            tracing::debug!("failed to parse crt.sh JSON response");
            return Vec::new();
        }
    };
    let mut seen = HashSet::new();
    let mut subdomains = Vec::new();
    for entry in &entries {
        for name in entry.name_value.split('\n') {
            let name = name.trim().trim_start_matches("*.");
            if !name.is_empty() && seen.insert(name) {
                subdomains.push(name.to_string());
            }
        }
    }
    subdomains
}

#[derive(serde::Deserialize)]
struct CrtshEntry {
    #[serde(default)]
    name_value: String,
}

pub(crate) fn crtsh_to_operations(subdomains: &[String], seq: &mut u64) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "crtsh", seq)
}

/// Queries SecurityTrails API for subdomains of the target domain.
///
/// Requires `SECURITYTRAILS_API_KEY` environment variable. Returns empty vec
/// if the key is not set or the query fails. Free tier: 50 queries/month.
pub fn query_securitytrails(target: &str) -> Vec<String> {
    let api_key = match std::env::var("SECURITYTRAILS_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            tracing::debug!("SECURITYTRAILS_API_KEY not set, skipping SecurityTrails query");
            return Vec::new();
        }
    };
    let Some(domain) = crate::recon_client::validated_domain(target) else {
        return Vec::new();
    };
    let url = format!("https://api.securitytrails.com/v1/domain/{domain}/subdomains");
    let client = match crate::recon_client::build_client(std::time::Duration::from_secs(30)) {
        Some(c) => c,
        None => {
            tracing::warn!("failed to build HTTP client for SecurityTrails");
            return Vec::new();
        }
    };
    let response = match client.get(&url).header("APIKEY", &api_key).send() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "SecurityTrails query failed");
            return Vec::new();
        }
    };
    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "SecurityTrails returned non-success status"
        );
        return Vec::new();
    }
    let body = match response.text() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read SecurityTrails response body");
            return Vec::new();
        }
    };
    let subdomains = parse_securitytrails_response(&body, &domain);
    if !subdomains.is_empty() {
        tracing::info!(count = subdomains.len(), "SecurityTrails found subdomains");
    }
    subdomains
}

/// Parses SecurityTrails JSON response into fully-qualified subdomain names.
///
/// SecurityTrails returns subdomain prefixes only (e.g. "www", "api").
/// This function appends the base domain to create FQDNs.
pub(crate) fn parse_securitytrails_response(body: &str, domain: &str) -> Vec<String> {
    let response: SecurityTrailsResponse = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(_) => {
            tracing::debug!("failed to parse SecurityTrails JSON response");
            return Vec::new();
        }
    };
    response
        .subdomains
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(|prefix| format!("{prefix}.{domain}"))
        .collect()
}

#[derive(serde::Deserialize)]
struct SecurityTrailsResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

pub(crate) fn securitytrails_to_operations(
    subdomains: &[String],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    subdomains_to_operations_with_source(subdomains, "securitytrails", seq)
}

/// Converts trufflehog results into AddFinding operations.
pub(crate) fn secret_findings_to_operations(
    results: &[ExploitResult],
    seq: &mut u64,
) -> Vec<OperationLogEntry> {
    results
        .iter()
        .map(|r| {
            *seq += 1;
            let severity = r.severity_upgrade.unwrap_or(5.0);
            OperationLogEntry {
                sequence_number: *seq,
                module: ModuleIdentifier::PassiveRecon,
                operation: GraphOperation::AddFinding {
                    linked_node_ids: vec![],
                    vulnerability_class: VulnerabilityClass::SensitiveDataExposure,
                    severity,
                    confidence: aegis_protocol::finding::Confidence::new(0.85).unwrap(),
                    certificate: Vec::new(),
                },
                timestamp_unix_ms: timestamp_ms(),
            }
        })
        .collect()
}
