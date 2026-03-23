use crate::intersection_observer_audit::*;

#[test]
fn no_observer_no_issues() {
    assert!(analyze_intersection_observer("<html></html>").is_empty());
}

#[test]
fn detects_observer() {
    let body = r#"<script>new IntersectionObserver(cb).observe(el)</script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::ObserverDetected));
}

#[test]
fn detects_visibility_tracking_fetch() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            entries.forEach(e => {
                if (e.isIntersecting) fetch("/track?visible=true");
            });
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::VisibilityTracking));
}

#[test]
fn detects_visibility_tracking_beacon() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) navigator.sendBeacon("/view");
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::VisibilityTracking));
}

#[test]
fn no_tracking_without_fetch() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) lazyLoad();
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(!issues.contains(&IntersectionObserverIssue::VisibilityTracking));
}

#[test]
fn detects_multiple_thresholds() {
    let body = r#"<script>
        new IntersectionObserver(cb, {
            threshold: [0, 0.1, 0.2, 0.3, 0.4, 0.5]
        });
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::MultipleThresholds));
}

#[test]
fn no_multiple_with_few_thresholds() {
    let body = r#"<script>
        new IntersectionObserver(cb, {threshold: [0, 1]});
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(!issues.contains(&IntersectionObserverIssue::MultipleThresholds));
}

#[test]
fn detects_cross_origin_target() {
    let body = r#"<script>
        const iframe = document.querySelector("iframe");
        new IntersectionObserver(cb).observe(iframe);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::CrossOriginTarget));
}

#[test]
fn detects_scroll_jacking() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            el.scrollIntoView({behavior: "smooth"});
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::ScrollJacking));
}

#[test]
fn detects_ad_visibility() {
    let body = r#"<script>
        const ad = document.querySelector(".ad-banner");
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) trackAdView();
        }).observe(ad);
    </script>"#;
    let issues = analyze_intersection_observer(body);
    assert!(issues.contains(&IntersectionObserverIssue::AdVisibilityCheck));
}

#[test]
fn severity_tracking_highest() {
    assert_eq!(
        intersection_observer_severity(&IntersectionObserverIssue::VisibilityTracking),
        5.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        intersection_observer_severity(&IntersectionObserverIssue::ObserverDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        IntersectionObserverIssue::ObserverDetected,
        IntersectionObserverIssue::VisibilityTracking,
    ];
    let mut seq = 0;
    let ops = intersection_observer_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        IntersectionObserverIssue::ObserverDetected.to_string(),
        "observer_detected"
    );
    assert_eq!(
        IntersectionObserverIssue::VisibilityTracking.to_string(),
        "visibility_tracking"
    );
    assert_eq!(
        IntersectionObserverIssue::MultipleThresholds.to_string(),
        "multiple_thresholds"
    );
    assert_eq!(
        IntersectionObserverIssue::CrossOriginTarget.to_string(),
        "cross_origin_target"
    );
    assert_eq!(
        IntersectionObserverIssue::ScrollJacking.to_string(),
        "scroll_jacking"
    );
    assert_eq!(
        IntersectionObserverIssue::AdVisibilityCheck.to_string(),
        "ad_visibility_check"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_intersection_observer("").is_empty());
}

// Security issue tests

#[test]
fn security_no_observer_no_issues() {
    assert!(analyze_intersection_observer_security("<html></html>").is_empty());
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_intersection_observer_security("").is_empty());
}

#[test]
fn security_detects_visibility_tracking_analytics() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                analytics.track('view', {element: 'hero'});
            }
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::VisibilityTracking));
}

#[test]
fn security_detects_visibility_tracking_fetch() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                fetch('/track/view?element=banner');
            }
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::VisibilityTracking));
}

#[test]
fn security_detects_visibility_tracking_beacon() {
    let body = r#"<script>
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    navigator.sendBeacon('/api/view', JSON.stringify({id: entry.target.id}));
                }
            });
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::VisibilityTracking));
}

#[test]
fn security_detects_adblock_detection_lowercase() {
    let body = r#"<script>
        const adDiv = document.querySelector('.ad');
        new IntersectionObserver((entries) => {
            if (!entries[0].isIntersecting) {
                console.log('adblock detected');
            }
        }).observe(adDiv);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::AdBlockDetection));
}

#[test]
fn security_detects_adblock_detection_uppercase() {
    let body = r#"<script>
        // Check for ADBLOCKER
        new IntersectionObserver(checkAdBlock).observe(ad);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::AdBlockDetection));
}

#[test]
fn security_detects_adblock_detection_hyphenated() {
    let body = r#"<script>
        const isBlocked = new IntersectionObserver((entries) => {
            // ad-block detection logic
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::AdBlockDetection));
}

#[test]
fn security_detects_scroll_jacking_scrollto() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                window.scrollTo(0, 500);
            }
        }).observe(section);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ScrollJacking));
}

#[test]
fn security_detects_scroll_jacking_scrollintoview() {
    let body = r#"<script>
        const observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                nextSection.scrollIntoView({behavior: 'smooth'});
            }
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ScrollJacking));
}

#[test]
fn security_detects_scroll_jacking_scroll_method() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                container.scroll(0, 300);
            }
        }).observe(trigger);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ScrollJacking));
}

#[test]
fn security_detects_lazyload_fingerprint() {
    let body = r#"<script>
        const lazyObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const start = performance.now();
                    img.src = img.dataset.lazy;
                    const end = performance.now();
                    console.log('load time:', end - start);
                }
            });
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::LazyLoadFingerprint));
}

#[test]
fn security_detects_cross_origin_visibility_iframe() {
    let body = r#"<script>
        const iframe = document.querySelector('iframe');
        new IntersectionObserver((entries) => {
            console.log('iframe visible:', entries[0].isIntersecting);
        }).observe(iframe);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::CrossOriginVisibility));
}

#[test]
fn security_detects_cross_origin_visibility_crossorigin() {
    let body = r#"<script>
        const img = document.createElement('img');
        img.crossOrigin = 'anonymous';
        new IntersectionObserver(cb).observe(img);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::CrossOriginVisibility));
}

#[test]
fn security_detects_viewport_size_leakage_innerwidth() {
    let body = r#"<script>
        const observer = new IntersectionObserver(cb, {
            rootMargin: `${window.innerWidth}px`
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ViewportSizeLeakage));
}

#[test]
fn security_detects_viewport_size_leakage_innerheight() {
    let body = r#"<script>
        new IntersectionObserver(cb, {
            rootMargin: window.innerHeight + 'px'
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ViewportSizeLeakage));
}

#[test]
fn security_detects_viewport_size_leakage_viewport() {
    let body = r#"<script>
        const viewport = document.querySelector('meta[name="viewport"]');
        new IntersectionObserver(cb, {rootMargin: '100px'});
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ViewportSizeLeakage));
}

#[test]
fn security_detects_element_timing_attack_performance_now() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                const t = performance.now();
                console.log('visible at:', t);
            }
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ElementTimingAttack));
}

#[test]
fn security_detects_element_timing_attack_date_now() {
    let body = r#"<script>
        const observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                const timestamp = Date.now();
            }
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ElementTimingAttack));
}

#[test]
fn security_detects_intersection_with_storage_localstorage() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                localStorage.setItem('viewed', 'true');
            }
        }).observe(banner);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::IntersectionWithStorage));
}

#[test]
fn security_detects_intersection_with_storage_sessionstorage() {
    let body = r#"<script>
        const observer = new IntersectionObserver((entries) => {
            sessionStorage.setItem('view_count', count++);
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::IntersectionWithStorage));
}

#[test]
fn security_detects_intersection_with_storage_indexeddb() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            const db = indexedDB.open('views');
            db.onsuccess = () => { /* store */ };
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::IntersectionWithStorage));
}

#[test]
fn security_detects_intersection_with_storage_cookie() {
    let body = r#"<script>
        const observer = new IntersectionObserver((entries) => {
            document.cookie = 'viewed=1; max-age=3600';
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::IntersectionWithStorage));
}

#[test]
fn security_detects_infinite_scroll_tracking_keyword() {
    let body = r#"<script>
        // Infinite scroll implementation
        new IntersectionObserver((entries) => {
            loadMore();
        }).observe(sentinel);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::InfiniteScrollTracking));
}

#[test]
fn security_detects_infinite_scroll_tracking_pattern() {
    let body = r#"<script>
        new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                container.append(createNewItems());
            }
        }).observe(loadTrigger);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::InfiniteScrollTracking));
}

#[test]
fn security_detects_intersection_in_worker_worker_constructor() {
    let body = r#"<script>
        const worker = new Worker('observer-worker.js');
        new IntersectionObserver((entries) => {
            worker.postMessage({visible: entries[0].isIntersecting});
        }).observe(el);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::IntersectionInWorker));
}

#[test]
fn security_detects_intersection_in_worker_postmessage() {
    let body = r#"<script>
        const observer = new IntersectionObserver((entries) => {
            postMessage({type: 'intersection', data: entries});
        });
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::IntersectionInWorker));
}

#[test]
fn security_severity_cross_origin_highest() {
    assert_eq!(
        intersection_observer_security_severity(
            &IntersectionObserverSecurityIssue::CrossOriginVisibility
        ),
        7.0
    );
}

#[test]
fn security_severity_element_timing_second() {
    assert_eq!(
        intersection_observer_security_severity(
            &IntersectionObserverSecurityIssue::ElementTimingAttack
        ),
        6.5
    );
}

#[test]
fn security_severity_visibility_tracking() {
    assert_eq!(
        intersection_observer_security_severity(
            &IntersectionObserverSecurityIssue::VisibilityTracking
        ),
        6.0
    );
}

#[test]
fn security_severity_worker_lowest() {
    assert_eq!(
        intersection_observer_security_severity(
            &IntersectionObserverSecurityIssue::IntersectionInWorker
        ),
        3.8
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        IntersectionObserverSecurityIssue::VisibilityTracking,
        IntersectionObserverSecurityIssue::CrossOriginVisibility,
        IntersectionObserverSecurityIssue::AdBlockDetection,
    ];
    let mut seq = 100;
    let ops = intersection_observer_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 103);
}

#[test]
fn security_to_operations_empty_input() {
    let issues = vec![];
    let mut seq = 0;
    let ops = intersection_observer_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
fn security_display_visibility_tracking() {
    assert_eq!(
        IntersectionObserverSecurityIssue::VisibilityTracking.to_string(),
        "visibility_tracking"
    );
}

#[test]
fn security_display_adblock_detection() {
    assert_eq!(
        IntersectionObserverSecurityIssue::AdBlockDetection.to_string(),
        "adblock_detection"
    );
}

#[test]
fn security_display_scroll_jacking() {
    assert_eq!(
        IntersectionObserverSecurityIssue::ScrollJacking.to_string(),
        "scroll_jacking"
    );
}

#[test]
fn security_display_lazyload_fingerprint() {
    assert_eq!(
        IntersectionObserverSecurityIssue::LazyLoadFingerprint.to_string(),
        "lazyload_fingerprint"
    );
}

#[test]
fn security_display_cross_origin_visibility() {
    assert_eq!(
        IntersectionObserverSecurityIssue::CrossOriginVisibility.to_string(),
        "cross_origin_visibility"
    );
}

#[test]
fn security_display_viewport_size_leakage() {
    assert_eq!(
        IntersectionObserverSecurityIssue::ViewportSizeLeakage.to_string(),
        "viewport_size_leakage"
    );
}

#[test]
fn security_display_element_timing_attack() {
    assert_eq!(
        IntersectionObserverSecurityIssue::ElementTimingAttack.to_string(),
        "element_timing_attack"
    );
}

#[test]
fn security_display_intersection_with_storage() {
    assert_eq!(
        IntersectionObserverSecurityIssue::IntersectionWithStorage.to_string(),
        "intersection_with_storage"
    );
}

#[test]
fn security_display_infinite_scroll_tracking() {
    assert_eq!(
        IntersectionObserverSecurityIssue::InfiniteScrollTracking.to_string(),
        "infinite_scroll_tracking"
    );
}

#[test]
fn security_display_intersection_in_worker() {
    assert_eq!(
        IntersectionObserverSecurityIssue::IntersectionInWorker.to_string(),
        "intersection_in_worker"
    );
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"<script>
        const observer = new IntersectionObserver((entries) => {
            if (entries[0].isIntersecting) {
                const time = performance.now();
                localStorage.setItem('view_time', time);
                fetch('/track/view');
                window.scrollTo(0, 0);
            }
        });
        const iframe = document.querySelector('iframe');
        observer.observe(iframe);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.len() >= 4);
    assert!(issues.contains(&IntersectionObserverSecurityIssue::VisibilityTracking));
    assert!(issues.contains(&IntersectionObserverSecurityIssue::ElementTimingAttack));
    assert!(issues.contains(&IntersectionObserverSecurityIssue::IntersectionWithStorage));
    assert!(issues.contains(&IntersectionObserverSecurityIssue::CrossOriginVisibility));
}

#[test]
fn security_no_false_positive_without_observer() {
    let body = r#"<script>
        fetch('/track');
        localStorage.setItem('data', 'value');
        window.scrollTo(0, 100);
    </script>"#;
    let issues = analyze_intersection_observer_security(body);
    assert!(issues.is_empty());
}
