use crate::web_vitals_audit::*;

#[test]
fn test_no_api_detected() {
    let body = r#"
        <html>
        <body>
            <script>
                console.log('Hello World');
            </script>
        </body>
        </html>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.is_empty());
}

#[test]
fn test_api_detected_web_vitals() {
    let body = r#"
        <script src="https://unpkg.com/web-vitals@3/dist/web-vitals.iife.js"></script>
        <script>
            webVitals.onCLS(console.log);
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}

#[test]
fn test_api_detected_get_cls() {
    let body = r#"
        <script>
            import {getCLS} from 'web-vitals';
            getCLS(console.log);
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}

#[test]
fn test_api_detected_get_fid() {
    let body = r#"
        <script>
            import {getFID} from 'web-vitals';
            getFID(console.log);
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}

#[test]
fn test_api_detected_get_lcp() {
    let body = r#"
        <script>
            import {getLCP} from 'web-vitals';
            getLCP(console.log);
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}

#[test]
fn test_api_detected_get_inp() {
    let body = r#"
        <script>
            import {getINP} from 'web-vitals';
            getINP(console.log);
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}

#[test]
fn test_api_detected_get_ttfb() {
    let body = r#"
        <script>
            import {getTTFB} from 'web-vitals';
            getTTFB(console.log);
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}

#[test]
fn test_metric_exfiltration_fetch() {
    let body = r#"
        <script>
            import {getCLS} from 'web-vitals';
            getCLS((metric) => {
                fetch('https://analytics.example.com/collect', {
                    method: 'POST',
                    body: JSON.stringify(metric)
                });
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::MetricExfiltration));
}

#[test]
fn test_metric_exfiltration_send_beacon() {
    let body = r#"
        <script>
            import {getLCP} from 'web-vitals';
            getLCP((metric) => {
                navigator.sendBeacon('https://tracking.example.com/metrics', JSON.stringify(metric));
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::MetricExfiltration));
}

#[test]
fn test_metric_exfiltration_xhr() {
    let body = r#"
        <script>
            import {getFID} from 'web-vitals';
            getFID((metric) => {
                const xhr = new XMLHttpRequest();
                xhr.open('POST', 'https://thirdparty.com/analytics');
                xhr.send(JSON.stringify(metric));
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::MetricExfiltration));
}

#[test]
fn test_no_exfiltration_with_same_origin() {
    let body = r#"
        <script>
            import {getCLS} from 'web-vitals';
            getCLS((metric) => {
                fetch(location.origin + '/metrics', {
                    method: 'POST',
                    body: JSON.stringify(metric)
                });
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}

#[test]
fn test_no_exfiltration_with_same_origin_policy() {
    let body = r#"
        <script>
            import {getCLS} from 'web-vitals';
            getCLS((metric) => {
                fetch('https://api.example.com/metrics', {
                    method: 'POST',
                    mode: 'same-origin',
                    body: JSON.stringify(metric)
                });
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}

#[test]
fn test_timing_fingerprinting() {
    let body = r#"
        <script>
            import {getCLS} from 'web-vitals';
            const perfObserver = new PerformanceObserver((list) => {
                const entries = list.getEntries();
                const fingerprint = generateUniqueHash(entries);
                sendToServer(fingerprint);
            });
            perfObserver.observe({entryTypes: ['navigation', 'resource']});
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::TimingFingerprinting));
}

#[test]
fn test_timing_fingerprinting_with_performance_now() {
    let body = r#"
        <script>
            import {getLCP} from 'web-vitals';
            const timings = [];
            setInterval(() => {
                timings.push(performance.now());
                const identity = calculateFingerprint(timings);
            }, 100);
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::TimingFingerprinting));
}

#[test]
fn test_user_behavior_tracking() {
    let body = r#"
        <script>
            import {getINP} from 'web-vitals';
            document.addEventListener('click', (e) => {
                trackUserInteraction(e);
                sendAnalytics('click', e.target);
            });
            document.addEventListener('scroll', () => {
                monitor('scroll', window.scrollY);
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::UserBehaviorTracking));
}

#[test]
fn test_user_behavior_tracking_input() {
    let body = r#"
        <script>
            import {getTTFB} from 'web-vitals';
            document.querySelectorAll('input').forEach(input => {
                input.addEventListener('input', (e) => {
                    analytics.track('input_changed', e.target.name);
                });
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::UserBehaviorTracking));
}

#[test]
fn test_resource_timing_leak() {
    let body = r#"
        <script>
            import {getCLS} from 'web-vitals';
            const resources = performance.getEntriesByType('resource');
            resources.forEach((r) => {
                if (r instanceof PerformanceResourceTiming) {
                    console.log(r.transferSize, r.encodedBodySize);
                }
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::ResourceTimingLeak));
}

#[test]
fn test_resource_timing_leak_server_timing() {
    let body = r#"
        <script>
            import {getLCP} from 'web-vitals';
            performance.getEntries().forEach(entry => {
                if (entry.serverTiming) {
                    entry.serverTiming.forEach(timing => {
                        console.log(timing.name, timing.duration);
                    });
                }
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::ResourceTimingLeak));
}

#[test]
fn test_all_issues_combined() {
    let body = r#"
        <script>
            import {getCLS, getLCP, getFID} from 'web-vitals';

            // Metric exfiltration
            getCLS((metric) => {
                fetch('https://analytics.thirdparty.com/collect', {
                    method: 'POST',
                    body: JSON.stringify(metric)
                });
            });

            // Timing fingerprinting
            const perfObserver = new PerformanceObserver((list) => {
                const entries = performance.getEntries();
                const fingerprint = generateUniqueHash(entries);
            });
            perfObserver.observe({entryTypes: ['navigation']});

            // User behavior tracking
            document.addEventListener('click', (e) => {
                analytics.track('click', e.target);
            });

            // Resource timing leak
            const resources = performance.getEntriesByType('resource');
            resources.forEach((r) => {
                console.log(r.transferSize, r.encodedBodySize);
            });
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&WebVitalsIssue::ApiDetected));
    assert!(issues.contains(&WebVitalsIssue::MetricExfiltration));
    assert!(issues.contains(&WebVitalsIssue::TimingFingerprinting));
    assert!(issues.contains(&WebVitalsIssue::UserBehaviorTracking));
    assert!(issues.contains(&WebVitalsIssue::ResourceTimingLeak));
}

#[test]
fn test_display_impl() {
    assert_eq!(WebVitalsIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebVitalsIssue::MetricExfiltration.to_string(), "metric_exfiltration");
    assert_eq!(WebVitalsIssue::TimingFingerprinting.to_string(), "timing_fingerprinting");
    assert_eq!(WebVitalsIssue::UserBehaviorTracking.to_string(), "user_behavior_tracking");
    assert_eq!(WebVitalsIssue::ResourceTimingLeak.to_string(), "resource_timing_leak");
}

#[test]
fn test_severity_values() {
    assert_eq!(web_vitals_severity(&WebVitalsIssue::ApiDetected), 2.0);
    assert_eq!(web_vitals_severity(&WebVitalsIssue::MetricExfiltration), 7.0);
    assert_eq!(web_vitals_severity(&WebVitalsIssue::TimingFingerprinting), 6.5);
    assert_eq!(web_vitals_severity(&WebVitalsIssue::UserBehaviorTracking), 6.0);
    assert_eq!(web_vitals_severity(&WebVitalsIssue::ResourceTimingLeak), 5.5);
}

#[test]
fn test_to_operations() {
    let issues = vec![
        WebVitalsIssue::ApiDetected,
        WebVitalsIssue::MetricExfiltration,
        WebVitalsIssue::TimingFingerprinting,
    ];
    let mut seq = 100;
    let ops = web_vitals_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 103);
}

#[test]
fn test_case_sensitive_detection() {
    let body = r#"
        <script>
            // Wrong case should NOT trigger
            getclS(console.log);
            getClS(console.log);
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert!(issues.is_empty());
}

#[test]
fn test_partial_matches_no_false_positive() {
    let body = r#"
        <script>
            // These should NOT trigger metric exfiltration
            import {getCLS} from 'web-vitals';
            getCLS(console.log); // No network calls
        </script>
    "#;
    let issues = analyze_web_vitals(body);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0], WebVitalsIssue::ApiDetected);
}
