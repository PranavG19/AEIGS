use crate::web_animation_audit::*;

#[test]
fn empty_body_returns_nothing() {
    assert!(analyze_web_animation("").is_empty());
}

#[test]
fn no_animation_api_returns_nothing() {
    assert!(analyze_web_animation("<html><body>Hello world</body></html>").is_empty());
}

#[test]
fn detects_element_animate() {
    let body = "<script>element.animate([{transform: 'rotate(0)'}], 1000);</script>";
    let issues = analyze_web_animation(body);
    assert!(issues.contains(&WebAnimationIssue::ApiDetected));
}

#[test]
fn detects_animation_constructor() {
    let body = "<script>const anim = new Animation(effect, timeline);</script>";
    let issues = analyze_web_animation(body);
    assert!(issues.contains(&WebAnimationIssue::ApiDetected));
}

#[test]
fn detects_keyframe_effect() {
    let body = "<script>const effect = new KeyframeEffect(el, frames);</script>";
    let issues = analyze_web_animation(body);
    assert!(issues.contains(&WebAnimationIssue::ApiDetected));
}

#[test]
fn detects_get_animations() {
    let body = "<script>document.getAnimations();</script>";
    let issues = analyze_web_animation(body);
    assert!(issues.contains(&WebAnimationIssue::ApiDetected));
}

#[test]
fn detects_ui_redressing() {
    let body = "<script>
        element.animate([{transform: 'translateX(100px)'}], 1000);
        div.style.cssText = 'position: fixed; top: 0;';
    </script>";
    let issues = analyze_web_animation(body);
    assert!(issues.contains(&WebAnimationIssue::UiRedressing));
}

#[test]
fn no_ui_redressing_without_positioning() {
    let body = "<script>
        element.animate([{color: 'red'}], 1000);
        div.style.cssText = 'position: fixed;';
    </script>";
    let issues = analyze_web_animation(body);
    assert!(!issues.contains(&WebAnimationIssue::UiRedressing));
}

#[test]
fn detects_resource_exhaustion() {
    let body = "<script>
        element.animate([{transform: 'rotate(360deg)'}],
            {iterations: Infinity, duration: 100});
    </script>";
    let issues = analyze_web_animation(body);
    assert!(issues.contains(&WebAnimationIssue::ResourceExhaustion));
}

#[test]
fn no_exhaustion_with_cancel() {
    let body = "<script>
        const anim = element.animate([{transform: 'rotate(360deg)'}],
            {iterations: Infinity});
        anim.cancel();
    </script>";
    let issues = analyze_web_animation(body);
    assert!(!issues.contains(&WebAnimationIssue::ResourceExhaustion));
}

#[test]
fn no_exhaustion_with_pause() {
    let body = "<script>
        const anim = element.animate([{transform: 'rotate(360deg)'}],
            {iterations: Infinity});
        anim.pause();
    </script>";
    let issues = analyze_web_animation(body);
    assert!(!issues.contains(&WebAnimationIssue::ResourceExhaustion));
}

#[test]
fn detects_timing_side_channel() {
    let body = "<script>
        const anim = element.animate([{opacity: 0}], 500);
        anim.finished.then(() => {
            const t = performance.now();
        });
    </script>";
    let issues = analyze_web_animation(body);
    assert!(issues.contains(&WebAnimationIssue::TimingSideChannel));
}

#[test]
fn no_timing_without_perf_api() {
    let body = "<script>
        const anim = element.animate([{opacity: 0}], 500);
        anim.finished.then(() => console.log('done'));
    </script>";
    let issues = analyze_web_animation(body);
    assert!(!issues.contains(&WebAnimationIssue::TimingSideChannel));
}

#[test]
fn detects_clickjacking_via_animation() {
    let body = "<script>
        element.animate([{opacity: 0}], 1000);
        el.addEventListener('click', handler);
        el.style.pointerEvents = 'none';
    </script>";
    let issues = analyze_web_animation(body);
    assert!(issues.contains(&WebAnimationIssue::ClickjackingViaAnimation));
}

#[test]
fn no_clickjacking_without_pointer_events() {
    let body = "<script>
        element.animate([{opacity: 0}], 1000);
        el.addEventListener('click', handler);
    </script>";
    let issues = analyze_web_animation(body);
    assert!(!issues.contains(&WebAnimationIssue::ClickjackingViaAnimation));
}

#[test]
fn all_issues_detected() {
    let body = "<script>
        element.animate([{transform: 'rotate(360deg)', opacity: 0}],
            {iterations: Infinity, duration: 100});
        div.style.cssText = 'position: fixed;';
        anim.finished.then(() => { const t = performance.now(); });
        anim.onfinish = () => { Date.now(); };
        el.addEventListener('click', handler);
        el.style.pointerEvents = 'none';
        el.style.visibility = 'hidden';
    </script>";
    let issues = analyze_web_animation(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&WebAnimationIssue::ApiDetected));
    assert!(issues.contains(&WebAnimationIssue::UiRedressing));
    assert!(issues.contains(&WebAnimationIssue::ResourceExhaustion));
    assert!(issues.contains(&WebAnimationIssue::TimingSideChannel));
    assert!(issues.contains(&WebAnimationIssue::ClickjackingViaAnimation));
}

#[test]
fn severity_values_correct() {
    assert_eq!(
        web_animation_severity(&WebAnimationIssue::ClickjackingViaAnimation),
        7.0
    );
    assert_eq!(
        web_animation_severity(&WebAnimationIssue::UiRedressing),
        6.5
    );
    assert_eq!(
        web_animation_severity(&WebAnimationIssue::ResourceExhaustion),
        6.0
    );
    assert_eq!(
        web_animation_severity(&WebAnimationIssue::TimingSideChannel),
        5.5
    );
    assert_eq!(web_animation_severity(&WebAnimationIssue::ApiDetected), 2.0);
}

#[test]
fn display_impl_works() {
    assert_eq!(WebAnimationIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(WebAnimationIssue::UiRedressing.to_string(), "ui_redressing");
    assert_eq!(
        WebAnimationIssue::ResourceExhaustion.to_string(),
        "resource_exhaustion"
    );
    assert_eq!(
        WebAnimationIssue::TimingSideChannel.to_string(),
        "timing_side_channel"
    );
    assert_eq!(
        WebAnimationIssue::ClickjackingViaAnimation.to_string(),
        "clickjacking_via_animation"
    );
}

#[test]
fn operations_generated_correctly() {
    let issues = vec![
        WebAnimationIssue::ApiDetected,
        WebAnimationIssue::ClickjackingViaAnimation,
    ];
    let mut seq = 0;
    let ops = web_animation_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_increment_sequence() {
    let issues = vec![
        WebAnimationIssue::ApiDetected,
        WebAnimationIssue::UiRedressing,
        WebAnimationIssue::ResourceExhaustion,
    ];
    let mut seq = 10;
    let ops = web_animation_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}
