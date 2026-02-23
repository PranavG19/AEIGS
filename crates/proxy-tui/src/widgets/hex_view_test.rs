use super::*;

#[test]
fn new_starts_raw_mode() {
    let view = HexView::new(b"hello".to_vec());
    assert_eq!(view.mode, BodyViewMode::Raw);
}

#[test]
fn toggle_raw_to_hex() {
    let mut view = HexView::new(b"hello".to_vec());
    view.toggle_mode();
    assert_eq!(view.mode, BodyViewMode::Hex);
}

#[test]
fn toggle_hex_to_pretty() {
    let mut view = HexView::new(b"hello".to_vec());
    view.toggle_mode();
    view.toggle_mode();
    assert_eq!(view.mode, BodyViewMode::Pretty);
}

#[test]
fn toggle_pretty_to_raw() {
    let mut view = HexView::new(b"hello".to_vec());
    view.toggle_mode();
    view.toggle_mode();
    view.toggle_mode();
    assert_eq!(view.mode, BodyViewMode::Raw);
}

#[test]
fn raw_mode_lines_utf8() {
    let view = HexView::new(b"line1\nline2\nline3".to_vec());
    let lines = view.lines();
    assert_eq!(lines, vec!["line1", "line2", "line3"]);
}

#[test]
fn raw_mode_invalid_utf8() {
    let body = vec![0xFF, 0xFE, 0x41, 0x42];
    let view = HexView::new(body);
    let lines = view.lines();
    assert!(!lines.is_empty());
}

#[test]
fn hex_mode_format() {
    let mut view = HexView::new(b"Hello World\n".to_vec());
    view.toggle_mode();
    let lines = view.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(
        lines[0],
        "00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 0a              |Hello World.|"
    );
}

#[test]
fn hex_mode_short_body() {
    let mut view = HexView::new(b"Hi".to_vec());
    view.toggle_mode();
    let lines = view.lines();
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert!(line.starts_with("00000000"));
    assert!(line.contains("|Hi|"));
}

#[test]
fn hex_mode_empty_body() {
    let mut view = HexView::new(vec![]);
    view.toggle_mode();
    assert_eq!(view.lines(), Vec::<String>::new());
}

#[test]
fn pretty_mode_valid_json() {
    let json = b"{\"key\":\"value\"}".to_vec();
    let mut view = HexView::new(json);
    view.toggle_mode();
    view.toggle_mode();
    let lines = view.lines();
    let rejoined = lines.join("\n");
    assert!(rejoined.contains("\"key\""));
    assert!(rejoined.contains("\"value\""));
    assert!(rejoined.contains('\n'));
}

#[test]
fn pretty_mode_invalid_json_falls_back() {
    let body = b"not json at all".to_vec();
    let mut view = HexView::new(body);
    view.toggle_mode();
    view.toggle_mode();
    let lines = view.lines();
    assert_eq!(lines, vec!["not json at all"]);
}

#[test]
fn scroll_down_advances_offset() {
    let body = b"a\nb\nc\nd\ne".to_vec();
    let mut view = HexView::new(body);
    view.scroll_down(2);
    assert_eq!(view.scroll_offset, 2);
}

#[test]
fn scroll_up_clamps_at_zero() {
    let body = b"a\nb\nc".to_vec();
    let mut view = HexView::new(body);
    view.scroll_up(5);
    assert_eq!(view.scroll_offset, 0);
}

#[test]
fn visible_lines_slices_correctly() {
    let body = b"a\nb\nc\nd\ne\nf".to_vec();
    let mut view = HexView::new(body);
    view.scroll_down(1);
    let visible = view.visible_lines(3);
    assert_eq!(visible, vec!["b", "c", "d"]);
}
