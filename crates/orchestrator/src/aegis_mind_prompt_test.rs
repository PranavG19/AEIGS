use super::*;

#[test]
fn default_config_uses_red_team_persona() {
    let config = MindPromptConfig::default();
    assert_eq!(config.persona, AgentPersona::RedTeamOperator);
    assert_eq!(config.methodology, Methodology::OHPEL);
    assert_eq!(config.max_context_tokens, 32000);
    assert!(config.include_memory_context);
    assert!(config.include_defense_map);
    assert!(config.include_tech_attack_patterns);
}

#[test]
fn default_mission_prompt_contains_key_sections() {
    let prompt = default_mission_prompt();
    assert!(prompt.contains("AEGIS-MIND"));
    assert!(prompt.contains("Hypothesis Generation"));
    assert!(prompt.contains("Payload Crafting Guidelines"));
    assert!(prompt.contains("Response Format"));
    assert!(prompt.contains("Behavioral Rules"));
    assert!(prompt.contains("Tech Stack Attack Patterns"));
}

#[test]
fn load_mission_prompt_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("custom_prompt.md");
    std::fs::write(&path, "# Custom Prompt\nDo custom things.").unwrap();

    let prompt = load_mission_prompt(Some(&path)).unwrap();
    assert!(prompt.contains("Custom Prompt"));
}

#[test]
fn load_mission_prompt_default_when_none() {
    let prompt = load_mission_prompt(None).unwrap();
    assert!(prompt.contains("AEGIS-MIND"));
}

#[test]
fn assemble_prompt_includes_all_sections() {
    let config = MindPromptConfig::default();
    let briefing = "# TARGET\n- url: http://127.0.0.1:3000\n";
    let memory = MemoryContext {
        historical_success_rates: vec![("SQL Injection".to_string(), 0.75)],
        known_bypasses: vec!["unicode-normalization".to_string()],
        stack_correlations: vec![("Express".to_string(), "SSTI".to_string(), 0.6)],
    };

    let assembled = assemble_prompt(&config, briefing, Some(&memory), Some("WAF: Cloudflare"));

    assert!(assembled.system_prompt.contains("Red Team Operator"));
    assert!(assembled.system_prompt.contains("OBSERVE"));
    assert!(assembled.system_prompt.contains("Knowledge Base"));
    assert!(assembled.system_prompt.contains("Output Format"));
    assert!(assembled.system_prompt.contains("Behavioral Rules"));
    assert!(assembled.user_prompt.contains("CROSS-SESSION MEMORY"));
    assert!(assembled.user_prompt.contains("SQL Injection: 75%"));
    assert!(assembled.user_prompt.contains("unicode-normalization"));
    assert!(assembled.user_prompt.contains("DEFENSE MAP"));
    assert!(assembled.user_prompt.contains("TARGET"));
    assert!(assembled.total_token_estimate > 0);

    assert!(assembled.sections_included.contains(&"PERSONA".to_string()));
    assert!(
        assembled
            .sections_included
            .contains(&"METHODOLOGY".to_string())
    );
    assert!(
        assembled
            .sections_included
            .contains(&"KNOWLEDGE".to_string())
    );
    assert!(
        assembled
            .sections_included
            .contains(&"OUTPUT_FORMAT".to_string())
    );
    assert!(
        assembled
            .sections_included
            .contains(&"MEMORY_CONTEXT".to_string())
    );
    assert!(
        assembled
            .sections_included
            .contains(&"DEFENSE_MAP".to_string())
    );
    assert!(
        assembled
            .sections_included
            .contains(&"SCAN_BRIEFING".to_string())
    );
}

#[test]
fn assemble_prompt_without_optional_sections() {
    let config = MindPromptConfig {
        include_memory_context: false,
        include_defense_map: false,
        include_tech_attack_patterns: false,
        ..MindPromptConfig::default()
    };

    let assembled = assemble_prompt(&config, "briefing", None, None);

    assert!(
        !assembled
            .system_prompt
            .contains("Tech Stack Attack Patterns")
    );
    assert!(!assembled.user_prompt.contains("CROSS-SESSION MEMORY"));
    assert!(!assembled.user_prompt.contains("DEFENSE MAP"));
    assert!(
        !assembled
            .sections_included
            .contains(&"MEMORY_CONTEXT".to_string())
    );
    assert!(
        !assembled
            .sections_included
            .contains(&"DEFENSE_MAP".to_string())
    );
}

#[test]
fn assemble_prompt_with_custom_instructions() {
    let config = MindPromptConfig {
        custom_instructions: vec![
            "Focus on JWT vulnerabilities".to_string(),
            "Ignore XSS for this scan".to_string(),
        ],
        ..MindPromptConfig::default()
    };

    let assembled = assemble_prompt(&config, "briefing", None, None);

    assert!(assembled.system_prompt.contains("Additional Instructions"));
    assert!(assembled.system_prompt.contains("Focus on JWT"));
    assert!(assembled.system_prompt.contains("Ignore XSS"));
    assert!(
        assembled
            .sections_included
            .contains(&"CUSTOM_INSTRUCTIONS".to_string())
    );
}

#[test]
fn persona_descriptions_are_nonempty() {
    for persona in &[
        AgentPersona::RedTeamOperator,
        AgentPersona::BugBountyHunter,
        AgentPersona::ComplianceAuditor,
        AgentPersona::PenetrationTester,
    ] {
        assert!(!persona.description().is_empty());
        assert!(!persona.to_string().is_empty());
    }
}

#[test]
fn persona_display_formatting() {
    assert_eq!(
        format!("{}", AgentPersona::RedTeamOperator),
        "Red Team Operator"
    );
    assert_eq!(
        format!("{}", AgentPersona::BugBountyHunter),
        "Bug Bounty Hunter"
    );
    assert_eq!(
        format!("{}", AgentPersona::ComplianceAuditor),
        "Compliance Auditor"
    );
    assert_eq!(
        format!("{}", AgentPersona::PenetrationTester),
        "Penetration Tester"
    );
}

#[test]
fn methodology_steps_are_nonempty() {
    assert!(!Methodology::OHPEL.steps().is_empty());
    assert!(!Methodology::REEP.steps().is_empty());
    assert_eq!(Methodology::OHPEL.steps().len(), 5);
    assert_eq!(Methodology::REEP.steps().len(), 4);
}

#[test]
fn build_system_prompt_standalone() {
    let config = MindPromptConfig::default();
    let prompt = build_system_prompt(&config);
    assert!(prompt.contains("AEGIS-MIND"));
    assert!(prompt.contains("Knowledge Base"));
}

#[test]
fn different_personas_produce_different_prompts() {
    let red_team = assemble_prompt(
        &MindPromptConfig {
            persona: AgentPersona::RedTeamOperator,
            ..MindPromptConfig::default()
        },
        "briefing",
        None,
        None,
    );

    let compliance = assemble_prompt(
        &MindPromptConfig {
            persona: AgentPersona::ComplianceAuditor,
            ..MindPromptConfig::default()
        },
        "briefing",
        None,
        None,
    );

    assert!(red_team.system_prompt.contains("adversarially"));
    assert!(compliance.system_prompt.contains("compliance auditor"));
    assert_ne!(red_team.system_prompt, compliance.system_prompt);
}

#[test]
fn different_methodologies_produce_different_steps() {
    let ohpel = assemble_prompt(
        &MindPromptConfig {
            methodology: Methodology::OHPEL,
            ..MindPromptConfig::default()
        },
        "briefing",
        None,
        None,
    );

    let reep = assemble_prompt(
        &MindPromptConfig {
            methodology: Methodology::REEP,
            ..MindPromptConfig::default()
        },
        "briefing",
        None,
        None,
    );

    assert!(ohpel.system_prompt.contains("OBSERVE"));
    assert!(reep.system_prompt.contains("RECON"));
}

#[test]
fn output_format_structured_json_includes_schema() {
    let config = MindPromptConfig {
        output_format: OutputFormatSpec::StructuredJson,
        ..MindPromptConfig::default()
    };
    let assembled = assemble_prompt(&config, "briefing", None, None);
    assert!(assembled.system_prompt.contains("\"hypotheses\""));
    assert!(assembled.system_prompt.contains("\"actions\""));
    assert!(assembled.system_prompt.contains("valid JSON"));
}

#[test]
fn output_format_freeform_mentions_json_block() {
    let config = MindPromptConfig {
        output_format: OutputFormatSpec::FreeformWithJson,
        ..MindPromptConfig::default()
    };
    let assembled = assemble_prompt(&config, "briefing", None, None);
    assert!(assembled.system_prompt.contains("natural language"));
}

#[test]
fn memory_context_with_empty_fields() {
    let mem = MemoryContext {
        historical_success_rates: vec![],
        known_bypasses: vec![],
        stack_correlations: vec![],
    };
    let ctx = format_memory_context(&mem);
    assert!(ctx.contains("CROSS-SESSION MEMORY"));
    // Empty sections should not crash
}

#[test]
fn assembled_prompt_serde_roundtrip() {
    let assembled = AssembledPrompt {
        system_prompt: "test system".to_string(),
        user_prompt: "test user".to_string(),
        total_token_estimate: 100,
        sections_included: vec!["A".to_string(), "B".to_string()],
    };
    let json = serde_json::to_string(&assembled).unwrap();
    let parsed: AssembledPrompt = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.total_token_estimate, 100);
    assert_eq!(parsed.sections_included.len(), 2);
}

#[test]
fn persona_serde_roundtrip() {
    let persona = AgentPersona::BugBountyHunter;
    let json = serde_json::to_string(&persona).unwrap();
    let parsed: AgentPersona = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, AgentPersona::BugBountyHunter);
}

#[test]
fn behavioral_rules_contain_key_directives() {
    let rules = build_behavioral_rules();
    assert!(rules.contains("aggressive"));
    assert!(rules.contains("creative"));
    assert!(rules.contains("specific"));
    assert!(rules.contains("adaptive"));
    assert!(rules.contains("Chain"));
    assert!(rules.contains("absence"));
}
