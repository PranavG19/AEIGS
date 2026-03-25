use std::collections::HashMap;

/// Interest or hobby extracted from social media.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedInterest {
    pub topic: String,
    pub category: InterestCategory,
    pub evidence: Vec<InterestEvidence>,
    pub strength: f64,
}

/// Category of interest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterestCategory {
    Technology,
    Sports,
    Music,
    Gaming,
    Travel,
    Food,
    Finance,
    Politics,
    Fitness,
    Art,
    Science,
    Education,
    Pets,
    Family,
    Career,
    Other,
}

impl std::fmt::Display for InterestCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Technology => write!(f, "Technology"),
            Self::Sports => write!(f, "Sports"),
            Self::Music => write!(f, "Music"),
            Self::Gaming => write!(f, "Gaming"),
            Self::Travel => write!(f, "Travel"),
            Self::Food => write!(f, "Food"),
            Self::Finance => write!(f, "Finance"),
            Self::Politics => write!(f, "Politics"),
            Self::Fitness => write!(f, "Fitness"),
            Self::Art => write!(f, "Art"),
            Self::Science => write!(f, "Science"),
            Self::Education => write!(f, "Education"),
            Self::Pets => write!(f, "Pets"),
            Self::Family => write!(f, "Family"),
            Self::Career => write!(f, "Career"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Evidence for an interest detection.
#[derive(Debug, Clone, PartialEq)]
pub struct InterestEvidence {
    pub source: String,
    pub detail: String,
    pub timestamp: Option<String>,
}

/// Communication style analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct CommunicationStyle {
    pub formality: FormalityLevel,
    pub technical_depth: TechnicalLevel,
    pub avg_message_length: f64,
    pub emoji_usage: f64,
    pub response_time_pattern: Option<String>,
    pub preferred_channels: Vec<String>,
    pub vocabulary_complexity: f64,
}

/// How formal the target communicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormalityLevel {
    VeryFormal,
    Formal,
    Neutral,
    Casual,
    VeryCasual,
}

impl std::fmt::Display for FormalityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VeryFormal => write!(f, "Very Formal"),
            Self::Formal => write!(f, "Formal"),
            Self::Neutral => write!(f, "Neutral"),
            Self::Casual => write!(f, "Casual"),
            Self::VeryCasual => write!(f, "Very Casual"),
        }
    }
}

/// How technical the target's communication is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechnicalLevel {
    Expert,
    Proficient,
    Moderate,
    Basic,
    NonTechnical,
}

impl std::fmt::Display for TechnicalLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expert => write!(f, "Expert"),
            Self::Proficient => write!(f, "Proficient"),
            Self::Moderate => write!(f, "Moderate"),
            Self::Basic => write!(f, "Basic"),
            Self::NonTechnical => write!(f, "Non-Technical"),
        }
    }
}

/// Authority figure in the target's org structure.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorityFigure {
    pub name: String,
    pub title: Option<String>,
    pub relationship: AuthorityRelationship,
    pub trust_level: f64,
    pub source: String,
}

/// Relationship to an authority figure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityRelationship {
    DirectManager,
    SkipLevel,
    Peer,
    Mentor,
    ExternalVendor,
    Client,
    Unknown,
}

impl std::fmt::Display for AuthorityRelationship {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectManager => write!(f, "Direct Manager"),
            Self::SkipLevel => write!(f, "Skip Level"),
            Self::Peer => write!(f, "Peer"),
            Self::Mentor => write!(f, "Mentor"),
            Self::ExternalVendor => write!(f, "External Vendor"),
            Self::Client => write!(f, "Client"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Emotional trigger that could be exploited.
#[derive(Debug, Clone, PartialEq)]
pub struct EmotionalTrigger {
    pub trigger_type: TriggerType,
    pub description: String,
    pub recency: Option<String>,
    pub exploitability: f64,
}

/// Type of emotional trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TriggerType {
    JobChange,
    Promotion,
    Layoff,
    RelationshipChange,
    Relocation,
    Achievement,
    Loss,
    HealthEvent,
    FinancialChange,
    NewChild,
    Graduation,
}

impl std::fmt::Display for TriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JobChange => write!(f, "Job Change"),
            Self::Promotion => write!(f, "Promotion"),
            Self::Layoff => write!(f, "Layoff"),
            Self::RelationshipChange => write!(f, "Relationship Change"),
            Self::Relocation => write!(f, "Relocation"),
            Self::Achievement => write!(f, "Achievement"),
            Self::Loss => write!(f, "Loss"),
            Self::HealthEvent => write!(f, "Health Event"),
            Self::FinancialChange => write!(f, "Financial Change"),
            Self::NewChild => write!(f, "New Child"),
            Self::Graduation => write!(f, "Graduation"),
        }
    }
}

/// Generated phishing email template.
#[derive(Debug, Clone, PartialEq)]
pub struct PhishingTemplate {
    pub pretext: String,
    pub subject: String,
    pub body: String,
    pub sender_persona: String,
    pub urgency: UrgencyLevel,
    pub personalization_hooks: Vec<String>,
    pub call_to_action: String,
    pub effectiveness_estimate: f64,
}

/// Urgency level for a phishing template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UrgencyLevel {
    Critical,
    High,
    Medium,
    Low,
    Subtle,
}

impl std::fmt::Display for UrgencyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "Critical"),
            Self::High => write!(f, "High"),
            Self::Medium => write!(f, "Medium"),
            Self::Low => write!(f, "Low"),
            Self::Subtle => write!(f, "Subtle"),
        }
    }
}

/// Pretexting scenario for in-person or phone social engineering.
#[derive(Debug, Clone, PartialEq)]
pub struct PretextScenario {
    pub scenario_name: String,
    pub persona: String,
    pub backstory: String,
    pub objectives: Vec<String>,
    pub conversation_starters: Vec<String>,
    pub trust_building_points: Vec<String>,
    pub information_to_extract: Vec<String>,
    pub risk_level: f64,
}

/// Vishing (voice phishing) script.
#[derive(Debug, Clone, PartialEq)]
pub struct VishingScript {
    pub scenario_name: String,
    pub caller_persona: String,
    pub opening_line: String,
    pub script_branches: Vec<ScriptBranch>,
    pub objection_handlers: Vec<ObjectionHandler>,
    pub closing_technique: String,
    pub target_information: Vec<String>,
}

/// A branch in a vishing conversation tree.
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptBranch {
    pub condition: String,
    pub response: String,
    pub follow_up: String,
}

/// Handler for common objections during vishing.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectionHandler {
    pub objection: String,
    pub response: String,
    pub escalation: Option<String>,
}

/// Full social engineering profile.
#[derive(Debug, Clone)]
pub struct SocialEngineeringProfile {
    pub target_name: String,
    pub interests: Vec<ExtractedInterest>,
    pub communication_style: CommunicationStyle,
    pub authority_figures: Vec<AuthorityFigure>,
    pub emotional_triggers: Vec<EmotionalTrigger>,
    pub phishing_templates: Vec<PhishingTemplate>,
    pub pretext_scenarios: Vec<PretextScenario>,
    pub vishing_scripts: Vec<VishingScript>,
    pub overall_susceptibility: f64,
}

/// Extract interests from social media post text.
pub fn extract_interests(posts: &[&str]) -> Vec<ExtractedInterest> {
    let topic_keywords: Vec<(&str, InterestCategory, &[&str])> = vec![
        (
            "technology",
            InterestCategory::Technology,
            &[
                "coding",
                "programming",
                "software",
                "tech",
                "ai",
                "machine learning",
                "startup",
                "developer",
                "hack",
                "linux",
                "cloud",
                "data",
                "api",
            ],
        ),
        (
            "sports",
            InterestCategory::Sports,
            &[
                "football",
                "basketball",
                "soccer",
                "baseball",
                "tennis",
                "golf",
                "nfl",
                "nba",
                "mlb",
                "gym",
                "running",
                "marathon",
                "crossfit",
            ],
        ),
        (
            "music",
            InterestCategory::Music,
            &[
                "concert", "album", "spotify", "playlist", "guitar", "band", "music", "song",
                "vinyl", "festival",
            ],
        ),
        (
            "gaming",
            InterestCategory::Gaming,
            &[
                "gaming",
                "playstation",
                "xbox",
                "nintendo",
                "steam",
                "twitch",
                "esports",
                "rpg",
                "fps",
                "mmorpg",
            ],
        ),
        (
            "travel",
            InterestCategory::Travel,
            &[
                "travel",
                "flight",
                "hotel",
                "vacation",
                "backpacking",
                "airport",
                "passport",
                "wanderlust",
                "roadtrip",
            ],
        ),
        (
            "food",
            InterestCategory::Food,
            &[
                "recipe",
                "cooking",
                "restaurant",
                "foodie",
                "brunch",
                "baking",
                "vegan",
                "chef",
                "kitchen",
            ],
        ),
        (
            "finance",
            InterestCategory::Finance,
            &[
                "investing",
                "stocks",
                "crypto",
                "bitcoin",
                "trading",
                "401k",
                "retirement",
                "portfolio",
                "dividend",
            ],
        ),
        (
            "fitness",
            InterestCategory::Fitness,
            &[
                "workout", "fitness", "yoga", "peloton", "hiit", "lifting", "protein", "squat",
                "bench",
            ],
        ),
        (
            "pets",
            InterestCategory::Pets,
            &[
                "dog", "cat", "puppy", "kitten", "pet", "rescue", "adoption", "vet", "walk",
            ],
        ),
    ];

    let mut topic_scores: HashMap<&str, (InterestCategory, Vec<InterestEvidence>, usize)> =
        HashMap::new();

    for post in posts {
        let lower = post.to_lowercase();
        for &(topic, category, keywords) in &topic_keywords {
            let matches: Vec<&&str> = keywords.iter().filter(|kw| lower.contains(**kw)).collect();
            if !matches.is_empty() {
                let entry = topic_scores
                    .entry(topic)
                    .or_insert_with(|| (category, Vec::new(), 0));
                entry.1.push(InterestEvidence {
                    source: "social_media".to_string(),
                    detail: format!(
                        "Matched keywords: {}",
                        matches.iter().map(|m| **m).collect::<Vec<_>>().join(", ")
                    ),
                    timestamp: None,
                });
                entry.2 += matches.len();
            }
        }
    }

    let max_score = topic_scores.values().map(|v| v.2).max().unwrap_or(1);

    let mut interests: Vec<ExtractedInterest> = topic_scores
        .into_iter()
        .map(|(topic, (category, evidence, score))| ExtractedInterest {
            topic: topic.to_string(),
            category,
            evidence,
            strength: (score as f64 / max_score as f64).min(1.0),
        })
        .collect();

    interests.sort_by(|a, b| b.strength.partial_cmp(&a.strength).unwrap());
    interests
}

/// Analyze communication style from message samples.
pub fn analyze_communication_style(messages: &[&str]) -> CommunicationStyle {
    if messages.is_empty() {
        return CommunicationStyle {
            formality: FormalityLevel::Neutral,
            technical_depth: TechnicalLevel::Moderate,
            avg_message_length: 0.0,
            emoji_usage: 0.0,
            response_time_pattern: None,
            preferred_channels: Vec::new(),
            vocabulary_complexity: 0.5,
        };
    }

    let total = messages.len() as f64;
    let avg_len = messages.iter().map(|m| m.len()).sum::<usize>() as f64 / total;

    let formal_markers = [
        "sincerely",
        "regards",
        "dear",
        "kindly",
        "pursuant",
        "herewith",
        "enclosed",
    ];
    let casual_markers = [
        "hey", "lol", "haha", "gonna", "wanna", "btw", "tbh", "ngl", "omg", "bruh",
    ];
    let tech_markers = [
        "api",
        "deploy",
        "kubernetes",
        "docker",
        "terraform",
        "ci/cd",
        "microservice",
        "vpc",
        "ssl",
        "oauth",
        "jwt",
        "graphql",
        "rest",
        "sdk",
    ];

    let formal_count: usize = messages
        .iter()
        .map(|m| {
            let lower = m.to_lowercase();
            formal_markers
                .iter()
                .filter(|mk| lower.contains(**mk))
                .count()
        })
        .sum();

    let casual_count: usize = messages
        .iter()
        .map(|m| {
            let lower = m.to_lowercase();
            casual_markers
                .iter()
                .filter(|mk| lower.contains(**mk))
                .count()
        })
        .sum();

    let tech_count: usize = messages
        .iter()
        .map(|m| {
            let lower = m.to_lowercase();
            tech_markers
                .iter()
                .filter(|mk| lower.contains(**mk))
                .count()
        })
        .sum();

    let emoji_msgs = messages
        .iter()
        .filter(|m| {
            m.contains('😀')
                || m.contains('👍')
                || m.contains('🙂')
                || m.contains('❤')
                || m.contains(":)")
                || m.contains(":D")
                || m.contains(";)")
        })
        .count();

    let formality = if formal_count > casual_count * 2 {
        FormalityLevel::VeryFormal
    } else if formal_count > casual_count {
        FormalityLevel::Formal
    } else if casual_count > formal_count * 2 {
        FormalityLevel::VeryCasual
    } else if casual_count > formal_count {
        FormalityLevel::Casual
    } else {
        FormalityLevel::Neutral
    };

    let tech_per_msg = tech_count as f64 / total;
    let technical_depth = if tech_per_msg > 3.0 {
        TechnicalLevel::Expert
    } else if tech_per_msg > 1.5 {
        TechnicalLevel::Proficient
    } else if tech_per_msg > 0.5 {
        TechnicalLevel::Moderate
    } else if tech_per_msg > 0.1 {
        TechnicalLevel::Basic
    } else {
        TechnicalLevel::NonTechnical
    };

    let unique_words: std::collections::HashSet<String> = messages
        .iter()
        .flat_map(|m| m.split_whitespace().map(|w| w.to_lowercase()))
        .collect();
    let total_words: usize = messages.iter().map(|m| m.split_whitespace().count()).sum();
    let vocabulary_complexity = if total_words > 0 {
        (unique_words.len() as f64 / total_words as f64).min(1.0)
    } else {
        0.0
    };

    CommunicationStyle {
        formality,
        technical_depth,
        avg_message_length: avg_len,
        emoji_usage: emoji_msgs as f64 / total,
        response_time_pattern: None,
        preferred_channels: Vec::new(),
        vocabulary_complexity,
    }
}

/// Detect emotional triggers from life events in posts.
pub fn detect_emotional_triggers(posts: &[(&str, Option<&str>)]) -> Vec<EmotionalTrigger> {
    let trigger_patterns: Vec<(TriggerType, &[&str], f64)> = vec![
        (
            TriggerType::JobChange,
            &[
                "new job",
                "started at",
                "joining",
                "first day at",
                "excited to announce",
                "new role",
            ],
            0.70,
        ),
        (
            TriggerType::Promotion,
            &[
                "promoted",
                "new title",
                "senior",
                "lead",
                "director",
                "vp",
                "head of",
            ],
            0.65,
        ),
        (
            TriggerType::Layoff,
            &[
                "laid off",
                "let go",
                "looking for opportunities",
                "open to work",
                "seeking new",
                "unfortunately",
            ],
            0.85,
        ),
        (
            TriggerType::Relocation,
            &[
                "moved to",
                "relocating",
                "new city",
                "new apartment",
                "new house",
                "settling in",
            ],
            0.60,
        ),
        (
            TriggerType::Achievement,
            &[
                "graduated",
                "certified",
                "published",
                "launched",
                "shipped",
                "won",
                "award",
            ],
            0.55,
        ),
        (
            TriggerType::NewChild,
            &[
                "baby",
                "newborn",
                "parent",
                "dad life",
                "mom life",
                "expecting",
            ],
            0.50,
        ),
        (
            TriggerType::Graduation,
            &["graduated", "degree", "diploma", "commencement", "class of"],
            0.55,
        ),
        (
            TriggerType::FinancialChange,
            &[
                "bought a house",
                "mortgage",
                "investment",
                "fundraise",
                "series a",
                "ipo",
            ],
            0.60,
        ),
    ];

    let mut triggers = Vec::new();

    for &(ref post, date) in posts {
        let lower = post.to_lowercase();
        for &(ref trigger_type, keywords, exploitability) in &trigger_patterns {
            if keywords.iter().any(|kw| lower.contains(kw)) {
                triggers.push(EmotionalTrigger {
                    trigger_type: *trigger_type,
                    description: if post.len() > 100 {
                        format!("{}...", &post[..100])
                    } else {
                        post.to_string()
                    },
                    recency: date.map(String::from),
                    exploitability,
                });
                break;
            }
        }
    }

    triggers
}

/// Generate personalized phishing templates.
pub fn generate_phishing_templates(
    target_name: &str,
    interests: &[ExtractedInterest],
    triggers: &[EmotionalTrigger],
    role: Option<&str>,
    company: Option<&str>,
) -> Vec<PhishingTemplate> {
    let mut templates = Vec::new();

    if let Some(company) = company {
        templates.push(PhishingTemplate {
            pretext: "IT Department Password Reset".to_string(),
            subject: format!("[{company}] Mandatory Security Update - Action Required"),
            body: format!(
                "Hi {target_name},\n\nOur security team has detected unusual activity on your account. \
                 As part of our ongoing security measures, we need you to verify your credentials \
                 within the next 24 hours.\n\nPlease click the link below to complete the verification:\n\n\
                 [LINK]\n\nThank you for helping us keep {company} secure.\n\nBest regards,\n{company} IT Security"
            ),
            sender_persona: format!("{company} IT Security"),
            urgency: UrgencyLevel::High,
            personalization_hooks: vec![
                format!("Uses {company} branding"),
                "References security incident".to_string(),
            ],
            call_to_action: "Click verification link".to_string(),
            effectiveness_estimate: 0.65,
        });
    }

    for trigger in triggers {
        if trigger.trigger_type == TriggerType::JobChange
            || trigger.trigger_type == TriggerType::Layoff
        {
            templates.push(PhishingTemplate {
                pretext: "Recruiter Outreach".to_string(),
                subject: format!("{target_name}, I came across your profile"),
                body: format!(
                    "Hi {target_name},\n\nI noticed your recent career update and wanted to reach out. \
                     We have several exciting opportunities that align with your experience.\n\n\
                     Could you review the attached job descriptions and let me know if any interest you?\n\n\
                     Looking forward to connecting.\n\nBest,\nSarah Mitchell\nTalent Acquisition"
                ),
                sender_persona: "Recruiter".to_string(),
                urgency: UrgencyLevel::Low,
                personalization_hooks: vec![
                    "References career transition".to_string(),
                    format!("Trigger: {}", trigger.trigger_type),
                ],
                call_to_action: "Open attached document".to_string(),
                effectiveness_estimate: 0.75,
            });
        }
    }

    for interest in interests.iter().take(2) {
        templates.push(PhishingTemplate {
            pretext: format!("{} Community", interest.topic),
            subject: format!("Exclusive {} resource for you", interest.topic),
            body: format!(
                "Hi {target_name},\n\nAs a fellow {} enthusiast, I thought you'd find this resource valuable. \
                 Our community just published a comprehensive guide that's been getting great feedback.\n\n\
                 Download it here: [LINK]\n\nEnjoy!\n\nThe {} Community Team",
                interest.topic, interest.topic
            ),
            sender_persona: format!("{} Community", interest.topic),
            urgency: UrgencyLevel::Subtle,
            personalization_hooks: vec![
                format!("Targets {} interest", interest.topic),
                format!("Interest strength: {:.0}%", interest.strength * 100.0),
            ],
            call_to_action: "Download resource".to_string(),
            effectiveness_estimate: 0.45 + (interest.strength * 0.25),
        });
    }

    if let Some(role) = role {
        let role_lower = role.to_lowercase();
        if role_lower.contains("engineer") || role_lower.contains("developer") {
            templates.push(PhishingTemplate {
                pretext: "Open Source Contribution Request".to_string(),
                subject: format!("Issue with your recent commit, {target_name}"),
                body: format!(
                    "Hi {target_name},\n\nI noticed a potential security issue in the repository. \
                     Could you take a look at this pull request?\n\n[LINK]\n\n\
                     The CI pipeline is failing and it seems related to your recent changes.\n\nThanks!"
                ),
                sender_persona: "Fellow developer".to_string(),
                urgency: UrgencyLevel::Medium,
                personalization_hooks: vec![
                    "Targets developer workflow".to_string(),
                    "Creates urgency via CI failure".to_string(),
                ],
                call_to_action: "Review pull request".to_string(),
                effectiveness_estimate: 0.70,
            });
        }
    }

    templates
}

/// Generate pretexting scenarios based on target profile.
pub fn generate_pretext_scenarios(
    target_name: &str,
    role: Option<&str>,
    company: Option<&str>,
    interests: &[ExtractedInterest],
) -> Vec<PretextScenario> {
    let mut scenarios = Vec::new();

    if let Some(company) = company {
        scenarios.push(PretextScenario {
            scenario_name: "New Vendor Onboarding".to_string(),
            persona: format!("Account manager from a vendor that {company} uses"),
            backstory: format!(
                "Claim to be setting up a new integration with {company}'s systems. \
                 Reference a real vendor they use (discovered through DNS/JS analysis)."
            ),
            objectives: vec![
                "Obtain internal system names".to_string(),
                "Learn authentication processes".to_string(),
                "Get names of IT staff".to_string(),
            ],
            conversation_starters: vec![
                format!("Hi, I'm calling from [vendor]. We're working with {company} on the new integration."),
                "I was told to reach out to your team about setting up API access.".to_string(),
            ],
            trust_building_points: vec![
                "Reference real vendor names from OSINT".to_string(),
                "Use correct internal terminology".to_string(),
                format!("Mention {target_name}'s manager by name"),
            ],
            information_to_extract: vec![
                "VPN setup process".to_string(),
                "Internal ticketing system".to_string(),
                "IT support contact details".to_string(),
            ],
            risk_level: 0.60,
        });
    }

    if let Some(role) = role {
        let role_lower = role.to_lowercase();
        if role_lower.contains("manager")
            || role_lower.contains("director")
            || role_lower.contains("lead")
        {
            scenarios.push(PretextScenario {
                scenario_name: "Executive Briefing Request".to_string(),
                persona: "Industry analyst or journalist".to_string(),
                backstory: "Writing a piece about industry trends and seeking expert commentary."
                    .to_string(),
                objectives: vec![
                    "Extract org structure details".to_string(),
                    "Learn about upcoming projects".to_string(),
                    "Identify technology decisions".to_string(),
                ],
                conversation_starters: vec![
                    format!("Hi {target_name}, I'm writing about trends in your industry."),
                    "Would you be available for a brief interview about your team's approach?"
                        .to_string(),
                ],
                trust_building_points: vec![
                    "Reference real industry publications".to_string(),
                    "Demonstrate knowledge of their work".to_string(),
                ],
                information_to_extract: vec![
                    "Team size and structure".to_string(),
                    "Technology stack details".to_string(),
                    "Security tooling in use".to_string(),
                ],
                risk_level: 0.45,
            });
        }
    }

    if !interests.is_empty() {
        let top_interest = &interests[0];
        scenarios.push(PretextScenario {
            scenario_name: format!("{} Meetup Organizer", top_interest.topic),
            persona: format!("Local {} community organizer", top_interest.topic),
            backstory: format!(
                "Organizing a {} event and looking for speakers or participants.",
                top_interest.topic
            ),
            objectives: vec![
                "Build rapport through shared interest".to_string(),
                "Obtain personal contact information".to_string(),
                "Learn about their schedule and habits".to_string(),
            ],
            conversation_starters: vec![
                format!(
                    "I saw your posts about {}. We're putting together an event.",
                    top_interest.topic
                ),
                "Would you be interested in giving a talk or attending?".to_string(),
            ],
            trust_building_points: vec![
                format!("Demonstrate {} knowledge", top_interest.topic),
                "Reference specific posts they've made".to_string(),
            ],
            information_to_extract: vec![
                "Personal email address".to_string(),
                "Phone number".to_string(),
                "Physical location / workplace".to_string(),
            ],
            risk_level: 0.35,
        });
    }

    scenarios
}

/// Generate vishing scripts for phone-based social engineering.
pub fn generate_vishing_scripts(
    target_name: &str,
    role: Option<&str>,
    company: Option<&str>,
) -> Vec<VishingScript> {
    let mut scripts = Vec::new();

    if let Some(company) = company {
        scripts.push(VishingScript {
            scenario_name: "IT Helpdesk Impersonation".to_string(),
            caller_persona: format!("{company} IT Support"),
            opening_line: format!(
                "Hi {target_name}, this is Alex from IT support at {company}. \
                 We've detected some unusual login attempts on your account and need to verify your identity."
            ),
            script_branches: vec![
                ScriptBranch {
                    condition: "Target cooperates".to_string(),
                    response: "I'll need to verify your employee ID and the last 4 digits of your phone number.".to_string(),
                    follow_up: "Now I'll need you to visit our secure portal to reset your credentials.".to_string(),
                },
                ScriptBranch {
                    condition: "Target is skeptical".to_string(),
                    response: "I completely understand your caution. You can verify this ticket in ServiceNow - the ticket number is INC0012345.".to_string(),
                    follow_up: "While you check that, let me confirm - you are using the VPN to connect, correct?".to_string(),
                },
            ],
            objection_handlers: vec![
                ObjectionHandler {
                    objection: "I'll call IT directly".to_string(),
                    response: "Of course, that's the right thing to do. The direct line is [fake number]. Ask for Alex in security operations.".to_string(),
                    escalation: Some("If they actually call IT, abort and move to next target".to_string()),
                },
                ObjectionHandler {
                    objection: "I need to verify your identity".to_string(),
                    response: format!("Sure. I can see you're in the {} department. Your manager is [name from OSINT]. Is that correct?", role.unwrap_or("engineering")),
                    escalation: None,
                },
            ],
            closing_technique: "I'll send you a follow-up email with the remediation steps. Can you confirm your email address?".to_string(),
            target_information: vec![
                "Employee ID".to_string(),
                "VPN configuration".to_string(),
                "Internal system names".to_string(),
                "Email address confirmation".to_string(),
            ],
        });
    }

    scripts.push(VishingScript {
        scenario_name: "Delivery Service".to_string(),
        caller_persona: "Courier / delivery service".to_string(),
        opening_line: format!(
            "Hello, is this {target_name}? I have a package for you but the address label is damaged. \
             Could you confirm your delivery address?"
        ),
        script_branches: vec![
            ScriptBranch {
                condition: "Target provides address".to_string(),
                response: "Thank you. And can you confirm the suite or apartment number?".to_string(),
                follow_up: "We'll reschedule delivery for tomorrow. What time works best?".to_string(),
            },
            ScriptBranch {
                condition: "Target asks who sent it".to_string(),
                response: "Let me check... it looks like it's from [company name from OSINT]. Internal mail.".to_string(),
                follow_up: "Can you confirm the address so I can get this to you?".to_string(),
            },
        ],
        objection_handlers: vec![
            ObjectionHandler {
                objection: "I'm not expecting any package".to_string(),
                response: "It might be from your company's HR department. They sometimes send welcome packages or benefits materials.".to_string(),
                escalation: None,
            },
        ],
        closing_technique: "We'll have it to you by end of day. Thank you for confirming.".to_string(),
        target_information: vec![
            "Physical address".to_string(),
            "Availability schedule".to_string(),
        ],
    });

    scripts
}

/// Compute overall susceptibility score.
pub fn compute_susceptibility_score(
    interests_count: usize,
    trigger_count: usize,
    social_media_exposure: f64,
    communication_formality: &FormalityLevel,
    has_security_training: bool,
) -> f64 {
    let interest_score = (interests_count as f64 / 5.0).min(1.0) * 15.0;
    let trigger_score = (trigger_count as f64 / 3.0).min(1.0) * 25.0;
    let exposure_score = social_media_exposure * 20.0;
    let formality_score = match communication_formality {
        FormalityLevel::VeryCasual => 15.0,
        FormalityLevel::Casual => 12.0,
        FormalityLevel::Neutral => 8.0,
        FormalityLevel::Formal => 5.0,
        FormalityLevel::VeryFormal => 3.0,
    };
    let training_penalty = if has_security_training { -15.0 } else { 15.0 };

    (interest_score + trigger_score + exposure_score + formality_score + training_penalty)
        .max(0.0)
        .min(100.0)
}

/// Build the full social engineering profile.
pub fn build_social_engineering_profile(
    target_name: &str,
    interests: Vec<ExtractedInterest>,
    communication_style: CommunicationStyle,
    authority_figures: Vec<AuthorityFigure>,
    emotional_triggers: Vec<EmotionalTrigger>,
    phishing_templates: Vec<PhishingTemplate>,
    pretext_scenarios: Vec<PretextScenario>,
    vishing_scripts: Vec<VishingScript>,
    social_media_exposure: f64,
    has_security_training: bool,
) -> SocialEngineeringProfile {
    let susceptibility = compute_susceptibility_score(
        interests.len(),
        emotional_triggers.len(),
        social_media_exposure,
        &communication_style.formality,
        has_security_training,
    );

    SocialEngineeringProfile {
        target_name: target_name.to_string(),
        interests,
        communication_style,
        authority_figures,
        emotional_triggers,
        phishing_templates,
        pretext_scenarios,
        vishing_scripts,
        overall_susceptibility: susceptibility,
    }
}
