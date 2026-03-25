use std::collections::HashMap;

/// Inferred access level for a workforce member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AccessLevel {
    External,
    Contractor,
    Individual,
    TeamLead,
    Manager,
    Director,
    Executive,
    Admin,
}

impl std::fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::External => write!(f, "External"),
            Self::Contractor => write!(f, "Contractor"),
            Self::Individual => write!(f, "Individual Contributor"),
            Self::TeamLead => write!(f, "Team Lead"),
            Self::Manager => write!(f, "Manager"),
            Self::Director => write!(f, "Director"),
            Self::Executive => write!(f, "Executive"),
            Self::Admin => write!(f, "Admin/Root"),
        }
    }
}

/// Technical sophistication score bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TechSophistication {
    NonTechnical,
    BasicUser,
    PowerUser,
    Developer,
    SeniorEngineer,
    Architect,
    SecurityEngineer,
}

impl std::fmt::Display for TechSophistication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonTechnical => write!(f, "Non-Technical"),
            Self::BasicUser => write!(f, "Basic User"),
            Self::PowerUser => write!(f, "Power User"),
            Self::Developer => write!(f, "Developer"),
            Self::SeniorEngineer => write!(f, "Senior Engineer"),
            Self::Architect => write!(f, "Architect"),
            Self::SecurityEngineer => write!(f, "Security Engineer"),
        }
    }
}

/// Social engineering susceptibility assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SocialEngSusceptibility {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl std::fmt::Display for SocialEngSusceptibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::VeryHigh => write!(f, "Very High"),
        }
    }
}

/// Source of workforce intelligence data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkforceDataSource {
    JobPosting,
    GitHubCommits,
    ConferenceTalks,
    PatentFilings,
    LinkedInPublic,
    CompanyWebsite,
    PressRelease,
}

impl std::fmt::Display for WorkforceDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JobPosting => write!(f, "Job Posting"),
            Self::GitHubCommits => write!(f, "GitHub Commits"),
            Self::ConferenceTalks => write!(f, "Conference Talks"),
            Self::PatentFilings => write!(f, "Patent Filings"),
            Self::LinkedInPublic => write!(f, "LinkedIn (Public)"),
            Self::CompanyWebsite => write!(f, "Company Website"),
            Self::PressRelease => write!(f, "Press Release"),
        }
    }
}

/// A job posting with extractable intelligence.
#[derive(Debug, Clone, PartialEq)]
pub struct JobPostingData {
    pub title: String,
    pub department: Option<String>,
    pub technologies: Vec<String>,
    pub seniority_signals: Vec<String>,
    pub security_requirements: Vec<String>,
    pub clearance_required: bool,
    pub remote_allowed: bool,
    pub posted_date: Option<String>,
    pub source_url: String,
}

/// GitHub commit pattern data for a contributor.
#[derive(Debug, Clone, PartialEq)]
pub struct GitCommitPattern {
    pub username: String,
    pub email: Option<String>,
    pub repositories: Vec<String>,
    pub commit_count: usize,
    pub active_hours: Vec<u8>,
    pub active_days: Vec<String>,
    pub languages: Vec<String>,
    pub first_commit_date: Option<String>,
    pub last_commit_date: Option<String>,
}

/// Conference speaker metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct ConferenceSpeaker {
    pub name: String,
    pub affiliation: Option<String>,
    pub talk_title: String,
    pub conference_name: String,
    pub topics: Vec<String>,
    pub year: u16,
}

/// Patent co-authorship record.
#[derive(Debug, Clone, PartialEq)]
pub struct PatentRecord {
    pub inventors: Vec<String>,
    pub title: String,
    pub patent_number: Option<String>,
    pub filing_date: Option<String>,
    pub assignee: String,
    pub technology_area: String,
}

/// A node in the reconstructed org chart.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkforceNode {
    pub id: u64,
    pub name: String,
    pub role: Option<String>,
    pub department: Option<String>,
    pub inferred_access: AccessLevel,
    pub tech_sophistication: TechSophistication,
    pub social_eng_susceptibility: SocialEngSusceptibility,
    pub technologies: Vec<String>,
    pub data_sources: Vec<WorkforceDataSource>,
    pub metadata: HashMap<String, String>,
}

/// Relationship between workforce nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkforceEdge {
    pub source_id: u64,
    pub target_id: u64,
    pub relationship: WorkforceRelationship,
    pub confidence: f64,
    pub evidence: String,
}

/// Type of relationship in the workforce graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkforceRelationship {
    ReportsTo,
    CollaboratesWith,
    CoAuthor,
    SameTeam,
    SameDepartment,
    Mentors,
}

impl std::fmt::Display for WorkforceRelationship {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReportsTo => write!(f, "Reports To"),
            Self::CollaboratesWith => write!(f, "Collaborates With"),
            Self::CoAuthor => write!(f, "Co-Author"),
            Self::SameTeam => write!(f, "Same Team"),
            Self::SameDepartment => write!(f, "Same Department"),
            Self::Mentors => write!(f, "Mentors"),
        }
    }
}

/// Technology stack inferred from job postings.
#[derive(Debug, Clone, PartialEq)]
pub struct InferredTechStack {
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub databases: Vec<String>,
    pub cloud_providers: Vec<String>,
    pub security_tools: Vec<String>,
    pub ci_cd: Vec<String>,
    pub confidence: f64,
}

/// Workforce topology analysis result.
#[derive(Debug, Clone)]
pub struct WorkforceTopologyResult {
    pub nodes: Vec<WorkforceNode>,
    pub edges: Vec<WorkforceEdge>,
    pub inferred_tech_stack: InferredTechStack,
    pub department_summary: HashMap<String, usize>,
    pub high_value_targets: Vec<u64>,
    pub summary: String,
}

/// Configuration for the workforce topology reconstructor.
#[derive(Debug, Clone)]
pub struct WorkforceTopologyConfig {
    pub analyze_job_postings: bool,
    pub analyze_git_patterns: bool,
    pub analyze_conferences: bool,
    pub analyze_patents: bool,
    pub min_collaboration_confidence: f64,
}

impl Default for WorkforceTopologyConfig {
    fn default() -> Self {
        Self {
            analyze_job_postings: true,
            analyze_git_patterns: true,
            analyze_conferences: true,
            analyze_patents: true,
            min_collaboration_confidence: 0.3,
        }
    }
}

impl WorkforceTopologyConfig {
    pub fn with_analyze_job_postings(mut self, enabled: bool) -> Self {
        self.analyze_job_postings = enabled;
        self
    }

    pub fn with_analyze_git_patterns(mut self, enabled: bool) -> Self {
        self.analyze_git_patterns = enabled;
        self
    }

    pub fn with_min_collaboration_confidence(mut self, min: f64) -> Self {
        self.min_collaboration_confidence = min.clamp(0.0, 1.0);
        self
    }
}

/// Reconstructs organization charts from public data sources.
pub struct WorkforceTopologyReconstructor {
    config: WorkforceTopologyConfig,
    nodes: Vec<WorkforceNode>,
    edges: Vec<WorkforceEdge>,
    next_id: u64,
    name_index: HashMap<String, u64>,
}

impl WorkforceTopologyReconstructor {
    pub fn new(config: WorkforceTopologyConfig) -> Self {
        Self {
            config,
            nodes: Vec::new(),
            edges: Vec::new(),
            next_id: 0,
            name_index: HashMap::new(),
        }
    }

    /// Ingest job postings and extract tech stack, seniority, departments.
    pub fn ingest_job_postings(&mut self, postings: &[JobPostingData]) {
        if !self.config.analyze_job_postings {
            return;
        }
        for posting in postings {
            let access = self.infer_access_from_title(&posting.title);
            let tech_soph = self.infer_tech_sophistication_from_posting(posting);
            let dept = posting
                .department
                .clone()
                .unwrap_or_else(|| self.infer_department_from_title(&posting.title));
            let node_name = format!("[Open Role] {}", posting.title);
            let id = self.ensure_node(&node_name);
            let node = &mut self.nodes[id as usize];
            node.role = Some(posting.title.clone());
            node.department = Some(dept);
            node.inferred_access = access;
            node.tech_sophistication = tech_soph;
            node.technologies = posting.technologies.clone();
            if !node.data_sources.contains(&WorkforceDataSource::JobPosting) {
                node.data_sources.push(WorkforceDataSource::JobPosting);
            }
        }
    }

    /// Ingest GitHub commit patterns to build collaboration graph.
    pub fn ingest_git_patterns(&mut self, patterns: &[GitCommitPattern]) {
        if !self.config.analyze_git_patterns {
            return;
        }
        for pattern in patterns {
            let tech_soph = self.infer_tech_from_git(pattern);
            let id = self.ensure_node(&pattern.username);
            let node = &mut self.nodes[id as usize];
            node.technologies.extend(pattern.languages.clone());
            node.technologies.sort();
            node.technologies.dedup();
            if !node
                .data_sources
                .contains(&WorkforceDataSource::GitHubCommits)
            {
                node.data_sources.push(WorkforceDataSource::GitHubCommits);
            }
            node.tech_sophistication = tech_soph;
            if let Some(email) = &pattern.email {
                node.metadata.insert("email".to_string(), email.clone());
            }
            node.metadata.insert(
                "active_hours".to_string(),
                format!("{:?}", pattern.active_hours),
            );
        }

        self.detect_git_collaborations(patterns);
    }

    /// Ingest conference speaker data.
    pub fn ingest_conference_speakers(&mut self, speakers: &[ConferenceSpeaker]) {
        if !self.config.analyze_conferences {
            return;
        }
        for speaker in speakers {
            let id = self.ensure_node(&speaker.name);
            let node = &mut self.nodes[id as usize];
            if let Some(affil) = &speaker.affiliation {
                node.department = Some(affil.clone());
            }
            node.technologies.extend(speaker.topics.clone());
            node.technologies.sort();
            node.technologies.dedup();
            if !node
                .data_sources
                .contains(&WorkforceDataSource::ConferenceTalks)
            {
                node.data_sources.push(WorkforceDataSource::ConferenceTalks);
            }
            node.tech_sophistication =
                std::cmp::max(node.tech_sophistication, TechSophistication::SeniorEngineer);
            node.metadata.insert(
                "conference".to_string(),
                format!("{} ({})", speaker.conference_name, speaker.year),
            );
        }
    }

    /// Ingest patent records and detect co-authorship relationships.
    pub fn ingest_patents(&mut self, patents: &[PatentRecord]) {
        if !self.config.analyze_patents {
            return;
        }
        for patent in patents {
            let inventor_ids: Vec<u64> = patent
                .inventors
                .iter()
                .map(|name| {
                    let id = self.ensure_node(name);
                    let node = &mut self.nodes[id as usize];
                    node.technologies.push(patent.technology_area.clone());
                    node.technologies.sort();
                    node.technologies.dedup();
                    if !node
                        .data_sources
                        .contains(&WorkforceDataSource::PatentFilings)
                    {
                        node.data_sources.push(WorkforceDataSource::PatentFilings);
                    }
                    node.tech_sophistication =
                        std::cmp::max(node.tech_sophistication, TechSophistication::SeniorEngineer);
                    id
                })
                .collect();

            for i in 0..inventor_ids.len() {
                for j in (i + 1)..inventor_ids.len() {
                    self.edges.push(WorkforceEdge {
                        source_id: inventor_ids[i],
                        target_id: inventor_ids[j],
                        relationship: WorkforceRelationship::CoAuthor,
                        confidence: 0.9,
                        evidence: format!("Co-inventors on patent: {}", patent.title),
                    });
                }
            }
        }
    }

    /// Run full analysis: infer SE susceptibility, identify high-value targets.
    pub fn analyze(&mut self) -> WorkforceTopologyResult {
        self.infer_social_engineering_susceptibility();
        self.infer_reporting_relationships();
        let tech_stack = self.aggregate_tech_stack();
        let dept_summary = self.build_department_summary();
        let high_value = self.identify_high_value_targets();

        let summary = format!(
            "Workforce topology: {} people, {} relationships, {} departments, {} high-value targets",
            self.nodes.len(),
            self.edges.len(),
            dept_summary.len(),
            high_value.len()
        );

        WorkforceTopologyResult {
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
            inferred_tech_stack: tech_stack,
            department_summary: dept_summary,
            high_value_targets: high_value,
            summary,
        }
    }

    fn ensure_node(&mut self, name: &str) -> u64 {
        let normalized = name.to_lowercase();
        if let Some(&id) = self.name_index.get(&normalized) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.name_index.insert(normalized, id);
        self.nodes.push(WorkforceNode {
            id,
            name: name.to_string(),
            role: None,
            department: None,
            inferred_access: AccessLevel::Individual,
            tech_sophistication: TechSophistication::BasicUser,
            social_eng_susceptibility: SocialEngSusceptibility::Medium,
            technologies: Vec::new(),
            data_sources: Vec::new(),
            metadata: HashMap::new(),
        });
        id
    }

    fn infer_access_from_title(&self, title: &str) -> AccessLevel {
        let lower = title.to_lowercase();
        if lower.contains("cto")
            || lower.contains("ciso")
            || lower.contains("ceo")
            || lower.contains("vp ")
            || lower.contains("vice president")
            || lower.contains("chief ")
        {
            AccessLevel::Executive
        } else if lower.contains("director") {
            AccessLevel::Director
        } else if lower.contains("manager") || lower.contains("head of") {
            AccessLevel::Manager
        } else if lower.contains("lead") || lower.contains("principal") || lower.contains("staff") {
            AccessLevel::TeamLead
        } else if lower.contains("admin") || lower.contains("devops") || lower.contains("sre") {
            AccessLevel::Admin
        } else if lower.contains("intern") || lower.contains("contractor") {
            AccessLevel::Contractor
        } else {
            AccessLevel::Individual
        }
    }

    fn infer_tech_sophistication_from_posting(
        &self,
        posting: &JobPostingData,
    ) -> TechSophistication {
        let has_security = posting.technologies.iter().any(|t| {
            let tl = t.to_lowercase();
            tl.contains("security") || tl.contains("pentest") || tl.contains("appsec")
        }) || !posting.security_requirements.is_empty();

        if has_security {
            return TechSophistication::SecurityEngineer;
        }

        let title_lower = posting.title.to_lowercase();
        if title_lower.contains("architect") || title_lower.contains("principal") {
            TechSophistication::Architect
        } else if title_lower.contains("senior") || title_lower.contains("staff") {
            TechSophistication::SeniorEngineer
        } else if title_lower.contains("engineer")
            || title_lower.contains("developer")
            || title_lower.contains("programmer")
        {
            TechSophistication::Developer
        } else if posting.technologies.len() > 3 {
            TechSophistication::PowerUser
        } else {
            TechSophistication::BasicUser
        }
    }

    fn infer_department_from_title(&self, title: &str) -> String {
        let lower = title.to_lowercase();
        if lower.contains("security") || lower.contains("appsec") || lower.contains("ciso") {
            "Security".to_string()
        } else if lower.contains("devops") || lower.contains("sre") || lower.contains("infra") {
            "Infrastructure".to_string()
        } else if lower.contains("frontend") || lower.contains("ui") || lower.contains("ux") {
            "Frontend".to_string()
        } else if lower.contains("backend") || lower.contains("api") {
            "Backend".to_string()
        } else if lower.contains("data") || lower.contains("ml") || lower.contains("ai") {
            "Data/ML".to_string()
        } else if lower.contains("mobile") || lower.contains("ios") || lower.contains("android") {
            "Mobile".to_string()
        } else if lower.contains("qa") || lower.contains("test") || lower.contains("quality") {
            "QA".to_string()
        } else {
            "Engineering".to_string()
        }
    }

    fn infer_tech_from_git(&self, pattern: &GitCommitPattern) -> TechSophistication {
        if pattern.commit_count > 500 && pattern.languages.len() > 3 {
            TechSophistication::SeniorEngineer
        } else if pattern.commit_count > 100 {
            TechSophistication::Developer
        } else if pattern.commit_count > 20 {
            TechSophistication::PowerUser
        } else {
            TechSophistication::BasicUser
        }
    }

    fn detect_git_collaborations(&mut self, patterns: &[GitCommitPattern]) {
        let mut repo_contributors: HashMap<String, Vec<u64>> = HashMap::new();
        for pattern in patterns {
            if let Some(&id) = self.name_index.get(&pattern.username.to_lowercase()) {
                for repo in &pattern.repositories {
                    repo_contributors.entry(repo.clone()).or_default().push(id);
                }
            }
        }

        for (repo, contributors) in &repo_contributors {
            if contributors.len() < 2 {
                continue;
            }
            for i in 0..contributors.len() {
                for j in (i + 1)..contributors.len() {
                    let confidence = self.collaboration_confidence(contributors.len());
                    if confidence >= self.config.min_collaboration_confidence {
                        self.edges.push(WorkforceEdge {
                            source_id: contributors[i],
                            target_id: contributors[j],
                            relationship: WorkforceRelationship::CollaboratesWith,
                            confidence,
                            evidence: format!("Both contribute to {}", repo),
                        });
                    }
                }
            }
        }
    }

    fn collaboration_confidence(&self, team_size: usize) -> f64 {
        match team_size {
            2 => 0.8,
            3..=5 => 0.6,
            6..=10 => 0.4,
            _ => 0.2,
        }
    }

    fn infer_social_engineering_susceptibility(&mut self) {
        for node in &mut self.nodes {
            let tech_factor = match node.tech_sophistication {
                TechSophistication::SecurityEngineer => 0,
                TechSophistication::Architect => 1,
                TechSophistication::SeniorEngineer => 1,
                TechSophistication::Developer => 2,
                TechSophistication::PowerUser => 3,
                TechSophistication::BasicUser => 4,
                TechSophistication::NonTechnical => 5,
            };
            let access_factor = match node.inferred_access {
                AccessLevel::Executive => 3,
                AccessLevel::Admin => 2,
                AccessLevel::Director | AccessLevel::Manager => 2,
                _ => 1,
            };
            let exposure = node.data_sources.len();
            let score = tech_factor + access_factor + exposure;
            node.social_eng_susceptibility = if score >= 8 {
                SocialEngSusceptibility::VeryHigh
            } else if score >= 5 {
                SocialEngSusceptibility::High
            } else if score >= 3 {
                SocialEngSusceptibility::Medium
            } else {
                SocialEngSusceptibility::Low
            };
        }
    }

    fn infer_reporting_relationships(&mut self) {
        let mut dept_members: HashMap<String, Vec<(u64, AccessLevel)>> = HashMap::new();
        for node in &self.nodes {
            if let Some(dept) = &node.department {
                dept_members
                    .entry(dept.clone())
                    .or_default()
                    .push((node.id, node.inferred_access));
            }
        }

        let mut new_edges = Vec::new();
        for (_dept, members) in &dept_members {
            if members.len() < 2 {
                continue;
            }
            let highest = members.iter().max_by_key(|(_, access)| *access);
            if let Some((lead_id, lead_access)) = highest {
                for (member_id, member_access) in members {
                    if member_id != lead_id && member_access < lead_access {
                        new_edges.push(WorkforceEdge {
                            source_id: *member_id,
                            target_id: *lead_id,
                            relationship: WorkforceRelationship::ReportsTo,
                            confidence: 0.4,
                            evidence: "Same department, inferred hierarchy".to_string(),
                        });
                    }
                }
            }

            for i in 0..members.len() {
                for j in (i + 1)..members.len() {
                    new_edges.push(WorkforceEdge {
                        source_id: members[i].0,
                        target_id: members[j].0,
                        relationship: WorkforceRelationship::SameDepartment,
                        confidence: 0.5,
                        evidence: "Same department inference".to_string(),
                    });
                }
            }
        }
        self.edges.extend(new_edges);
    }

    fn aggregate_tech_stack(&self) -> InferredTechStack {
        let mut langs = Vec::new();
        let mut frameworks = Vec::new();
        let mut databases = Vec::new();
        let mut clouds = Vec::new();
        let mut security = Vec::new();
        let mut ci_cd = Vec::new();

        let lang_keywords = [
            "rust",
            "python",
            "java",
            "go",
            "typescript",
            "javascript",
            "c++",
            "c#",
            "ruby",
            "kotlin",
            "swift",
            "scala",
            "php",
        ];
        let framework_keywords = [
            "react", "angular", "vue", "django", "flask", "spring", "express", "rails", "nextjs",
            "fastapi",
        ];
        let db_keywords = [
            "postgres",
            "mysql",
            "mongodb",
            "redis",
            "elasticsearch",
            "dynamodb",
            "cassandra",
            "sqlite",
        ];
        let cloud_keywords = ["aws", "gcp", "azure", "cloudflare", "digitalocean"];
        let security_keywords = ["burp", "owasp", "nmap", "metasploit", "wireshark"];
        let cicd_keywords = [
            "jenkins",
            "github actions",
            "gitlab ci",
            "circleci",
            "terraform",
            "ansible",
            "docker",
            "kubernetes",
        ];

        for node in &self.nodes {
            for tech in &node.technologies {
                let lower = tech.to_lowercase();
                Self::categorize_tech(&lower, &lang_keywords, &mut langs);
                Self::categorize_tech(&lower, &framework_keywords, &mut frameworks);
                Self::categorize_tech(&lower, &db_keywords, &mut databases);
                Self::categorize_tech(&lower, &cloud_keywords, &mut clouds);
                Self::categorize_tech(&lower, &security_keywords, &mut security);
                Self::categorize_tech(&lower, &cicd_keywords, &mut ci_cd);
            }
        }

        for list in [
            &mut langs,
            &mut frameworks,
            &mut databases,
            &mut clouds,
            &mut security,
            &mut ci_cd,
        ] {
            list.sort();
            list.dedup();
        }

        let total_sources = self
            .nodes
            .iter()
            .map(|n| n.data_sources.len())
            .sum::<usize>();
        let confidence = if total_sources > 10 {
            0.8
        } else if total_sources > 5 {
            0.6
        } else {
            0.3
        };

        InferredTechStack {
            languages: langs,
            frameworks,
            databases,
            cloud_providers: clouds,
            security_tools: security,
            ci_cd,
            confidence,
        }
    }

    fn categorize_tech(tech_lower: &str, keywords: &[&str], bucket: &mut Vec<String>) {
        for kw in keywords {
            if tech_lower.contains(kw) {
                bucket.push(tech_lower.to_string());
                return;
            }
        }
    }

    fn build_department_summary(&self) -> HashMap<String, usize> {
        let mut summary = HashMap::new();
        for node in &self.nodes {
            if let Some(dept) = &node.department {
                *summary.entry(dept.clone()).or_default() += 1;
            }
        }
        summary
    }

    fn identify_high_value_targets(&self) -> Vec<u64> {
        let mut targets: Vec<(u64, u64)> = self
            .nodes
            .iter()
            .filter_map(|node| {
                let access_score = match node.inferred_access {
                    AccessLevel::Admin => 10,
                    AccessLevel::Executive => 9,
                    AccessLevel::Director => 7,
                    AccessLevel::Manager => 5,
                    AccessLevel::TeamLead => 4,
                    AccessLevel::Individual => 2,
                    AccessLevel::Contractor => 1,
                    AccessLevel::External => 0,
                };
                let se_score = match node.social_eng_susceptibility {
                    SocialEngSusceptibility::VeryHigh => 4,
                    SocialEngSusceptibility::High => 3,
                    SocialEngSusceptibility::Medium => 2,
                    SocialEngSusceptibility::Low => 1,
                };
                let combined = access_score * se_score;
                if combined >= 10 {
                    Some((node.id, combined))
                } else {
                    None
                }
            })
            .collect();
        targets.sort_by(|a, b| b.1.cmp(&a.1));
        targets.iter().map(|(id, _)| *id).collect()
    }

    /// Read access to nodes.
    pub fn nodes(&self) -> &[WorkforceNode] {
        &self.nodes
    }

    /// Read access to edges.
    pub fn edges(&self) -> &[WorkforceEdge] {
        &self.edges
    }
}
