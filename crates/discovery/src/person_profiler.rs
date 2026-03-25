use std::collections::HashMap;

/// Platform where a username was discovered or checked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Platform {
    GitHub,
    Twitter,
    LinkedIn,
    Reddit,
    Instagram,
    TikTok,
    Discord,
    Telegram,
    Facebook,
    YouTube,
    Pinterest,
    StackOverflow,
    HackerNews,
    Medium,
    DevTo,
    Mastodon,
    Keybase,
    BitBucket,
    GitLab,
    Twitch,
    Spotify,
    SoundCloud,
    Flickr,
    Snapchat,
    WhatsApp,
    Signal,
    Slack,
    Custom(String),
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitHub => write!(f, "GitHub"),
            Self::Twitter => write!(f, "Twitter"),
            Self::LinkedIn => write!(f, "LinkedIn"),
            Self::Reddit => write!(f, "Reddit"),
            Self::Instagram => write!(f, "Instagram"),
            Self::TikTok => write!(f, "TikTok"),
            Self::Discord => write!(f, "Discord"),
            Self::Telegram => write!(f, "Telegram"),
            Self::Facebook => write!(f, "Facebook"),
            Self::YouTube => write!(f, "YouTube"),
            Self::Pinterest => write!(f, "Pinterest"),
            Self::StackOverflow => write!(f, "StackOverflow"),
            Self::HackerNews => write!(f, "HackerNews"),
            Self::Medium => write!(f, "Medium"),
            Self::DevTo => write!(f, "Dev.to"),
            Self::Mastodon => write!(f, "Mastodon"),
            Self::Keybase => write!(f, "Keybase"),
            Self::BitBucket => write!(f, "BitBucket"),
            Self::GitLab => write!(f, "GitLab"),
            Self::Twitch => write!(f, "Twitch"),
            Self::Spotify => write!(f, "Spotify"),
            Self::SoundCloud => write!(f, "SoundCloud"),
            Self::Flickr => write!(f, "Flickr"),
            Self::Snapchat => write!(f, "Snapchat"),
            Self::WhatsApp => write!(f, "WhatsApp"),
            Self::Signal => write!(f, "Signal"),
            Self::Slack => write!(f, "Slack"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

/// URL template for username lookup on a platform.
#[derive(Debug, Clone)]
pub struct PlatformCheck {
    pub platform: Platform,
    pub url_template: String,
    pub category: PlatformCategory,
}

/// Category grouping for platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformCategory {
    SocialMedia,
    Developer,
    Professional,
    Messaging,
    Media,
    Gaming,
    Other,
}

impl std::fmt::Display for PlatformCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocialMedia => write!(f, "Social Media"),
            Self::Developer => write!(f, "Developer"),
            Self::Professional => write!(f, "Professional"),
            Self::Messaging => write!(f, "Messaging"),
            Self::Media => write!(f, "Media"),
            Self::Gaming => write!(f, "Gaming"),
            Self::Other => write!(f, "Other"),
        }
    }
}

/// Result of checking a username on a single platform.
#[derive(Debug, Clone, PartialEq)]
pub struct UsernameMatch {
    pub platform: Platform,
    pub url: String,
    pub confidence: f64,
    pub category: PlatformCategory,
}

/// Possible email format templates.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EmailFormat {
    FirstDotLast,
    FLast,
    FirstL,
    FirstOnly,
    FirstUnderscoreLast,
    FirstHyphenLast,
    LastDotFirst,
    LastFirst,
}

impl EmailFormat {
    /// Generate an email from a first name, last name, and domain.
    pub fn generate(&self, first: &str, last: &str, domain: &str) -> String {
        let f = first.to_lowercase();
        let l = last.to_lowercase();
        match self {
            Self::FirstDotLast => format!("{f}.{l}@{domain}"),
            Self::FLast => format!("{}{l}@{domain}", &f[..1.min(f.len())]),
            Self::FirstL => format!("{f}{}@{domain}", &l[..1.min(l.len())]),
            Self::FirstOnly => format!("{f}@{domain}"),
            Self::FirstUnderscoreLast => format!("{f}_{l}@{domain}"),
            Self::FirstHyphenLast => format!("{f}-{l}@{domain}"),
            Self::LastDotFirst => format!("{l}.{f}@{domain}"),
            Self::LastFirst => format!("{l}{f}@{domain}"),
        }
    }

    /// All standard formats.
    pub fn all_formats() -> Vec<Self> {
        vec![
            Self::FirstDotLast,
            Self::FLast,
            Self::FirstL,
            Self::FirstOnly,
            Self::FirstUnderscoreLast,
            Self::FirstHyphenLast,
            Self::LastDotFirst,
            Self::LastFirst,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::FirstDotLast => "first.last@domain",
            Self::FLast => "flast@domain",
            Self::FirstL => "firstl@domain",
            Self::FirstOnly => "first@domain",
            Self::FirstUnderscoreLast => "first_last@domain",
            Self::FirstHyphenLast => "first-last@domain",
            Self::LastDotFirst => "last.first@domain",
            Self::LastFirst => "lastfirst@domain",
        }
    }
}

/// Breach record for an individual.
#[derive(Debug, Clone, PartialEq)]
pub struct PersonBreachRecord {
    pub breach_name: String,
    pub breach_date: Option<String>,
    pub data_types: Vec<String>,
    pub is_verified: bool,
    pub is_sensitive: bool,
}

/// Social graph connection between two people.
#[derive(Debug, Clone, PartialEq)]
pub struct SocialConnection {
    pub platform: Platform,
    pub target_username: String,
    pub relationship: ConnectionType,
    pub interaction_count: Option<u32>,
}

/// Type of social connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionType {
    Follower,
    Following,
    Mutual,
    Collaborator,
    Colleague,
    Friend,
    Unknown,
}

impl std::fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Follower => write!(f, "Follower"),
            Self::Following => write!(f, "Following"),
            Self::Mutual => write!(f, "Mutual"),
            Self::Collaborator => write!(f, "Collaborator"),
            Self::Colleague => write!(f, "Colleague"),
            Self::Friend => write!(f, "Friend"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Employment record for a person.
#[derive(Debug, Clone, PartialEq)]
pub struct EmploymentRecord {
    pub company: String,
    pub title: Option<String>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub source: Platform,
    pub confidence: f64,
}

/// Inferred location for a person.
#[derive(Debug, Clone, PartialEq)]
pub struct InferredLocation {
    pub location: String,
    pub method: LocationMethod,
    pub confidence: f64,
}

/// How a location was inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocationMethod {
    TimezoneAnalysis,
    GeotagExtraction,
    CheckInPattern,
    ProfileDeclaration,
    IpGeolocation,
    LanguageInference,
}

impl std::fmt::Display for LocationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimezoneAnalysis => write!(f, "Timezone Analysis"),
            Self::GeotagExtraction => write!(f, "Geotag Extraction"),
            Self::CheckInPattern => write!(f, "Check-in Pattern"),
            Self::ProfileDeclaration => write!(f, "Profile Declaration"),
            Self::IpGeolocation => write!(f, "IP Geolocation"),
            Self::LanguageInference => write!(f, "Language Inference"),
        }
    }
}

/// Technology skill with evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct TechSkill {
    pub technology: String,
    pub proficiency: ProficiencyLevel,
    pub evidence_sources: Vec<Platform>,
    pub confidence: f64,
}

/// Proficiency level in a technology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProficiencyLevel {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

impl std::fmt::Display for ProficiencyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Beginner => write!(f, "Beginner"),
            Self::Intermediate => write!(f, "Intermediate"),
            Self::Advanced => write!(f, "Advanced"),
            Self::Expert => write!(f, "Expert"),
        }
    }
}

/// Complete person profile from OSINT aggregation.
#[derive(Debug, Clone)]
pub struct PersonProfile {
    pub name: Option<String>,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub usernames: Vec<String>,
    pub platform_matches: Vec<UsernameMatch>,
    pub email_permutations: Vec<String>,
    pub breach_records: Vec<PersonBreachRecord>,
    pub social_graph: Vec<SocialConnection>,
    pub employment_history: Vec<EmploymentRecord>,
    pub locations: Vec<InferredLocation>,
    pub tech_skills: Vec<TechSkill>,
    pub digital_footprint_score: f64,
    pub data_points: HashMap<String, DataPoint>,
}

/// A single data point with its confidence score.
#[derive(Debug, Clone, PartialEq)]
pub struct DataPoint {
    pub value: String,
    pub confidence: f64,
    pub source: Platform,
}

/// Input seed for person profiling.
#[derive(Debug, Clone, Default)]
pub struct PersonSeed {
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub username: Option<String>,
    pub known_employers: Vec<String>,
}

/// Build the master list of platform checks for username correlation.
pub fn build_platform_checks() -> Vec<PlatformCheck> {
    let mut checks = Vec::with_capacity(530);

    let social_platforms = [
        (Platform::Twitter, "https://twitter.com/{username}"),
        (Platform::Instagram, "https://instagram.com/{username}"),
        (Platform::Facebook, "https://facebook.com/{username}"),
        (Platform::TikTok, "https://tiktok.com/@{username}"),
        (Platform::Reddit, "https://reddit.com/user/{username}"),
        (Platform::Pinterest, "https://pinterest.com/{username}"),
        (Platform::Snapchat, "https://snapchat.com/add/{username}"),
        (Platform::YouTube, "https://youtube.com/@{username}"),
        (Platform::Twitch, "https://twitch.tv/{username}"),
        (Platform::Mastodon, "https://mastodon.social/@{username}"),
    ];

    for (platform, template) in social_platforms {
        checks.push(PlatformCheck {
            platform,
            url_template: template.to_string(),
            category: PlatformCategory::SocialMedia,
        });
    }

    let dev_platforms = [
        (Platform::GitHub, "https://github.com/{username}"),
        (Platform::GitLab, "https://gitlab.com/{username}"),
        (Platform::BitBucket, "https://bitbucket.org/{username}"),
        (
            Platform::StackOverflow,
            "https://stackoverflow.com/users/{username}",
        ),
        (
            Platform::HackerNews,
            "https://news.ycombinator.com/user?id={username}",
        ),
        (Platform::Medium, "https://medium.com/@{username}"),
        (Platform::DevTo, "https://dev.to/{username}"),
        (Platform::Keybase, "https://keybase.io/{username}"),
    ];

    for (platform, template) in dev_platforms {
        checks.push(PlatformCheck {
            platform,
            url_template: template.to_string(),
            category: PlatformCategory::Developer,
        });
    }

    let professional = [(Platform::LinkedIn, "https://linkedin.com/in/{username}")];

    for (platform, template) in professional {
        checks.push(PlatformCheck {
            platform,
            url_template: template.to_string(),
            category: PlatformCategory::Professional,
        });
    }

    let messaging = [
        (Platform::Discord, "https://discord.com/users/{username}"),
        (Platform::Telegram, "https://t.me/{username}"),
        (Platform::Slack, "https://{username}.slack.com"),
        (Platform::Signal, "https://signal.me/{username}"),
    ];

    for (platform, template) in messaging {
        checks.push(PlatformCheck {
            platform,
            url_template: template.to_string(),
            category: PlatformCategory::Messaging,
        });
    }

    let media = [
        (
            Platform::Spotify,
            "https://open.spotify.com/user/{username}",
        ),
        (Platform::SoundCloud, "https://soundcloud.com/{username}"),
        (Platform::Flickr, "https://flickr.com/people/{username}"),
    ];

    for (platform, template) in media {
        checks.push(PlatformCheck {
            platform,
            url_template: template.to_string(),
            category: PlatformCategory::Media,
        });
    }

    let extra_sites = [
        "about.me",
        "behance.net",
        "dribbble.com",
        "goodreads.com",
        "producthunt.com",
        "angel.co",
        "crunchbase.com",
        "gravatar.com",
        "hackthebox.com",
        "tryhackme.com",
        "leetcode.com",
        "codewars.com",
        "hackerrank.com",
        "replit.com",
        "codepen.io",
        "jsfiddle.net",
        "npmjs.com",
        "pypi.org",
        "crates.io",
        "rubygems.org",
        "hub.docker.com",
        "kaggle.com",
        "researchgate.net",
        "academia.edu",
        "orcid.org",
        "arxiv.org",
        "slideshare.net",
        "speakerdeck.com",
        "meetup.com",
        "eventbrite.com",
        "patreon.com",
        "buymeacoffee.com",
        "gumroad.com",
        "ko-fi.com",
        "substack.com",
        "hashnode.dev",
        "wordpress.com",
        "blogger.com",
        "tumblr.com",
        "livejournal.com",
        "vimeo.com",
        "dailymotion.com",
        "imgur.com",
        "9gag.com",
        "quora.com",
        "ask.fm",
        "formspring.me",
        "spring.me",
        "foursquare.com",
        "swarm.com",
        "untappd.com",
        "strava.com",
        "fitbit.com",
        "myfitnesspal.com",
        "last.fm",
        "rateyourmusic.com",
        "discogs.com",
        "bandcamp.com",
        "mixcloud.com",
        "deezer.com",
        "tidal.com",
        "genius.com",
        "musixmatch.com",
        "shazam.com",
        "giphy.com",
        "tenor.com",
        "deviantart.com",
        "artstation.com",
        "pixiv.net",
        "newgrounds.com",
        "furaffinity.net",
        "wattpad.com",
        "fanfiction.net",
        "archiveofourown.org",
        "lulu.com",
        "blurb.com",
        "issuu.com",
        "scribd.com",
        "fiverr.com",
        "upwork.com",
        "freelancer.com",
        "toptal.com",
        "triplebyte.com",
        "hired.com",
        "glassdoor.com",
        "indeed.com",
        "monster.com",
        "ziprecruiter.com",
        "careerbuilder.com",
        "dice.com",
        "simplyhired.com",
        "snagajob.com",
        "yelp.com",
        "tripadvisor.com",
        "airbnb.com",
        "booking.com",
        "couchsurfing.com",
        "trustpilot.com",
        "g2.com",
        "capterra.com",
        "alternativeto.net",
        "slant.co",
        "stackshare.io",
        "siftery.com",
        "builtwith.com",
        "wappalyzer.com",
        "namemc.com",
        "steamcommunity.com",
        "epicgames.com",
        "ea.com",
        "ubisoft.com",
        "bethesda.net",
        "gog.com",
        "itch.io",
        "roblox.com",
        "minecraft.net",
        "chess.com",
        "lichess.org",
        "osu.ppy.sh",
        "vndb.org",
        "myanimelist.net",
        "anilist.co",
        "kitsu.io",
        "letterboxd.com",
        "trakt.tv",
        "imdb.com",
        "rottentomatoes.com",
        "metacritic.com",
        "boardgamegeek.com",
        "goodreads.com",
        "storygraph.com",
        "librarything.com",
        "openlibrary.org",
        "worldcat.org",
        "zotero.org",
        "mendeley.com",
        "citeulike.org",
        "bibsonomy.org",
        "overleaf.com",
        "sharelatex.com",
        "authorea.com",
        "figshare.com",
        "zenodo.org",
        "dryad.org",
        "dataverse.org",
        "protocols.io",
        "bioprotocol.org",
        "addgene.org",
        "benchling.com",
        "notion.so",
        "coda.io",
        "airtable.com",
        "clickup.com",
        "monday.com",
        "asana.com",
        "trello.com",
        "basecamp.com",
        "linear.app",
        "shortcut.com",
        "jira.atlassian.com",
        "confluence.atlassian.com",
        "miro.com",
        "figma.com",
        "canva.com",
        "sketch.com",
        "invisionapp.com",
        "zeplin.io",
        "abstract.com",
        "framer.com",
        "webflow.com",
        "bubble.io",
        "retool.com",
        "appsheet.google.com",
        "glideapps.com",
        "zapier.com",
        "ifttt.com",
        "make.com",
        "n8n.io",
        "pipedream.com",
        "tray.io",
        "workato.com",
        "mulesoft.com",
        "postman.com",
        "insomnia.rest",
        "swagger.io",
        "readme.io",
        "gitbook.com",
        "docusaurus.io",
        "vuepress.vuejs.org",
        "vercel.com",
        "netlify.com",
        "heroku.com",
        "render.com",
        "railway.app",
        "fly.io",
        "digitalocean.com",
        "linode.com",
        "vultr.com",
        "hetzner.com",
        "ovh.com",
        "scaleway.com",
        "cloudflare.com",
        "fastly.com",
        "akamai.com",
        "bunny.net",
        "statuspage.io",
        "betterstack.com",
        "pagerduty.com",
        "opsgenie.com",
        "victorops.com",
        "datadog.com",
        "newrelic.com",
        "sentry.io",
        "bugsnag.com",
        "rollbar.com",
        "honeybadger.io",
        "airbrake.io",
        "logrocket.com",
        "fullstory.com",
        "hotjar.com",
        "mixpanel.com",
        "amplitude.com",
        "segment.com",
        "heap.io",
        "plausible.io",
        "fathomanalytics.com",
        "simpleanalytics.com",
        "matomo.org",
        "umami.is",
        "countly.com",
        "posthog.com",
        "launchdarkly.com",
        "split.io",
        "optimizely.com",
        "vwo.com",
        "abtasty.com",
        "convertkit.com",
        "mailchimp.com",
        "sendgrid.com",
        "postmarkapp.com",
        "sparkpost.com",
        "mailgun.com",
        "sendinblue.com",
        "hubspot.com",
        "salesforce.com",
        "zoho.com",
        "freshworks.com",
        "intercom.io",
        "drift.com",
        "crisp.chat",
        "tawk.to",
        "zendesk.com",
        "helpscout.com",
        "freshdesk.com",
        "kayako.com",
        "groove.com",
        "dixa.com",
        "gorgias.com",
        "kustomer.com",
        "gladly.com",
        "front.com",
        "missive.com",
        "hiver.com",
        "dragapp.com",
        "hey.com",
        "superhuman.com",
        "spark.com",
        "edison.com",
        "newton.com",
        "polymail.io",
        "mailspring.com",
        "thunderbird.net",
        "protonmail.com",
        "tutanota.com",
        "fastmail.com",
        "runbox.com",
        "mailfence.com",
        "disroot.org",
        "riseup.net",
        "autistici.org",
        "kolabnow.com",
        "posteo.de",
        "mailbox.org",
        "startmail.com",
        "ctemplar.com",
        "cock.li",
        "airmail.cc",
        "dnmx.org",
        "onionmail.org",
        "elude.in",
        "secmail.pro",
        "ebay.com",
        "etsy.com",
        "amazon.com",
        "aliexpress.com",
        "wish.com",
        "shopify.com",
        "bigcartel.com",
        "depop.com",
        "poshmark.com",
        "mercari.com",
        "offerup.com",
        "craigslist.org",
        "facebook.com/marketplace",
        "nextdoor.com",
        "thingiverse.com",
        "myminifactory.com",
        "printables.com",
        "thangs.com",
        "grabcad.com",
        "onshape.com",
        "instructables.com",
        "hackaday.io",
        "element14.com",
        "eevblog.com",
        "allaboutcircuits.com",
        "edaboard.com",
        "circuitlab.com",
        "kicad.org",
        "altium.com",
        "digikey.com",
        "mouser.com",
        "arrow.com",
        "newark.com",
        "sparkfun.com",
        "adafruit.com",
        "seeedstudio.com",
        "pololu.com",
        "robotshop.com",
        "servocity.com",
        "openai.com/community",
        "huggingface.co",
        "wandb.ai",
        "comet.ml",
        "neptune.ai",
        "mlflow.org",
        "dvc.org",
        "labelbox.com",
        "scale.ai",
        "snorkel.ai",
        "colab.google",
        "deepnote.com",
        "observable.com",
        "datalore.io",
        "hex.tech",
        "mode.com",
        "metabase.com",
        "redash.io",
        "superset.apache.org",
        "grafana.com",
        "kibana.elastic.co",
        "splunk.com",
        "sumologic.com",
        "logz.io",
        "mezmo.com",
        "papertrail.com",
        "logtail.com",
        "axiom.co",
        "cribl.io",
        "fluentd.org",
        "vector.dev",
        "opensearch.org",
        "typesense.org",
        "meilisearch.com",
        "algolia.com",
        "elastic.co",
        "solr.apache.org",
        "weaviate.io",
        "pinecone.io",
        "qdrant.tech",
        "milvus.io",
        "vespa.ai",
        "marqo.ai",
        "supabase.com",
        "neon.tech",
        "planetscale.com",
        "cockroachlabs.com",
        "yugabyte.com",
        "tidb.io",
        "singlestore.com",
        "citus-data.com",
        "timescale.com",
        "questdb.io",
        "influxdata.com",
        "victoriametrics.com",
        "clickhouse.com",
        "duckdb.org",
        "motherduck.com",
        "snowflake.com",
        "databricks.com",
        "firebolt.io",
        "starburst.io",
        "trino.io",
        "dremio.com",
        "airbyte.com",
        "fivetran.com",
        "stitch.com",
        "matillion.com",
        "talend.com",
        "informatica.com",
        "snaplogic.com",
        "boomi.com",
        "celigo.com",
        "dbt.com",
        "dataform.co",
        "sqlmesh.com",
        "dagster.io",
        "prefect.io",
        "temporal.io",
        "airflow.apache.org",
        "luigi.readthedocs.io",
        "argo-workflows.readthedocs.io",
        "kubeflow.org",
        "mlflow.org/tracking",
        "bentoml.com",
        "seldon.io",
        "cortex.dev",
        "ray.io",
        "anyscale.com",
    ];

    for site in extra_sites {
        checks.push(PlatformCheck {
            platform: Platform::Custom(site.to_string()),
            url_template: format!("https://{site}/{{username}}"),
            category: PlatformCategory::Other,
        });
    }

    checks
}

/// Generate all email permutations for a person given known employers.
pub fn generate_email_permutations(
    first_name: &str,
    last_name: &str,
    domains: &[&str],
) -> Vec<String> {
    let formats = EmailFormat::all_formats();
    let mut permutations = Vec::with_capacity(formats.len() * domains.len());

    for domain in domains {
        for format in &formats {
            permutations.push(format.generate(first_name, last_name, domain));
        }
    }

    permutations
}

/// Check a username against all platform URL templates and return match URLs.
pub fn correlate_username(username: &str, checks: &[PlatformCheck]) -> Vec<UsernameMatch> {
    checks
        .iter()
        .map(|check| UsernameMatch {
            platform: check.platform.clone(),
            url: check.url_template.replace("{username}", username),
            confidence: base_confidence_for_platform(&check.platform),
            category: check.category,
        })
        .collect()
}

fn base_confidence_for_platform(platform: &Platform) -> f64 {
    match platform {
        Platform::GitHub | Platform::LinkedIn | Platform::Twitter => 0.85,
        Platform::Reddit | Platform::StackOverflow | Platform::HackerNews => 0.75,
        Platform::Instagram | Platform::Facebook | Platform::TikTok => 0.70,
        Platform::Discord | Platform::Telegram | Platform::Slack => 0.60,
        Platform::Medium | Platform::DevTo | Platform::Mastodon => 0.65,
        _ => 0.50,
    }
}

/// Analyze posting timestamps to infer timezone/location.
pub fn infer_timezone_from_posts(timestamps_utc_hour: &[u8]) -> Vec<InferredLocation> {
    if timestamps_utc_hour.is_empty() {
        return Vec::new();
    }

    let mut hour_counts = [0u32; 24];
    for &h in timestamps_utc_hour {
        if (h as usize) < 24 {
            hour_counts[h as usize] += 1;
        }
    }

    let total = timestamps_utc_hour.len() as f64;
    let mut quiet_start = 0u8;
    let mut min_activity = u32::MAX;

    for window_start in 0u8..24 {
        let mut window_sum = 0u32;
        for offset in 0u8..6 {
            let idx = ((window_start + offset) % 24) as usize;
            window_sum += hour_counts[idx];
        }
        if window_sum < min_activity {
            min_activity = window_sum;
            quiet_start = window_start;
        }
    }

    let sleep_midpoint = (quiet_start as i32 + 3) % 24;
    let utc_offset = (3 - sleep_midpoint + 24) % 24;
    let utc_offset = if utc_offset > 12 {
        utc_offset - 24
    } else {
        utc_offset
    };

    let confidence = if total >= 100.0 {
        0.85
    } else if total >= 50.0 {
        0.70
    } else if total >= 20.0 {
        0.55
    } else {
        0.35
    };

    let tz_name = match utc_offset {
        -12..=-9 => "US/Alaska or Pacific Islands",
        -8 => "US/Pacific (PST/PDT)",
        -7 => "US/Mountain (MST/MDT)",
        -6 => "US/Central (CST/CDT)",
        -5 => "US/Eastern (EST/EDT)",
        -4 => "Atlantic (AST)",
        -3 => "South America/East (BRT)",
        -2..=-1 => "Mid-Atlantic",
        0 => "UTC / Western Europe (GMT/WET)",
        1 => "Central Europe (CET)",
        2 => "Eastern Europe (EET)",
        3 => "Moscow / Middle East (MSK)",
        4..=5 => "Central Asia / India (IST)",
        6..=7 => "Southeast Asia (ICT)",
        8 => "East Asia (CST/SGT/HKT)",
        9 => "Japan/Korea (JST/KST)",
        10..=12 => "Australia/Pacific (AEST)",
        _ => "Unknown",
    };

    vec![InferredLocation {
        location: tz_name.to_string(),
        method: LocationMethod::TimezoneAnalysis,
        confidence,
    }]
}

/// Extract technology skills from repository languages and contribution data.
pub fn extract_tech_skills(repos: &[(&str, &str, u32)]) -> Vec<TechSkill> {
    let mut lang_stats: HashMap<String, (u32, u32)> = HashMap::new();

    for &(language, _repo_name, commit_count) in repos {
        let entry = lang_stats.entry(language.to_lowercase()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += commit_count;
    }

    let max_commits = lang_stats.values().map(|v| v.1).max().unwrap_or(1);

    let mut skills: Vec<TechSkill> = lang_stats
        .into_iter()
        .map(|(lang, (repo_count, commits))| {
            let proficiency = match (repo_count, commits) {
                (_, c) if c > max_commits / 2 => ProficiencyLevel::Expert,
                (r, _) if r >= 5 => ProficiencyLevel::Advanced,
                (r, _) if r >= 2 => ProficiencyLevel::Intermediate,
                _ => ProficiencyLevel::Beginner,
            };

            let confidence = (commits as f64 / max_commits as f64).min(1.0) * 0.7
                + (repo_count as f64 / 10.0).min(1.0) * 0.3;

            TechSkill {
                technology: lang,
                proficiency,
                evidence_sources: vec![Platform::GitHub],
                confidence: confidence.min(1.0),
            }
        })
        .collect();

    skills.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    skills
}

/// Compute digital footprint exposure score (0-100).
pub fn compute_footprint_score(
    platform_count: usize,
    breach_count: usize,
    email_count: usize,
    social_connections: usize,
    has_employment_history: bool,
    location_inferred: bool,
) -> f64 {
    let platform_score = (platform_count as f64 / 20.0).min(1.0) * 30.0;
    let breach_score = (breach_count as f64 / 5.0).min(1.0) * 25.0;
    let email_score = (email_count as f64 / 10.0).min(1.0) * 10.0;
    let social_score = (social_connections as f64 / 50.0).min(1.0) * 15.0;
    let employment_score = if has_employment_history { 10.0 } else { 0.0 };
    let location_score = if location_inferred { 10.0 } else { 0.0 };

    (platform_score + breach_score + email_score + social_score + employment_score + location_score)
        .min(100.0)
}

/// Build a full person profile from a seed and gathered intelligence data.
pub fn build_person_profile(
    seed: &PersonSeed,
    platform_matches: Vec<UsernameMatch>,
    email_permutations: Vec<String>,
    breach_records: Vec<PersonBreachRecord>,
    social_graph: Vec<SocialConnection>,
    employment_history: Vec<EmploymentRecord>,
    locations: Vec<InferredLocation>,
    tech_skills: Vec<TechSkill>,
) -> PersonProfile {
    let digital_footprint_score = compute_footprint_score(
        platform_matches.len(),
        breach_records.len(),
        email_permutations.len() + seed.email.iter().count(),
        social_graph.len(),
        !employment_history.is_empty(),
        !locations.is_empty(),
    );

    let mut data_points = HashMap::new();

    if let Some(ref name) = seed.name {
        data_points.insert(
            "name".to_string(),
            DataPoint {
                value: name.clone(),
                confidence: 1.0,
                source: Platform::Custom("seed".to_string()),
            },
        );
    }

    if let Some(ref email) = seed.email {
        data_points.insert(
            "primary_email".to_string(),
            DataPoint {
                value: email.clone(),
                confidence: 1.0,
                source: Platform::Custom("seed".to_string()),
            },
        );
    }

    for loc in &locations {
        data_points.insert(
            format!("location_{}", loc.method),
            DataPoint {
                value: loc.location.clone(),
                confidence: loc.confidence,
                source: Platform::Custom("analysis".to_string()),
            },
        );
    }

    PersonProfile {
        name: seed.name.clone(),
        emails: seed.email.iter().cloned().collect(),
        phones: seed.phone.iter().cloned().collect(),
        usernames: seed.username.iter().cloned().collect(),
        platform_matches,
        email_permutations,
        breach_records,
        social_graph,
        employment_history,
        locations,
        tech_skills,
        digital_footprint_score,
        data_points,
    }
}

/// Generate username variations from a name for cross-platform searching.
pub fn generate_username_variants(first: &str, last: &str) -> Vec<String> {
    let f = first.to_lowercase();
    let l = last.to_lowercase();
    let fi = &f[..1.min(f.len())];
    let li = &l[..1.min(l.len())];

    let mut variants = vec![
        format!("{f}{l}"),
        format!("{f}.{l}"),
        format!("{f}_{l}"),
        format!("{f}-{l}"),
        format!("{fi}{l}"),
        format!("{f}{li}"),
        format!("{l}{f}"),
        format!("{l}.{f}"),
        format!("{l}_{f}"),
        format!("{l}{fi}"),
        format!("{f}{l}1"),
        format!("{f}{l}99"),
        format!("{f}_{l}_"),
        format!("_{f}{l}"),
        format!("the{f}{l}"),
        format!("{f}{l}dev"),
        format!("{f}{l}official"),
        format!("real{f}{l}"),
        format!("{f}.{l}.dev"),
        format!("{f}{l}tech"),
    ];

    variants.sort();
    variants.dedup();
    variants
}

/// Parse HIBP API-style breach response JSON.
pub fn parse_hibp_breaches(json_str: &str) -> Vec<PersonBreachRecord> {
    let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(json_str);
    let entries = match parsed {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    entries
        .iter()
        .filter_map(|entry| {
            let name = entry.get("Name")?.as_str()?;
            let date = entry
                .get("BreachDate")
                .and_then(|v| v.as_str())
                .map(String::from);
            let data_classes = entry
                .get("DataClasses")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let is_verified = entry
                .get("IsVerified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let is_sensitive = entry
                .get("IsSensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            Some(PersonBreachRecord {
                breach_name: name.to_string(),
                breach_date: date,
                data_types: data_classes,
                is_verified,
                is_sensitive,
            })
        })
        .collect()
}

/// Classify social connections based on interaction patterns.
pub fn classify_connections(
    interactions: &[(&str, &str, u32, bool, bool)],
) -> Vec<SocialConnection> {
    interactions
        .iter()
        .map(
            |&(platform_str, username, count, follows_them, they_follow)| {
                let platform = match platform_str.to_lowercase().as_str() {
                    "github" => Platform::GitHub,
                    "twitter" => Platform::Twitter,
                    "linkedin" => Platform::LinkedIn,
                    "reddit" => Platform::Reddit,
                    "instagram" => Platform::Instagram,
                    "mastodon" => Platform::Mastodon,
                    "facebook" => Platform::Facebook,
                    _ => Platform::Custom(platform_str.to_string()),
                };

                let relationship = match (follows_them, they_follow) {
                    (true, true) => ConnectionType::Mutual,
                    (true, false) => ConnectionType::Following,
                    (false, true) => ConnectionType::Follower,
                    (false, false) => {
                        if count > 10 {
                            ConnectionType::Collaborator
                        } else {
                            ConnectionType::Unknown
                        }
                    }
                };

                SocialConnection {
                    platform,
                    target_username: username.to_string(),
                    relationship,
                    interaction_count: Some(count),
                }
            },
        )
        .collect()
}

/// Build employment history from raw records.
pub fn build_employment_history(
    records: &[(&str, Option<&str>, Option<&str>, Option<&str>, &str)],
) -> Vec<EmploymentRecord> {
    records
        .iter()
        .map(|&(company, title, start, end, source_str)| {
            let source = match source_str.to_lowercase().as_str() {
                "linkedin" => Platform::LinkedIn,
                "github" => Platform::GitHub,
                _ => Platform::Custom(source_str.to_string()),
            };

            EmploymentRecord {
                company: company.to_string(),
                title: title.map(String::from),
                start_date: start.map(String::from),
                end_date: end.map(String::from),
                source,
                confidence: match source_str.to_lowercase().as_str() {
                    "linkedin" => 0.90,
                    "github" => 0.70,
                    _ => 0.50,
                },
            }
        })
        .collect()
}

/// Detect naming pattern matches between known usernames.
pub fn detect_username_patterns(usernames: &[&str]) -> HashMap<String, Vec<String>> {
    let mut patterns: HashMap<String, Vec<String>> = HashMap::new();

    for username in usernames {
        let lower = username.to_lowercase();

        if lower.contains('.') {
            patterns
                .entry("dot_separated".to_string())
                .or_default()
                .push(lower.clone());
        }
        if lower.contains('_') {
            patterns
                .entry("underscore_separated".to_string())
                .or_default()
                .push(lower.clone());
        }
        if lower.contains('-') {
            patterns
                .entry("hyphen_separated".to_string())
                .or_default()
                .push(lower.clone());
        }
        if lower.chars().last().map_or(false, |c| c.is_ascii_digit()) {
            patterns
                .entry("numeric_suffix".to_string())
                .or_default()
                .push(lower.clone());
        }
        if lower.len() <= 6 {
            patterns
                .entry("short_handle".to_string())
                .or_default()
                .push(lower);
        } else {
            patterns
                .entry("long_handle".to_string())
                .or_default()
                .push(lower);
        }
    }

    patterns
}
