use std::collections::HashMap;
use std::fmt;

use regex::Regex;
use serde_json;

/// SEC EDGAR base URL for filing index retrieval by CIK.
const EDGAR_FILING_INDEX_BASE: &str = "https://data.sec.gov/submissions/CIK";

/// SEC EDGAR base URL for XBRL company facts.
const EDGAR_XBRL_FACTS_BASE: &str = "https://data.sec.gov/api/xbrl/companyfacts/CIK";

/// SEC filing types relevant to financial intelligence gathering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgarFilingType {
    /// Annual report with full financial statements, risk factors, and subsidiary disclosures.
    Form10K,
    /// Quarterly report with interim financial statements.
    Form10Q,
    /// Current report for material events (acquisitions, leadership changes, bankruptcy).
    Form8K,
    /// Definitive proxy statement with executive compensation and board composition.
    Def14A,
    /// Registration statement for IPO — full business model and risk disclosure.
    FormS1,
    /// Quarterly institutional investment manager holdings report.
    Form13F,
    /// Insider transaction report (officers, directors, 10%+ owners).
    Form4,
    /// Beneficial ownership report (activist investors, 5%+ stakes).
    Sc13D,
    /// Passive beneficial ownership report (5%+ stake, no activist intent).
    Sc13G,
    /// Proxy solicitation material for shareholder votes.
    Proxy,
    /// Unrecognized filing type captured as-is from EDGAR.
    Other,
}

impl EdgarFilingType {
    /// Parse a filing type string from EDGAR into the corresponding enum variant.
    pub fn from_edgar_str(s: &str) -> Self {
        let normalized = s.trim().to_uppercase();
        match normalized.as_str() {
            "10-K" | "10-K/A" => Self::Form10K,
            "10-Q" | "10-Q/A" => Self::Form10Q,
            "8-K" | "8-K/A" => Self::Form8K,
            "DEF 14A" | "DEF14A" => Self::Def14A,
            "S-1" | "S-1/A" => Self::FormS1,
            "13-F" | "13F-HR" | "13F-HR/A" => Self::Form13F,
            "4" | "4/A" => Self::Form4,
            "SC 13D" | "SC 13D/A" | "SC13D" => Self::Sc13D,
            "SC 13G" | "SC 13G/A" | "SC13G" => Self::Sc13G,
            "DEFA14A" | "PRE 14A" | "DFAN14A" => Self::Proxy,
            _ => Self::Other,
        }
    }

    /// EDGAR form string for URL construction.
    pub fn edgar_form_str(&self) -> &'static str {
        match self {
            Self::Form10K => "10-K",
            Self::Form10Q => "10-Q",
            Self::Form8K => "8-K",
            Self::Def14A => "DEF 14A",
            Self::FormS1 => "S-1",
            Self::Form13F => "13F-HR",
            Self::Form4 => "4",
            Self::Sc13D => "SC 13D",
            Self::Sc13G => "SC 13G",
            Self::Proxy => "DEFA14A",
            Self::Other => "",
        }
    }
}

impl fmt::Display for EdgarFilingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Form10K => write!(f, "10-K (Annual Report)"),
            Self::Form10Q => write!(f, "10-Q (Quarterly Report)"),
            Self::Form8K => write!(f, "8-K (Current Report)"),
            Self::Def14A => write!(f, "DEF 14A (Proxy Statement)"),
            Self::FormS1 => write!(f, "S-1 (Registration Statement)"),
            Self::Form13F => write!(f, "13F-HR (Institutional Holdings)"),
            Self::Form4 => write!(f, "Form 4 (Insider Transaction)"),
            Self::Sc13D => write!(f, "SC 13D (Beneficial Ownership)"),
            Self::Sc13G => write!(f, "SC 13G (Passive Ownership)"),
            Self::Proxy => write!(f, "Proxy (Solicitation Material)"),
            Self::Other => write!(f, "Other Filing"),
        }
    }
}

/// Company record from EDGAR full-text search or CIK lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgarCompany {
    pub cik: String,
    pub name: String,
    pub ticker: Option<String>,
    pub sic_code: Option<String>,
    pub sic_description: Option<String>,
    pub state_of_incorporation: Option<String>,
    pub fiscal_year_end: Option<String>,
    pub filing_count: usize,
}

impl fmt::Display for EdgarCompany {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (CIK {})", self.name, self.cik)?;
        if let Some(ticker) = &self.ticker {
            write!(f, " [{}]", ticker)?;
        }
        Ok(())
    }
}

/// Metadata for a single SEC filing from the EDGAR filing index.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgarFiling {
    pub accession_number: String,
    pub filing_type: EdgarFilingType,
    pub filing_type_raw: String,
    pub filing_date: String,
    pub primary_document: String,
    pub primary_doc_description: String,
    pub company_cik: String,
    pub company_name: String,
    pub file_number: Option<String>,
    pub film_number: Option<String>,
    pub items: Vec<String>,
    pub size_bytes: Option<u64>,
    pub is_amendment: bool,
}

impl fmt::Display for EdgarFiling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} filed {} ({})",
            self.filing_date, self.company_name, self.filing_type, self.accession_number
        )
    }
}

/// Subsidiary extracted from 10-K Exhibit 21 text.
#[derive(Debug, Clone, PartialEq)]
pub struct SubsidiaryInfo {
    pub name: String,
    pub jurisdiction: Option<String>,
    pub ownership_percentage: Option<f64>,
    pub parent_name: Option<String>,
    pub is_direct_subsidiary: bool,
    pub raw_line: String,
}

impl fmt::Display for SubsidiaryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(pct) = self.ownership_percentage {
            write!(f, " ({:.1}%)", pct)?;
        }
        if let Some(jur) = &self.jurisdiction {
            write!(f, " — {}", jur)?;
        }
        Ok(())
    }
}

/// A chain of ownership from a beneficial owner up through parent entities.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnershipChain {
    pub ultimate_parent: String,
    pub chain: Vec<OwnershipLink>,
    pub total_effective_ownership: Option<f64>,
}

impl fmt::Display for OwnershipChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ultimate_parent)?;
        for link in &self.chain {
            write!(f, " -> {}", link)?;
        }
        if let Some(pct) = self.total_effective_ownership {
            write!(f, " (effective: {:.1}%)", pct)?;
        }
        Ok(())
    }
}

/// Single link in an ownership chain.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnershipLink {
    pub entity_name: String,
    pub ownership_percentage: Option<f64>,
    pub relationship: OwnershipRelationship,
}

impl fmt::Display for OwnershipLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.entity_name, self.relationship)?;
        if let Some(pct) = self.ownership_percentage {
            write!(f, " {:.1}%", pct)?;
        }
        Ok(())
    }
}

/// Type of relationship in an ownership structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnershipRelationship {
    DirectSubsidiary,
    IndirectSubsidiary,
    JointVenture,
    Affiliate,
    BeneficialOwner,
    InsiderHolder,
}

impl fmt::Display for OwnershipRelationship {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectSubsidiary => write!(f, "direct subsidiary"),
            Self::IndirectSubsidiary => write!(f, "indirect subsidiary"),
            Self::JointVenture => write!(f, "joint venture"),
            Self::Affiliate => write!(f, "affiliate"),
            Self::BeneficialOwner => write!(f, "beneficial owner"),
            Self::InsiderHolder => write!(f, "insider holder"),
        }
    }
}

/// Investor holding from 13F or Schedule 13D/G filings.
#[derive(Debug, Clone, PartialEq)]
pub struct InvestorHolding {
    pub investor_name: String,
    pub investor_cik: Option<String>,
    pub shares_held: u64,
    pub value_usd: Option<u64>,
    pub percentage_of_class: Option<f64>,
    pub filing_type: EdgarFilingType,
    pub filing_date: String,
    pub is_new_position: bool,
}

impl fmt::Display for InvestorHolding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} shares", self.investor_name, self.shares_held)?;
        if let Some(pct) = self.percentage_of_class {
            write!(f, " ({:.2}%)", pct)?;
        }
        if let Some(val) = self.value_usd {
            write!(f, " worth ${}", val)?;
        }
        Ok(())
    }
}

/// Risk classification derived from filing analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FilingRisk {
    /// Routine periodic filing with no anomalies.
    Routine,
    /// Noteworthy event but expected (earnings, scheduled proxy).
    Informational,
    /// Potential governance or financial concern (restatement, auditor change).
    Elevated,
    /// Significant corporate action (acquisition, divestiture, leadership change).
    Significant,
    /// Active investor pressure, SEC investigation, or material weakness.
    Critical,
}

impl fmt::Display for FilingRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Routine => write!(f, "Routine"),
            Self::Informational => write!(f, "Informational"),
            Self::Elevated => write!(f, "Elevated"),
            Self::Significant => write!(f, "Significant"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Complete financial intelligence report aggregating EDGAR data.
#[derive(Debug, Clone)]
pub struct FinancialIntelReport {
    pub company: EdgarCompany,
    pub filings: Vec<EdgarFiling>,
    pub subsidiaries: Vec<SubsidiaryInfo>,
    pub ownership_chains: Vec<OwnershipChain>,
    pub investor_holdings: Vec<InvestorHolding>,
    pub filing_risks: HashMap<String, FilingRisk>,
    pub overall_risk: FilingRisk,
    pub summary: String,
}

impl fmt::Display for FinancialIntelReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Financial Intelligence Report ===")?;
        writeln!(f, "Company: {}", self.company)?;
        writeln!(f, "Filings analyzed: {}", self.filings.len())?;
        writeln!(f, "Subsidiaries identified: {}", self.subsidiaries.len())?;
        writeln!(f, "Ownership chains: {}", self.ownership_chains.len())?;
        writeln!(f, "Investor holdings: {}", self.investor_holdings.len())?;
        writeln!(f, "Overall risk: {}", self.overall_risk)?;
        writeln!(f, "---")?;
        write!(f, "{}", self.summary)
    }
}

/// Build EDGAR full-text search URL for company name lookup.
pub fn build_edgar_search_url(company_name: &str) -> String {
    let encoded = company_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_string()
            } else if c == ' ' {
                "%20".to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect::<String>();
    format!(
        "https://efts.sec.gov/LATEST/search-index?q={}&dateRange=custom&startdt=2020-01-01&forms=10-K",
        encoded
    )
}

/// Build EDGAR company search URL using the EDGAR company API.
pub fn build_company_search_url(company_name: &str) -> String {
    let encoded = company_name.replace(' ', "%20");
    format!(
        "https://efts.sec.gov/LATEST/search-index?q=%22{}%22&forms=10-K,10-Q,8-K",
        encoded
    )
}

/// Build EDGAR filing index URL from a CIK number.
/// Returns the submissions JSON endpoint which contains recent filings.
pub fn build_filing_index_url(cik: &str) -> String {
    let padded = format!("{:0>10}", cik.trim_start_matches('0'));
    format!("{}{}.json", EDGAR_FILING_INDEX_BASE, padded)
}

/// Build EDGAR XBRL company facts URL for structured financial data.
pub fn build_xbrl_facts_url(cik: &str) -> String {
    let padded = format!("{:0>10}", cik.trim_start_matches('0'));
    format!("{}{}.json", EDGAR_XBRL_FACTS_BASE, padded)
}

/// Build EDGAR filing document URL from an accession number and document filename.
pub fn build_filing_document_url(cik: &str, accession_number: &str, document: &str) -> String {
    let padded_cik = format!("{:0>10}", cik.trim_start_matches('0'));
    let clean_accession = accession_number.replace('-', "");
    format!(
        "https://www.sec.gov/Archives/edgar/data/{}/{}/{}",
        padded_cik, clean_accession, document
    )
}

/// Parse EDGAR company search JSON response to extract company records.
/// Handles both the EFTS search API format and the submissions API format.
pub fn parse_edgar_company_search(json_str: &str) -> Vec<EdgarCompany> {
    let mut companies = Vec::new();
    let parsed: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return companies,
    };

    if let Some(hits_outer) = parsed.get("hits") {
        let hits = hits_outer
            .get("hits")
            .and_then(|h| h.as_array())
            .unwrap_or(&Vec::new())
            .clone();
        for hit in &hits {
            let source = match hit.get("_source") {
                Some(s) => s,
                None => continue,
            };
            let cik = source
                .get("entity_id")
                .or_else(|| source.get("cik"))
                .and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .unwrap_or_default();
            let name = source
                .get("entity_name")
                .or_else(|| source.get("company_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            let ticker = source
                .get("tickers")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    source
                        .get("tickers")
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                })
                .map(|s| s.to_string());

            companies.push(EdgarCompany {
                cik,
                name,
                ticker,
                sic_code: source
                    .get("sic")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                sic_description: source
                    .get("sic_description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                state_of_incorporation: source
                    .get("state_of_incorporation")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                fiscal_year_end: source
                    .get("fiscal_year_end")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                filing_count: 0,
            });
        }
    }

    if companies.is_empty() {
        if let Some(cik_val) = parsed.get("cik") {
            let cik = match cik_val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                _ => return companies,
            };
            let name = parsed
                .get("name")
                .or_else(|| parsed.get("entityName"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();
            let ticker = parsed
                .get("tickers")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let sic_code = parsed.get("sic").and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            });
            let sic_description = parsed
                .get("sicDescription")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let state_of_incorporation = parsed
                .get("stateOfIncorporation")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let fiscal_year_end = parsed
                .get("fiscalYearEnd")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let filing_count = parsed
                .get("filings")
                .and_then(|f| f.get("recent"))
                .and_then(|r| r.get("form"))
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);

            companies.push(EdgarCompany {
                cik,
                name,
                ticker,
                sic_code,
                sic_description,
                state_of_incorporation,
                fiscal_year_end,
                filing_count,
            });
        }
    }

    companies
}

/// Parse EDGAR filing index JSON (from submissions endpoint) to extract filing metadata.
pub fn parse_filing_index(json_str: &str, company_cik: &str) -> Vec<EdgarFiling> {
    let mut filings = Vec::new();
    let parsed: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return filings,
    };

    let company_name = parsed
        .get("name")
        .or_else(|| parsed.get("entityName"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
        .to_string();

    let recent = match parsed.get("filings").and_then(|f| f.get("recent")) {
        Some(r) => r,
        None => return filings,
    };

    let forms = recent.get("form").and_then(|v| v.as_array());
    let dates = recent.get("filingDate").and_then(|v| v.as_array());
    let accessions = recent.get("accessionNumber").and_then(|v| v.as_array());
    let primary_docs = recent.get("primaryDocument").and_then(|v| v.as_array());
    let primary_descs = recent
        .get("primaryDocDescription")
        .and_then(|v| v.as_array());
    let file_numbers = recent.get("fileNumber").and_then(|v| v.as_array());
    let film_numbers = recent.get("filmNumber").and_then(|v| v.as_array());
    let items_arr = recent.get("items").and_then(|v| v.as_array());
    let sizes = recent.get("size").and_then(|v| v.as_array());
    let _is_amendment_arr = recent.get("isXBRL").and_then(|v| v.as_array());

    let count = forms.map(|a| a.len()).unwrap_or(0);

    for i in 0..count {
        let form_raw = forms
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let filing_type = EdgarFilingType::from_edgar_str(&form_raw);
        let filing_date = dates
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let accession = accessions
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let primary_doc = primary_docs
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let primary_desc = primary_descs
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let file_number = file_numbers
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let film_number = film_numbers
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let items_str = items_arr
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let items: Vec<String> = if items_str.is_empty() {
            Vec::new()
        } else {
            items_str.split(',').map(|s| s.trim().to_string()).collect()
        };
        let size_bytes = sizes.and_then(|a| a.get(i)).and_then(|v| v.as_u64());
        let is_amendment = form_raw.contains("/A");

        filings.push(EdgarFiling {
            accession_number: accession,
            filing_type,
            filing_type_raw: form_raw,
            filing_date,
            primary_document: primary_doc,
            primary_doc_description: primary_desc,
            company_cik: company_cik.to_string(),
            company_name: company_name.clone(),
            file_number,
            film_number,
            items,
            size_bytes,
            is_amendment,
        });
    }

    filings
}

/// Extract subsidiary information from 10-K Exhibit 21 text.
/// Parses tabular and free-form subsidiary disclosures, extracting names,
/// jurisdictions of incorporation, and ownership percentages where stated.
pub fn extract_subsidiaries_from_exhibit21(exhibit_text: &str) -> Vec<SubsidiaryInfo> {
    let mut subsidiaries = Vec::new();
    let mut seen_names: HashMap<String, usize> = HashMap::new();

    let tabular_re = Regex::new(
        r"(?i)^\s*(?:\d+[\.\)]\s*)?([A-Z][A-Za-z0-9\s&',\.\-\(\)]+?)\s{2,}([A-Za-z\s,]+?)(?:\s{2,}(\d{1,3}(?:\.\d+)?)\s*%?)?\s*$"
    ).expect("tabular regex must compile");

    let inline_re = Regex::new(
        r"(?i)([A-Z][A-Za-z0-9\s&',\.\-\(\)]{4,}?),?\s+(?:a |an )?(?:corporation |company |limited |LLC |Ltd\.?|Inc\.?|GmbH|S\.?A\.?|B\.?V\.?|L\.?P\.?|N\.?V\.?)\s*(?:(?:organized|incorporated|formed|registered)\s+(?:in|under the laws of)\s+)?(?:the\s+)?(?:State\s+of\s+|Republic\s+of\s+|Province\s+of\s+)?([A-Z][A-Za-z\s]+)"
    ).expect("inline regex must compile");

    let pct_re =
        Regex::new(r"(\d{1,3}(?:\.\d+)?)\s*(?:%|percent)").expect("pct regex must compile");

    let _ownership_qualifier_re = Regex::new(
        r"(?i)(?:wholly[- ]owned|100%|indirect(?:ly)?[- ]owned|majority[- ]owned|minority)",
    )
    .expect("ownership qualifier regex must compile");

    let jurisdiction_standalone_re = Regex::new(r"(?i)\(([A-Z][A-Za-z\s,]+)\)")
        .expect("jurisdiction standalone regex must compile");

    for line in exhibit_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.len() < 5
            || trimmed.starts_with("---")
            || trimmed.starts_with("===")
            || trimmed.to_lowercase().starts_with("exhibit")
            || trimmed.to_lowercase().starts_with("subsidiaries of")
            || trimmed.to_lowercase().starts_with("the following")
            || trimmed.to_lowercase().starts_with("name of")
            || trimmed.to_lowercase().starts_with("name ")
                && trimmed.to_lowercase().contains("jurisdiction")
        {
            continue;
        }

        if let Some(caps) = tabular_re.captures(trimmed) {
            let name = caps
                .get(1)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            let jurisdiction = caps.get(2).map(|m| m.as_str().trim().to_string());
            let pct = caps.get(3).and_then(|m| m.as_str().parse::<f64>().ok());

            if name.len() >= 3 && !name.to_lowercase().contains("name") {
                let normalized = name.to_lowercase();
                if seen_names.contains_key(&normalized) {
                    continue;
                }
                seen_names.insert(normalized, subsidiaries.len());

                let is_direct = !trimmed.to_lowercase().contains("indirect");
                let ownership = match pct {
                    Some(p) => Some(p),
                    None => infer_ownership_from_text(trimmed),
                };

                subsidiaries.push(SubsidiaryInfo {
                    name,
                    jurisdiction,
                    ownership_percentage: ownership,
                    parent_name: None,
                    is_direct_subsidiary: is_direct,
                    raw_line: trimmed.to_string(),
                });
                continue;
            }
        }

        if let Some(caps) = inline_re.captures(trimmed) {
            let name = caps
                .get(1)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            let jurisdiction_raw = caps.get(2).map(|m| m.as_str().trim().to_string());

            if name.len() >= 3 {
                let normalized = name.to_lowercase();
                if seen_names.contains_key(&normalized) {
                    continue;
                }
                seen_names.insert(normalized, subsidiaries.len());

                let pct = pct_re
                    .captures(trimmed)
                    .and_then(|c| c.get(1))
                    .and_then(|m| m.as_str().parse::<f64>().ok());
                let ownership = match pct {
                    Some(p) => Some(p),
                    None => infer_ownership_from_text(trimmed),
                };
                let is_direct = !trimmed.to_lowercase().contains("indirect");

                subsidiaries.push(SubsidiaryInfo {
                    name,
                    jurisdiction: jurisdiction_raw,
                    ownership_percentage: ownership,
                    parent_name: None,
                    is_direct_subsidiary: is_direct,
                    raw_line: trimmed.to_string(),
                });
                continue;
            }
        }

        if has_entity_suffix(trimmed) {
            let name = extract_entity_name(trimmed);
            if name.len() >= 3 {
                let normalized = name.to_lowercase();
                if seen_names.contains_key(&normalized) {
                    continue;
                }
                seen_names.insert(normalized, subsidiaries.len());

                let jurisdiction = jurisdiction_standalone_re
                    .captures(trimmed)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().trim().to_string());
                let pct = pct_re
                    .captures(trimmed)
                    .and_then(|c| c.get(1))
                    .and_then(|m| m.as_str().parse::<f64>().ok());
                let ownership = match pct {
                    Some(p) => Some(p),
                    None => infer_ownership_from_text(trimmed),
                };
                let is_direct = !trimmed.to_lowercase().contains("indirect");

                subsidiaries.push(SubsidiaryInfo {
                    name,
                    jurisdiction,
                    ownership_percentage: ownership,
                    parent_name: None,
                    is_direct_subsidiary: is_direct,
                    raw_line: trimmed.to_string(),
                });
            }
        }
    }

    subsidiaries
}

/// Build ownership chains from a flat list of subsidiaries.
/// Constructs parent-child trees and computes effective ownership percentages
/// through indirect holdings.
pub fn build_ownership_chain(
    parent_name: &str,
    subsidiaries: &[SubsidiaryInfo],
) -> Vec<OwnershipChain> {
    let mut chains = Vec::new();
    let direct_subs: Vec<&SubsidiaryInfo> = subsidiaries
        .iter()
        .filter(|s| s.is_direct_subsidiary)
        .collect();
    let indirect_subs: Vec<&SubsidiaryInfo> = subsidiaries
        .iter()
        .filter(|s| !s.is_direct_subsidiary)
        .collect();

    for sub in &direct_subs {
        let mut chain_links = vec![OwnershipLink {
            entity_name: sub.name.clone(),
            ownership_percentage: sub.ownership_percentage,
            relationship: OwnershipRelationship::DirectSubsidiary,
        }];

        let child_indirects: Vec<&&SubsidiaryInfo> = indirect_subs
            .iter()
            .filter(|ind| {
                ind.parent_name
                    .as_ref()
                    .map(|p| p.to_lowercase() == sub.name.to_lowercase())
                    .unwrap_or(false)
            })
            .collect();

        for indirect in &child_indirects {
            chain_links.push(OwnershipLink {
                entity_name: indirect.name.clone(),
                ownership_percentage: indirect.ownership_percentage,
                relationship: OwnershipRelationship::IndirectSubsidiary,
            });
        }

        let effective = compute_effective_ownership(&chain_links);

        chains.push(OwnershipChain {
            ultimate_parent: parent_name.to_string(),
            chain: chain_links,
            total_effective_ownership: effective,
        });
    }

    for orphan_indirect in &indirect_subs {
        let already_chained = chains.iter().any(|c| {
            c.chain
                .iter()
                .any(|l| l.entity_name.to_lowercase() == orphan_indirect.name.to_lowercase())
        });
        if !already_chained {
            let link = OwnershipLink {
                entity_name: orphan_indirect.name.clone(),
                ownership_percentage: orphan_indirect.ownership_percentage,
                relationship: OwnershipRelationship::IndirectSubsidiary,
            };
            chains.push(OwnershipChain {
                ultimate_parent: parent_name.to_string(),
                chain: vec![link],
                total_effective_ownership: orphan_indirect.ownership_percentage,
            });
        }
    }

    chains
}

/// Classify filing risk based on filing type, items, and amendment status.
pub fn classify_filing_risk(filing: &EdgarFiling) -> FilingRisk {
    let high_risk_8k_items = [
        "1.01", "1.02", "1.03", "2.01", "2.04", "2.05", "2.06", "4.01", "4.02", "5.01", "5.02",
    ];

    match filing.filing_type {
        EdgarFilingType::Form10K => {
            if filing.is_amendment {
                FilingRisk::Elevated
            } else {
                FilingRisk::Informational
            }
        }
        EdgarFilingType::Form10Q => {
            if filing.is_amendment {
                FilingRisk::Elevated
            } else {
                FilingRisk::Routine
            }
        }
        EdgarFilingType::Form8K => {
            let has_high_risk_item = filing
                .items
                .iter()
                .any(|item| high_risk_8k_items.iter().any(|hri| item.trim() == *hri));
            if has_high_risk_item {
                FilingRisk::Significant
            } else if filing.items.is_empty() {
                FilingRisk::Informational
            } else {
                FilingRisk::Informational
            }
        }
        EdgarFilingType::Def14A => FilingRisk::Informational,
        EdgarFilingType::FormS1 => FilingRisk::Significant,
        EdgarFilingType::Form13F => FilingRisk::Routine,
        EdgarFilingType::Form4 => FilingRisk::Informational,
        EdgarFilingType::Sc13D => FilingRisk::Critical,
        EdgarFilingType::Sc13G => FilingRisk::Elevated,
        EdgarFilingType::Proxy => FilingRisk::Informational,
        EdgarFilingType::Other => FilingRisk::Routine,
    }
}

/// Build a complete financial intelligence report from parsed EDGAR data.
pub fn build_financial_intel_report(
    company: EdgarCompany,
    filings: Vec<EdgarFiling>,
    exhibit21_text: Option<&str>,
    holdings: Vec<InvestorHolding>,
) -> FinancialIntelReport {
    let subsidiaries = match exhibit21_text {
        Some(text) => extract_subsidiaries_from_exhibit21(text),
        None => Vec::new(),
    };

    let ownership_chains = build_ownership_chain(&company.name, &subsidiaries);

    let mut filing_risks: HashMap<String, FilingRisk> = HashMap::new();
    let mut max_risk = FilingRisk::Routine;
    for filing in &filings {
        let risk = classify_filing_risk(filing);
        filing_risks.insert(filing.accession_number.clone(), risk);
        if risk > max_risk {
            max_risk = risk;
        }
    }

    let filing_type_counts = count_filing_types(&filings);
    let summary = build_report_summary(
        &company,
        &filings,
        &subsidiaries,
        &holdings,
        max_risk,
        &filing_type_counts,
    );

    FinancialIntelReport {
        company,
        filings,
        subsidiaries,
        ownership_chains,
        investor_holdings: holdings,
        filing_risks,
        overall_risk: max_risk,
        summary,
    }
}

fn compute_effective_ownership(links: &[OwnershipLink]) -> Option<f64> {
    let mut effective = 100.0_f64;
    let mut has_any = false;

    for link in links {
        if let Some(pct) = link.ownership_percentage {
            effective = effective * pct / 100.0;
            has_any = true;
        }
    }

    if has_any {
        Some(effective)
    } else {
        None
    }
}

fn infer_ownership_from_text(text: &str) -> Option<f64> {
    let lower = text.to_lowercase();
    if lower.contains("wholly-owned") || lower.contains("wholly owned") || lower.contains("100%") {
        Some(100.0)
    } else if lower.contains("majority-owned") || lower.contains("majority owned") {
        Some(51.0)
    } else {
        None
    }
}

fn has_entity_suffix(text: &str) -> bool {
    let suffixes = [
        " Inc.",
        " Inc",
        " LLC",
        " Ltd.",
        " Ltd",
        " Corp.",
        " Corp",
        " GmbH",
        " S.A.",
        " SA",
        " B.V.",
        " BV",
        " N.V.",
        " NV",
        " L.P.",
        " LP",
        " LLP",
        " PLC",
        " Plc",
        " Co.",
        " Co,",
        " Limited",
        " Incorporated",
        " Corporation",
        " S.r.l.",
        " Srl",
        " AG",
        " KG",
        " Pty",
    ];
    suffixes.iter().any(|sfx| text.contains(sfx))
}

fn extract_entity_name(text: &str) -> String {
    let cleaned = text.trim();
    let stripped = cleaned
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '.' || c == ')' || c == ' ');

    let paren_re = Regex::new(r"\([^)]*\)\s*$").expect("paren regex must compile");
    let without_trailing_parens = paren_re.replace(stripped, "").to_string();

    let pct_re =
        Regex::new(r"\s+\d{1,3}(?:\.\d+)?\s*%?\s*$").expect("trailing pct regex must compile");
    let without_pct = pct_re.replace(&without_trailing_parens, "").to_string();

    without_pct.trim().to_string()
}

fn count_filing_types(filings: &[EdgarFiling]) -> HashMap<EdgarFilingType, usize> {
    let mut counts = HashMap::new();
    for filing in filings {
        *counts.entry(filing.filing_type).or_insert(0) += 1;
    }
    counts
}

fn build_report_summary(
    company: &EdgarCompany,
    filings: &[EdgarFiling],
    subsidiaries: &[SubsidiaryInfo],
    holdings: &[InvestorHolding],
    overall_risk: FilingRisk,
    type_counts: &HashMap<EdgarFilingType, usize>,
) -> String {
    let mut parts = Vec::new();

    parts.push(format!(
        "{} has {} recent filings on record.",
        company.name,
        filings.len()
    ));

    let mut type_strs: Vec<String> = type_counts
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(ft, count)| format!("{}: {}", ft, count))
        .collect();
    type_strs.sort();
    if !type_strs.is_empty() {
        parts.push(format!("Filing breakdown: {}.", type_strs.join(", ")));
    }

    if !subsidiaries.is_empty() {
        let wholly_owned = subsidiaries
            .iter()
            .filter(|s| s.ownership_percentage == Some(100.0))
            .count();
        parts.push(format!(
            "{} subsidiaries identified ({} wholly-owned).",
            subsidiaries.len(),
            wholly_owned
        ));
    }

    if !holdings.is_empty() {
        let total_shares: u64 = holdings.iter().map(|h| h.shares_held).sum();
        parts.push(format!(
            "{} investor holdings tracked ({} total shares).",
            holdings.len(),
            total_shares
        ));
    }

    parts.push(format!("Overall risk assessment: {}.", overall_risk));

    parts.join(" ")
}
