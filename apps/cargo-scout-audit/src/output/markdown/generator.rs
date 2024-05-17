use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::output::{
    report::{Category, Finding, Report},
    utils,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct SummaryContext {
    pub date: String,
    pub categories: Vec<SummaryCategory>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SummaryCategory {
    pub name: String,
    pub link: String,
    pub results_count: usize,
    pub severity: String,
}

pub fn generate_summary_context(report: &Report) -> SummaryContext {
    let summary_map = summarize_findings(&report.categories, &report.findings);

    let summary_categories = report
        .categories
        .iter()
        .filter_map(|category| {
            summary_map
                .get(&category.id)
                .map(|&(count, ref severity)| SummaryCategory {
                    name: category.name.clone(),
                    link: utils::sanitize_category_name(&category.name),
                    results_count: count,
                    severity: severity.clone(),
                })
        })
        .collect();

    SummaryContext {
        date: report.date.clone(),
        categories: summary_categories,
    }
}

// This function remains mostly the same, but ensures it returns a map with the severity string
fn summarize_findings(
    categories: &[Category],
    findings: &[Finding],
) -> HashMap<String, (usize, String)> {
    let mut summary = HashMap::new();

    for finding in findings {
        if let Some(category) = categories.iter().find(|c| c.id == finding.category_id) {
            let severity = category
                .vulnerabilities
                .first()
                .map(|v| utils::capitalize(&v.severity))
                .unwrap_or_default();
            let entry = summary.entry(category.id.clone()).or_insert((0, severity));
            entry.0 += 1;
        }
    }

    summary
}
