use regex::RegexBuilder;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

const MAX_DEPTH: usize = 10;
const MAX_DEFINED_STEPS: usize = 100;
const MAX_EXECUTED_STEPS: usize = 50;

#[derive(Debug, Clone)]
pub struct WorkflowSummary {
    pub step_count: usize,
    pub run_count: usize,
    pub condition_count: usize,
    pub total_sleep_sec: u64,
    pub output_format: String,
    pub preview_line: String,
    pub stop_on_error: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatedWorkflow {
    pub root: Value,
    pub normalized_json: String,
    pub summary: WorkflowSummary,
}

#[derive(Debug, Clone)]
pub struct WorkflowTargetInfo {
    pub ip: String,
    pub port: u16,
    pub user: String,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct StepExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone)]
pub struct WorkflowExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub executed_steps: usize,
    pub commands_run: Vec<String>,
}

#[derive(Debug, Clone)]
struct StepRecord {
    id: String,
    exit_code: i32,
    ok: bool,
    stdout: String,
    raw_stdout: String,
    stderr: String,
    lines_count: usize,
    silent: bool,
}

struct WorkflowContext {
    target: WorkflowTargetInfo,
    vars: HashMap<String, String>,
    steps: HashMap<String, StepRecord>,
    step_order: Vec<StepRecord>,
    last: Option<StepRecord>,
    logs: Vec<String>,
    stderr_parts: Vec<String>,
    executed_count: usize,
    stopped: bool,
    final_exit_code: i32,
    commands_run: Vec<String>,
}

struct Counters {
    step_count: usize,
    run_count: usize,
    condition_count: usize,
    total_sleep_sec: u64,
}

fn validate_regex_str(pattern: &str, case_insensitive: bool, path: &str) -> Result<(), String> {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map(|_| ())
        .map_err(|e| format!("{path}: Ungültiger Regex \"{pattern}\" ({e})."))
}

fn is_valid_ident(s: &str) -> bool {
    if s.is_empty() || s.len() > 48 {
        return false;
    }
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn validate_filter(val: &Value, path: &str) -> Result<(), String> {
    if val.is_null() {
        return Ok(());
    }
    let Some(obj) = val.as_object() else {
        return Err(format!("{path}: filter muss ein JSON-Objekt sein."));
    };
    let ci = obj
        .get("caseInsensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(inc) = obj.get("include").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        validate_regex_str(inc, ci, &format!("{path}.include"))?;
    }
    if let Some(exc) = obj.get("exclude").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        validate_regex_str(exc, ci, &format!("{path}.exclude"))?;
    }
    if let Some(re) = obj.get("regex").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        validate_regex_str(re, ci, &format!("{path}.regex"))?;
    }
    if let Some(g) = obj.get("regexGroup") {
        let Some(n) = g.as_i64() else {
            return Err(format!("{path}.regexGroup muss eine Zahl zwischen 0 und 20 sein."));
        };
        if !(0..=20).contains(&n) {
            return Err(format!("{path}.regexGroup muss eine Zahl zwischen 0 und 20 sein."));
        }
    }
    if let Some(rep) = obj.get("replace") {
        let Some(arr) = rep.as_array() else {
            return Err(format!("{path}.replace muss ein Array sein."));
        };
        for (idx, item) in arr.iter().enumerate() {
            let Some(ro) = item.as_object() else {
                return Err(format!("{path}.replace[{idx}]: Muss ein Objekt sein."));
            };
            let pat = ro.get("pattern").and_then(Value::as_str).unwrap_or("");
            if pat.is_empty() {
                return Err(format!("{path}.replace[{idx}]: pattern (String) ist erforderlich."));
            }
            let flags = ro.get("flags").and_then(Value::as_str).unwrap_or("g");
            validate_regex_str(pat, flags.contains('i'), &format!("{path}.replace[{idx}]"))?;
        }
    }
    if let Some(cols) = obj.get("columns") {
        let Some(arr) = cols.as_array() else {
            return Err(format!("{path}.columns muss ein Zahlen-Array (1-basiert) sein."));
        };
        for c in arr {
            let Some(n) = c.as_i64() else {
                return Err(format!("{path}.columns enthält ungültige Spaltennummer."));
            };
            if !(1..=100).contains(&n) {
                return Err(format!("{path}.columns enthält ungültige Spaltennummer ({n})."));
            }
        }
    }
    if let Some(delim) = obj.get("delimiter").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        validate_regex_str(delim, false, &format!("{path}.delimiter"))?;
    }
    if let Some(h) = obj.get("head") {
        if h.as_i64().unwrap_or(0) < 1 {
            return Err(format!("{path}.head muss >= 1 sein."));
        }
    }
    if let Some(t) = obj.get("tail") {
        if t.as_i64().unwrap_or(0) < 1 {
            return Err(format!("{path}.tail muss >= 1 sein."));
        }
    }
    Ok(())
}

fn validate_condition(val: &Value, path: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "{path}: Maximale Verschachtelungstiefe ({MAX_DEPTH}) überschritten."
        ));
    }
    let Some(obj) = val.as_object() else {
        return Err(format!("{path}: Bedingung (when) muss ein JSON-Objekt sein."));
    };

    if obj.contains_key("all") || obj.contains_key("any") || obj.contains_key("not") {
        if let Some(all_v) = obj.get("all") {
            let Some(arr) = all_v.as_array().filter(|a| !a.is_empty()) else {
                return Err(format!("{path}.all muss ein nicht-leeres Array sein."));
            };
            for (i, item) in arr.iter().enumerate() {
                validate_condition(item, &format!("{path}.all[{i}]"), depth + 1)?;
            }
        }
        if let Some(any_v) = obj.get("any") {
            let Some(arr) = any_v.as_array().filter(|a| !a.is_empty()) else {
                return Err(format!("{path}.any muss ein nicht-leeres Array sein."));
            };
            for (i, item) in arr.iter().enumerate() {
                validate_condition(item, &format!("{path}.any[{i}]"), depth + 1)?;
            }
        }
        if let Some(not_v) = obj.get("not") {
            validate_condition(not_v, &format!("{path}.not"), depth + 1)?;
        }
        return Ok(());
    }

    let op = obj.get("op").and_then(Value::as_str).unwrap_or("").trim();
    const VALID_OPS: &[&str] = &[
        "equals",
        "==",
        "notEquals",
        "!=",
        "contains",
        "notContains",
        "startsWith",
        "endsWith",
        "matches",
        "notMatches",
        "isEmpty",
        "isNotEmpty",
        "gt",
        ">",
        "gte",
        ">=",
        "lt",
        "<",
        "lte",
        "<=",
    ];
    if !VALID_OPS.contains(&op) {
        return Err(format!(
            "{path}.op: Unbekannter Operator \"{op}\". Erlaubt: equals, notEquals, contains, notContains, startsWith, endsWith, matches, notMatches, isEmpty, isNotEmpty, gt, gte, lt, lte."
        ));
    }

    let field = obj
        .get("field")
        .and_then(Value::as_str)
        .unwrap_or("stdout")
        .trim();
    const VALID_FIELDS: &[&str] = &["stdout", "rawStdout", "stderr", "exitCode", "ok", "linesCount"];
    if !VALID_FIELDS.contains(&field) {
        return Err(format!(
            "{path}.field: Ungültiges Feld \"{field}\". Erlaubt: stdout, rawStdout, stderr, exitCode, ok, linesCount."
        ));
    }

    if (op == "matches" || op == "notMatches") && obj.get("value").and_then(Value::as_str).is_some() {
        let pat = obj.get("value").and_then(Value::as_str).unwrap_or("");
        let ci = obj
            .get("caseInsensitive")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        validate_regex_str(pat, ci, &format!("{path}.value"))?;
    }

    Ok(())
}

fn validate_steps(
    val: &Value,
    path: &str,
    depth: usize,
    counters: &mut Counters,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "{path}: Maximale Verschachtelungstiefe ({MAX_DEPTH}) überschritten."
        ));
    }
    let Some(arr) = val.as_array() else {
        return Err(format!("{path} muss ein JSON-Array aus Schritten sein."));
    };
    for (i, item) in arr.iter().enumerate() {
        let p = format!("{path}[{i}]");
        counters.step_count += 1;
        if counters.step_count > MAX_DEFINED_STEPS {
            return Err(format!(
                "Workflow darf maximal {MAX_DEFINED_STEPS} Schritte enthalten."
            ));
        }
        let Some(obj) = item.as_object() else {
            return Err(format!("{p}: Jeder Schritt muss ein JSON-Objekt sein."));
        };
        let step_type = obj.get("type").and_then(Value::as_str).unwrap_or("").trim();
        match step_type {
            "run" => {
                let cmd = obj.get("command").and_then(Value::as_str).unwrap_or("").trim();
                if cmd.is_empty() {
                    return Err(format!(
                        "{p}: \"run\"-Schritt benötigt ein nicht-leeres \"command\"-Feld."
                    ));
                }
                let id_raw = obj
                    .get("id")
                    .or_else(|| obj.get("saveAs"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                if !id_raw.is_empty() && !is_valid_ident(id_raw) {
                    return Err(format!(
                        "{p}.id: Ungültige Schritt-ID \"{id_raw}\" (erlaubt: Buchstaben, Ziffern, _, -)."
                    ));
                }
                let sleep_sec = obj
                    .get("sleepAfterSec")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .min(600);
                if let Some(f) = obj.get("filter") {
                    validate_filter(f, &format!("{p}.filter"))?;
                }
                counters.run_count += 1;
                counters.total_sleep_sec = counters.total_sleep_sec.saturating_add(sleep_sec);
            }
            "sleep" => {
                let Some(sec) = obj.get("seconds").and_then(Value::as_u64) else {
                    return Err(format!("{p}.seconds: Muss eine Zahl zwischen 0 und 600 sein."));
                };
                if sec > 600 {
                    return Err(format!("{p}.seconds: Muss eine Zahl zwischen 0 und 600 sein."));
                }
                counters.total_sleep_sec = counters.total_sleep_sec.saturating_add(sec);
            }
            "if" => {
                let Some(when_v) = obj.get("when") else {
                    return Err(format!("{p}.when: Bedingung fehlt."));
                };
                validate_condition(when_v, &format!("{p}.when"), depth + 1)?;
                let Some(then_v) = obj.get("then") else {
                    return Err(format!(
                        "{p}.then: Ein \"if\"-Schritt benötigt mindestens einen Schritt in \"then\"."
                    ));
                };
                if then_v.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                    return Err(format!(
                        "{p}.then: Ein \"if\"-Schritt benötigt mindestens einen Schritt in \"then\"."
                    ));
                }
                validate_steps(then_v, &format!("{p}.then"), depth + 1, counters)?;
                if let Some(else_v) = obj.get("else").filter(|v| !v.is_null()) {
                    validate_steps(else_v, &format!("{p}.else"), depth + 1, counters)?;
                }
                counters.condition_count += 1;
            }
            "set" => {
                let name = obj.get("name").and_then(Value::as_str).unwrap_or("").trim();
                if !is_valid_ident(name) {
                    return Err(format!("{p}.name: Ungültiger Variablenname \"{name}\"."));
                }
                if let Some(f) = obj.get("filter") {
                    validate_filter(f, &format!("{p}.filter"))?;
                }
            }
            "log" | "stop" | "fail" => {}
            other => {
                return Err(format!(
                    "{p}.type: Unbekannter Schritt-Typ \"{other}\". Erlaubt: run, sleep, if, set, log, stop, fail."
                ));
            }
        }
    }
    Ok(())
}

pub fn parse_and_validate_workflow(raw_json: &str) -> Result<ValidatedWorkflow, String> {
    let trimmed = raw_json.trim();
    if trimmed.is_empty() {
        return Err("Bitte geben Sie eine JSON-Workflow-Definition ein.".into());
    }
    let parsed: Value = serde_json::from_str(trimmed)
        .map_err(|e| format!("Ungültiges JSON: {e}"))?;

    let root = if parsed.is_array() {
        let mut map = Map::new();
        map.insert("stopOnError".into(), Value::Bool(true));
        map.insert("steps".into(), parsed);
        Value::Object(map)
    } else if parsed.is_object() {
        parsed
    } else {
        return Err("Der JSON-Workflow muss ein JSON-Objekt oder ein Array aus Schritten sein.".into());
    };

    let obj = root.as_object().ok_or("Ungültiges JSON-Objekt.")?;
    let Some(steps_val) = obj.get("steps") else {
        return Err("Der JSON-Workflow benötigt ein nicht-leeres \"steps\"-Array.".into());
    };
    if steps_val.as_array().map(|a| a.is_empty()).unwrap_or(true) {
        return Err("Der JSON-Workflow benötigt ein nicht-leeres \"steps\"-Array.".into());
    }

    let mut counters = Counters {
        step_count: 0,
        run_count: 0,
        condition_count: 0,
        total_sleep_sec: 0,
    };
    validate_steps(steps_val, "steps", 0, &mut counters)?;
    if counters.run_count == 0 {
        return Err(
            "Der JSON-Workflow muss mindestens einen \"run\"-Schritt mit einem SSH-Befehl enthalten."
                .into(),
        );
    }

    if let Some(vars_v) = obj.get("vars").filter(|v| !v.is_null()) {
        if !vars_v.is_object() {
            return Err("\"vars\" muss ein JSON-Objekt aus Schlüssel-Wert-Paaren sein.".into());
        }
    }

    let mut output_format = "default".to_string();
    if let Some(out_v) = obj.get("output").filter(|v| !v.is_null()) {
        let Some(out_obj) = out_v.as_object() else {
            return Err("\"output\" muss ein JSON-Objekt sein.".into());
        };
        let fmt = out_obj
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("text")
            .trim();
        if !matches!(fmt, "text" | "template" | "table" | "json" | "lines") {
            return Err(format!(
                "output.format \"{fmt}\" ist ungültig. Erlaubt: text, template, table, json, lines."
            ));
        }
        output_format = fmt.to_string();
        if let Some(f) = out_obj.get("filter") {
            validate_filter(f, "output.filter")?;
        }
        if let Some(delim) = out_obj
            .get("delimiter")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            validate_regex_str(delim, false, "output.delimiter")?;
        }
    }

    let stop_on_error = obj
        .get("stopOnError")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let mut summary_parts = vec![format!("{} SSH", counters.run_count)];
    if counters.condition_count > 0 {
        summary_parts.push(format!("{} if", counters.condition_count));
    }
    if counters.total_sleep_sec > 0 {
        summary_parts.push(format!("{}s sleep", counters.total_sleep_sec));
    }
    if output_format != "default" {
        summary_parts.push(format!("output:{output_format}"));
    }
    let preview_line = format!("JSON-Workflow ({})", summary_parts.join(" · "));

    let normalized_json = serde_json::to_string_pretty(&root).unwrap_or_else(|_| trimmed.to_string());

    Ok(ValidatedWorkflow {
        root,
        normalized_json,
        summary: WorkflowSummary {
            step_count: counters.step_count,
            run_count: counters.run_count,
            condition_count: counters.condition_count,
            total_sleep_sec: counters.total_sleep_sec,
            output_format,
            preview_line,
            stop_on_error,
        },
    })
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn apply_output_filter(input: &str, filter: Option<&Value>) -> String {
    let Some(f_obj) = filter.and_then(Value::as_object) else {
        return input.to_string();
    };

    let mut text = input.replace("\r\n", "\n");
    let trim_flag = f_obj.get("trim").and_then(Value::as_bool).unwrap_or(false);
    if trim_flag {
        text = text.trim().to_string();
    }

    if let Some(rules) = f_obj.get("replace").and_then(Value::as_array) {
        for r in rules {
            if let Some(ro) = r.as_object() {
                let pat = ro.get("pattern").and_then(Value::as_str).unwrap_or("");
                let with = ro.get("with").map(value_to_string).unwrap_or_default();
                let flags = ro.get("flags").and_then(Value::as_str).unwrap_or("g");
                if !pat.is_empty() {
                    if let Ok(re) = RegexBuilder::new(pat)
                        .case_insensitive(flags.contains('i'))
                        .multi_line(flags.contains('m'))
                        .dot_matches_new_line(flags.contains('s'))
                        .build()
                    {
                        if flags.contains('g') {
                            text = re.replace_all(&text, with.as_str()).to_string();
                        } else {
                            text = re.replace(&text, with.as_str()).to_string();
                        }
                    }
                }
            }
        }
    }

    let mut lines: Vec<String> = if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').map(|s| s.to_string()).collect()
    };

    let ci = f_obj
        .get("caseInsensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let drop_empty = f_obj
        .get("dropEmpty")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if drop_empty {
        lines.retain(|l| !l.trim().is_empty());
    }

    if let Some(inc) = f_obj.get("include").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        if let Ok(re) = RegexBuilder::new(inc).case_insensitive(ci).build() {
            lines.retain(|l| re.is_match(l));
        }
    }

    if let Some(exc) = f_obj.get("exclude").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        if let Ok(re) = RegexBuilder::new(exc).case_insensitive(ci).build() {
            lines.retain(|l| !re.is_match(l));
        }
    }

    if let Some(pat) = f_obj.get("regex").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        let group_idx = f_obj.get("regexGroup").and_then(Value::as_u64).unwrap_or(0) as usize;
        let regex_all = f_obj.get("regexAll").and_then(Value::as_bool).unwrap_or(false);
        if let Ok(re) = RegexBuilder::new(pat).case_insensitive(ci).build() {
            let mut extracted = Vec::new();
            for line in &lines {
                if regex_all {
                    for caps in re.captures_iter(line) {
                        if let Some(m) = caps.get(group_idx).or_else(|| caps.get(0)) {
                            extracted.push(m.as_str().to_string());
                        }
                    }
                } else if let Some(caps) = re.captures(line) {
                    if let Some(m) = caps.get(group_idx).or_else(|| caps.get(0)) {
                        extracted.push(m.as_str().to_string());
                    }
                }
            }
            lines = extracted;
        }
    }

    if let Some(cols_arr) = f_obj.get("columns").and_then(Value::as_array) {
        let cols: Vec<usize> = cols_arr
            .iter()
            .filter_map(Value::as_u64)
            .filter(|n| *n >= 1)
            .map(|n| n as usize)
            .collect();
        if !cols.is_empty() {
            let delim_pat = f_obj
                .get("delimiter")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(r"\s+");
            let joiner = f_obj.get("columnJoin").and_then(Value::as_str).unwrap_or(" ");
            if let Ok(delim_re) = RegexBuilder::new(delim_pat).build() {
                lines = lines
                    .into_iter()
                    .map(|line| {
                        let parts: Vec<&str> = delim_re.split(line.trim()).collect();
                        cols.iter()
                            .map(|c| parts.get(c.saturating_sub(1)).copied().unwrap_or(""))
                            .collect::<Vec<_>>()
                            .join(joiner)
                            .trim()
                            .to_string()
                    })
                    .collect();
            }
        }
    }

    if drop_empty {
        lines.retain(|l| !l.trim().is_empty());
    }

    if f_obj.get("sort").and_then(Value::as_bool).unwrap_or(false) {
        lines.sort();
    }

    if f_obj.get("unique").and_then(Value::as_bool).unwrap_or(false) {
        let mut seen = HashSet::new();
        lines.retain(|l| seen.insert(l.clone()));
    }

    if let Some(h) = f_obj.get("head").and_then(Value::as_u64).filter(|n| *n > 0) {
        lines.truncate(h as usize);
    }

    if let Some(t) = f_obj.get("tail").and_then(Value::as_u64).filter(|n| *n > 0) {
        let keep = t as usize;
        if lines.len() > keep {
            lines = lines.split_off(lines.len() - keep);
        }
    }

    let pre = f_obj.get("prefix").and_then(Value::as_str).unwrap_or("");
    let suf = f_obj.get("suffix").and_then(Value::as_str).unwrap_or("");
    if !pre.is_empty() || !suf.is_empty() {
        lines = lines
            .into_iter()
            .map(|l| format!("{pre}{l}{suf}"))
            .collect();
    }

    let join_with = f_obj.get("joinWith").and_then(Value::as_str).unwrap_or("\n");
    let joined = lines.join(join_with);
    if trim_flag {
        joined.trim().to_string()
    } else {
        joined
    }
}

fn resolve_path(path_str: &str, ctx: &WorkflowContext) -> String {
    let key = path_str.trim();
    if key.is_empty() {
        return String::new();
    }
    match key {
        "target.ip" => return ctx.target.ip.clone(),
        "target.port" => return ctx.target.port.to_string(),
        "target.user" => return ctx.target.user.clone(),
        "target.label" => return ctx.target.label.clone(),
        _ => {}
    }
    if let Some(var_name) = key.strip_prefix("vars.") {
        return ctx.vars.get(var_name).cloned().unwrap_or_default();
    }
    let normalized = key.strip_prefix("steps.").unwrap_or(key);
    if let Some((target_id, field)) = normalized.split_once('.') {
        let rec_opt = if target_id == "last" {
            ctx.last.as_ref()
        } else {
            ctx.steps.get(target_id)
        };
        if let Some(rec) = rec_opt {
            return match field {
                "stdout" | "filtered" => rec.stdout.clone(),
                "rawStdout" => rec.raw_stdout.clone(),
                "stderr" => rec.stderr.clone(),
                "exitCode" => rec.exit_code.to_string(),
                "ok" => if rec.ok { "true" } else { "false" }.to_string(),
                "linesCount" => rec.lines_count.to_string(),
                _ => String::new(),
            };
        }
        return String::new();
    }
    if let Some(v) = ctx.vars.get(key) {
        return v.clone();
    }
    if let Some(rec) = ctx.steps.get(key) {
        return rec.stdout.clone();
    }
    String::new()
}

fn interpolate_template(template: &str, ctx: &WorkflowContext) -> String {
    let Ok(re) = RegexBuilder::new(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}").build() else {
        return template.to_string();
    };
    re.replace_all(template, |caps: &regex::Captures<'_>| {
        let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        resolve_path(expr, ctx)
    })
    .to_string()
}

fn parse_numeric(s: &str) -> Option<f64> {
    let re = RegexBuilder::new(r"-?\d+(?:[.,]\d+)?").build().ok()?;
    let m = re.find(s.trim())?;
    m.as_str().replace(',', ".").parse::<f64>().ok()
}

fn evaluate_condition(cond: &Value, ctx: &WorkflowContext) -> bool {
    let Some(obj) = cond.as_object() else {
        return false;
    };
    if obj.contains_key("all") || obj.contains_key("any") || obj.contains_key("not") {
        if let Some(arr) = obj.get("all").and_then(Value::as_array) {
            if !arr.iter().all(|c| evaluate_condition(c, ctx)) {
                return false;
            }
        }
        if let Some(arr) = obj.get("any").and_then(Value::as_array) {
            if !arr.iter().any(|c| evaluate_condition(c, ctx)) {
                return false;
            }
        }
        if let Some(not_v) = obj.get("not") {
            if evaluate_condition(not_v, ctx) {
                return false;
            }
        }
        return true;
    }

    let from = obj
        .get("from")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("last");
    let field = obj
        .get("field")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("stdout");

    let actual_str = if let Some(vn) = from.strip_prefix("vars.") {
        ctx.vars.get(vn).cloned().unwrap_or_default()
    } else if from.starts_with("target.") {
        resolve_path(from, ctx)
    } else if ctx.vars.contains_key(from) && !ctx.steps.contains_key(from) && from != "last" {
        ctx.vars.get(from).cloned().unwrap_or_default()
    } else {
        let rec_opt = if from == "last" {
            ctx.last.as_ref()
        } else {
            ctx.steps.get(from)
        };
        if let Some(rec) = rec_opt {
            match field {
                "stdout" => rec.stdout.clone(),
                "rawStdout" => rec.raw_stdout.clone(),
                "stderr" => rec.stderr.clone(),
                "exitCode" => rec.exit_code.to_string(),
                "ok" => if rec.ok { "true" } else { "false" }.to_string(),
                "linesCount" => rec.lines_count.to_string(),
                _ => String::new(),
            }
        } else {
            String::new()
        }
    };

    let expected_raw = match obj.get("value") {
        Some(Value::String(s)) => interpolate_template(s, ctx),
        Some(other) => value_to_string(other),
        None => String::new(),
    };
    let ci = obj
        .get("caseInsensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let lhs = if ci {
        actual_str.to_lowercase()
    } else {
        actual_str.clone()
    };
    let rhs = if ci {
        expected_raw.to_lowercase()
    } else {
        expected_raw.clone()
    };

    let op = obj.get("op").and_then(Value::as_str).unwrap_or("").trim();
    match op {
        "equals" | "==" => lhs.trim() == rhs.trim(),
        "notEquals" | "!=" => lhs.trim() != rhs.trim(),
        "contains" => lhs.contains(&rhs),
        "notContains" => !lhs.contains(&rhs),
        "startsWith" => lhs.trim().starts_with(&rhs),
        "endsWith" => lhs.trim().ends_with(&rhs),
        "matches" => RegexBuilder::new(&expected_raw)
            .case_insensitive(ci)
            .build()
            .map(|re| re.is_match(&actual_str))
            .unwrap_or(false),
        "notMatches" => RegexBuilder::new(&expected_raw)
            .case_insensitive(ci)
            .build()
            .map(|re| !re.is_match(&actual_str))
            .unwrap_or(false),
        "isEmpty" => actual_str.trim().is_empty(),
        "isNotEmpty" => !actual_str.trim().is_empty(),
        "gt" | ">" => match (parse_numeric(&actual_str), parse_numeric(&expected_raw)) {
            (Some(a), Some(b)) => a > b,
            _ => false,
        },
        "gte" | ">=" => match (parse_numeric(&actual_str), parse_numeric(&expected_raw)) {
            (Some(a), Some(b)) => a >= b,
            _ => false,
        },
        "lt" | "<" => match (parse_numeric(&actual_str), parse_numeric(&expected_raw)) {
            (Some(a), Some(b)) => a < b,
            _ => false,
        },
        "lte" | "<=" => match (parse_numeric(&actual_str), parse_numeric(&expected_raw)) {
            (Some(a), Some(b)) => a <= b,
            _ => false,
        },
        _ => false,
    }
}

fn render_ascii_table(headers: &[String], rows: &[Vec<String>]) -> String {
    let mut col_count = headers.len();
    for r in rows {
        col_count = col_count.max(r.len());
    }
    if col_count == 0 {
        return String::new();
    }
    let mut widths = vec![1usize; col_count];
    for (i, h) in headers.iter().enumerate() {
        widths[i] = widths[i].max(h.chars().count());
    }
    for r in rows {
        for (i, cell) in r.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let fmt_row = |cells: &[String]| -> String {
        widths
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let s = cells.get(i).map(|v| v.as_str()).unwrap_or("");
                let pad = w.saturating_sub(s.chars().count());
                format!("{s}{}", " ".repeat(pad))
            })
            .collect::<Vec<_>>()
            .join(" | ")
    };

    let mut out = Vec::new();
    if !headers.is_empty() {
        out.push(fmt_row(headers));
        out.push(
            widths
                .iter()
                .map(|w| "-".repeat(*w))
                .collect::<Vec<_>>()
                .join("-+-"),
        );
    }
    for r in rows {
        out.push(fmt_row(r));
    }
    out.join("\n")
}

fn format_workflow_output(root: &Value, ctx: &WorkflowContext) -> String {
    let Some(out_obj) = root.get("output").and_then(Value::as_object) else {
        let mut parts = Vec::new();
        for rec in &ctx.step_order {
            if !rec.silent && !rec.stdout.trim().is_empty() {
                parts.push(rec.stdout.trim_end().to_string());
            }
        }
        for line in &ctx.logs {
            parts.push(line.clone());
        }
        return parts.join("\n");
    };

    let fmt = out_obj
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("text");

    if fmt == "template" || fmt == "text" {
        let rendered = if let Some(tpl) = out_obj.get("template").and_then(Value::as_str) {
            interpolate_template(tpl, ctx)
        } else if let Some(arr) = out_obj.get("lines").and_then(Value::as_array) {
            arr.iter()
                .map(|l| interpolate_template(&value_to_string(l), ctx))
                .collect::<Vec<_>>()
                .join("\n")
        } else if let Some(src) = out_obj.get("source").and_then(Value::as_str) {
            resolve_path(&format!("{src}.stdout"), ctx)
        } else {
            ctx.logs.join("\n")
        };
        return apply_output_filter(&rendered, out_obj.get("filter"));
    }

    if fmt == "json" {
        let auto_type = out_obj
            .get("autoType")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let mut map = Map::new();
        if let Some(fields) = out_obj.get("fields").and_then(Value::as_object) {
            for (k, v) in fields {
                if let Some(s) = v.as_str() {
                    let interp = interpolate_template(s, ctx);
                    if auto_type {
                        let t = interp.trim();
                        if t == "true" {
                            map.insert(k.clone(), Value::Bool(true));
                        } else if t == "false" {
                            map.insert(k.clone(), Value::Bool(false));
                        } else if let Ok(n) = t.parse::<i64>() {
                            map.insert(k.clone(), Value::Number(n.into()));
                        } else if let Ok(f) = t.parse::<f64>() {
                            if let Some(num) = serde_json::Number::from_f64(f) {
                                map.insert(k.clone(), Value::Number(num));
                            } else {
                                map.insert(k.clone(), Value::String(interp));
                            }
                        } else {
                            map.insert(k.clone(), Value::String(interp));
                        }
                    } else {
                        map.insert(k.clone(), Value::String(interp));
                    }
                } else {
                    map.insert(k.clone(), v.clone());
                }
            }
        } else {
            let mut steps_map = Map::new();
            for (id, rec) in &ctx.steps {
                let mut sm = Map::new();
                sm.insert("exitCode".into(), Value::Number(rec.exit_code.into()));
                sm.insert("ok".into(), Value::Bool(rec.ok));
                sm.insert("stdout".into(), Value::String(rec.stdout.clone()));
                steps_map.insert(id.clone(), Value::Object(sm));
            }
            map.insert(
                "target".into(),
                serde_json::json!({
                    "ip": ctx.target.ip,
                    "port": ctx.target.port,
                    "user": ctx.target.user,
                    "label": ctx.target.label,
                }),
            );
            map.insert("vars".into(), serde_json::json!(ctx.vars));
            map.insert("steps".into(), Value::Object(steps_map));
            if !ctx.logs.is_empty() {
                map.insert("logs".into(), serde_json::json!(ctx.logs));
            }
        }
        let json_text = serde_json::to_string_pretty(&Value::Object(map)).unwrap_or_default();
        return apply_output_filter(&json_text, out_obj.get("filter"));
    }

    if fmt == "table" {
        let headers: Vec<String> = out_obj
            .get("headers")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(value_to_string).collect())
            .unwrap_or_default();

        if let Some(rows_arr) = out_obj.get("rows").and_then(Value::as_array).filter(|a| !a.is_empty()) {
            let eff_headers = if headers.len() >= 2 {
                headers
            } else {
                vec!["Feld".into(), "Wert".into()]
            };
            let rows: Vec<Vec<String>> = rows_arr
                .iter()
                .filter_map(Value::as_object)
                .map(|r| {
                    let lbl = interpolate_template(
                        r.get("label").and_then(Value::as_str).unwrap_or(""),
                        ctx,
                    );
                    let val = interpolate_template(
                        r.get("value").and_then(Value::as_str).unwrap_or(""),
                        ctx,
                    )
                    .lines()
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join(" / ");
                    vec![lbl, val]
                })
                .collect();
            return render_ascii_table(&eff_headers, &rows);
        }

        if let Some(fields) = out_obj
            .get("fields")
            .and_then(Value::as_object)
            .filter(|m| !m.is_empty())
        {
            let eff_headers = if headers.len() >= 2 {
                headers
            } else {
                vec!["Feld".into(), "Wert".into()]
            };
            let rows: Vec<Vec<String>> = fields
                .iter()
                .map(|(k, v)| {
                    let val = interpolate_template(&value_to_string(v), ctx)
                        .lines()
                        .map(str::trim)
                        .collect::<Vec<_>>()
                        .join(" / ");
                    vec![k.clone(), val]
                })
                .collect();
            return render_ascii_table(&eff_headers, &rows);
        }

        let src = if let Some(s) = out_obj.get("source").and_then(Value::as_str) {
            resolve_path(&format!("{s}.stdout"), ctx)
        } else {
            ctx.last
                .as_ref()
                .map(|r| r.stdout.clone())
                .unwrap_or_default()
        };
        let filtered = apply_output_filter(&src, out_obj.get("filter"));
        let delim_pat = out_obj
            .get("delimiter")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(r"\s+");
        let cols: Vec<usize> = out_obj
            .get("columns")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_u64)
                    .filter(|n| *n >= 1)
                    .map(|n| n as usize)
                    .collect()
            })
            .unwrap_or_default();
        let delim_re = RegexBuilder::new(delim_pat)
            .build()
            .unwrap_or_else(|_| RegexBuilder::new(r"\s+").build().unwrap());
        let rows: Vec<Vec<String>> = filtered
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|line| {
                let parts: Vec<&str> = delim_re.split(line).collect();
                if !cols.is_empty() {
                    cols.iter()
                        .map(|c| parts.get(c.saturating_sub(1)).copied().unwrap_or("").to_string())
                        .collect()
                } else {
                    parts.into_iter().map(|s| s.to_string()).collect()
                }
            })
            .collect();
        return render_ascii_table(&headers, &rows);
    }

    // format == "lines"
    let raw = match out_obj.get("source").and_then(Value::as_str) {
        Some(s) if !s.is_empty() && s != "all" => resolve_path(&format!("{s}.stdout"), ctx),
        _ => {
            let mut parts: Vec<String> = ctx
                .step_order
                .iter()
                .filter(|r| !r.silent && !r.stdout.trim().is_empty())
                .map(|r| r.stdout.trim_end().to_string())
                .collect();
            parts.extend(ctx.logs.iter().cloned());
            parts.join("\n")
        }
    };

    let mut filter_map = out_obj
        .get("filter")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(jw) = out_obj.get("joinWith") {
        filter_map.insert("joinWith".into(), jw.clone());
    }
    apply_output_filter(&raw, Some(&Value::Object(filter_map)))
}

type RemoteRunner<'a> =
    &'a (dyn Fn(String, Duration) -> Pin<Box<dyn Future<Output = Result<StepExecOutput, String>> + Send>>
         + Send
         + Sync);

fn run_block<'a>(
    steps: &'a [Value],
    default_stop_on_error: bool,
    started: Instant,
    total_budget: Duration,
    timeout_sec: u64,
    ctx: &'a mut WorkflowContext,
    runner: RemoteRunner<'a>,
) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        for step in steps {
            if ctx.stopped {
                return Ok(());
            }
            if ctx.executed_count >= MAX_EXECUTED_STEPS {
                ctx.stderr_parts.push(format!(
                    "Workflow abgebrochen: Maximale Schrittanzahl ({MAX_EXECUTED_STEPS}) erreicht."
                ));
                ctx.final_exit_code = 125;
                ctx.stopped = true;
                return Ok(());
            }
            let elapsed = started.elapsed();
            if elapsed + Duration::from_millis(250) >= total_budget {
                ctx.stderr_parts.push(format!(
                    "Workflow nach {timeout_sec} Sekunden abgebrochen (Timeout)."
                ));
                ctx.final_exit_code = 124;
                ctx.stopped = true;
                return Ok(());
            }
            let rem = total_budget.saturating_sub(elapsed);

            ctx.executed_count += 1;
            let Some(obj) = step.as_object() else {
                continue;
            };
            let step_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
            match step_type {
                "run" => {
                    let raw_cmd = obj.get("command").and_then(Value::as_str).unwrap_or("");
                    let rendered_cmd = interpolate_template(raw_cmd, ctx);
                    ctx.commands_run.push(rendered_cmd.clone());

                    let res = runner(rendered_cmd.clone(), rem).await?;
                    let raw_stdout = res.stdout.replace("\r\n", "\n");
                    let filtered_stdout = apply_output_filter(&raw_stdout, obj.get("filter"));
                    let lines_count = if filtered_stdout.trim().is_empty() {
                        0
                    } else {
                        filtered_stdout.trim().split('\n').count()
                    };
                    let step_id = obj
                        .get("id")
                        .or_else(|| obj.get("saveAs"))
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("step_{}", ctx.step_order.len() + 1));

                    let record = StepRecord {
                        id: step_id.clone(),
                        exit_code: res.exit_code,
                        ok: res.exit_code == 0,
                        stdout: filtered_stdout,
                        raw_stdout,
                        stderr: res.stderr.clone(),
                        lines_count,
                        silent: obj.get("silent").and_then(Value::as_bool).unwrap_or(false),
                    };
                    ctx.steps.insert(step_id.clone(), record.clone());
                    ctx.step_order.push(record.clone());
                    ctx.last = Some(record);

                    if !res.stderr.trim().is_empty() {
                        ctx.stderr_parts
                            .push(format!("[{step_id}] {}", res.stderr.trim()));
                    }

                    let should_stop = match obj.get("continueOnError").and_then(Value::as_bool) {
                        Some(cont) => !cont,
                        None => default_stop_on_error,
                    };
                    if res.exit_code != 0 && should_stop {
                        ctx.final_exit_code = res.exit_code;
                        ctx.stopped = true;
                        return Ok(());
                    }

                    let sleep_after = obj
                        .get("sleepAfterSec")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .min(600);
                    if sleep_after > 0 {
                        let rem_now = total_budget.saturating_sub(started.elapsed());
                        let wait = Duration::from_secs(sleep_after).min(rem_now);
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                    }
                }
                "sleep" => {
                    let secs = obj
                        .get("seconds")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                        .min(600);
                    if secs > 0 {
                        let rem_now = total_budget.saturating_sub(started.elapsed());
                        let wait = Duration::from_secs(secs).min(rem_now);
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                    }
                }
                "if" => {
                    let matched = obj
                        .get("when")
                        .map(|w| evaluate_condition(w, ctx))
                        .unwrap_or(false);
                    if matched {
                        if let Some(then_steps) = obj.get("then").and_then(Value::as_array) {
                            run_block(
                                then_steps,
                                default_stop_on_error,
                                started,
                                total_budget,
                                timeout_sec,
                                ctx,
                                runner,
                            )
                            .await?;
                        }
                    } else if let Some(else_steps) = obj.get("else").and_then(Value::as_array) {
                        run_block(
                            else_steps,
                            default_stop_on_error,
                            started,
                            total_budget,
                            timeout_sec,
                            ctx,
                            runner,
                        )
                        .await?;
                    }
                }
                "set" => {
                    let name = obj
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim();
                    let raw_val = obj.get("value").map(value_to_string).unwrap_or_default();
                    let interp = interpolate_template(&raw_val, ctx);
                    let filtered = apply_output_filter(&interp, obj.get("filter"));
                    if !name.is_empty() {
                        ctx.vars.insert(name.to_string(), filtered);
                    }
                }
                "log" => {
                    let msg = obj.get("message").map(value_to_string).unwrap_or_default();
                    ctx.logs.push(interpolate_template(&msg, ctx));
                }
                "stop" | "fail" => {
                    let default_code = if step_type == "fail" { 1 } else { 0 };
                    let code = obj
                        .get("exitCode")
                        .and_then(Value::as_i64)
                        .unwrap_or(default_code)
                        .clamp(0, 255) as i32;
                    if let Some(m) = obj.get("message").and_then(Value::as_str) {
                        let rendered = interpolate_template(m, ctx);
                        if step_type == "fail" {
                            ctx.stderr_parts.push(rendered);
                        } else {
                            ctx.logs.push(rendered);
                        }
                    }
                    ctx.final_exit_code = code;
                    ctx.stopped = true;
                    return Ok(());
                }
                _ => {}
            }
        }
        Ok(())
    })
}

pub async fn execute_workflow<F, Fut>(
    workflow: &ValidatedWorkflow,
    target: WorkflowTargetInfo,
    timeout_sec: u64,
    run_remote: F,
) -> Result<WorkflowExecResult, String>
where
    F: Fn(String, Duration) -> Fut + Send + Sync,
    Fut: Future<Output = Result<StepExecOutput, String>> + Send + 'static,
{
    let started = Instant::now();
    let total_budget = Duration::from_secs(timeout_sec.clamp(5, 3600));

    let mut vars = HashMap::new();
    if let Some(v_obj) = workflow.root.get("vars").and_then(Value::as_object) {
        for (k, v) in v_obj {
            vars.insert(k.clone(), value_to_string(v));
        }
    }

    let mut ctx = WorkflowContext {
        target,
        vars,
        steps: HashMap::new(),
        step_order: Vec::new(),
        last: None,
        logs: Vec::new(),
        stderr_parts: Vec::new(),
        executed_count: 0,
        stopped: false,
        final_exit_code: 0,
        commands_run: Vec::new(),
    };

    let runner_closure = move |cmd: String, dur: Duration| -> Pin<Box<dyn Future<Output = Result<StepExecOutput, String>> + Send>> {
        Box::pin(run_remote(cmd, dur))
    };

    if let Some(steps) = workflow.root.get("steps").and_then(Value::as_array) {
        run_block(
            steps,
            workflow.summary.stop_on_error,
            started,
            total_budget,
            timeout_sec,
            &mut ctx,
            &runner_closure,
        )
        .await?;
    }

    let stdout = format_workflow_output(&workflow.root, &ctx);
    Ok(WorkflowExecResult {
        exit_code: ctx.final_exit_code,
        stdout,
        stderr: ctx.stderr_parts.join("\n"),
        executed_steps: ctx.executed_count,
        commands_run: ctx.commands_run,
    })
}

pub const DEFAULT_SERVICE_WORKFLOW_JSON: &str = r#"{
  "stopOnError": true,
  "vars": {
    "service": "nginx"
  },
  "steps": [
    {
      "type": "run",
      "id": "check",
      "command": "systemctl is-active {{vars.service}}",
      "continueOnError": true,
      "filter": {
        "trim": true
      }
    },
    {
      "type": "if",
      "when": {
        "from": "check",
        "field": "stdout",
        "op": "notEquals",
        "value": "active"
      },
      "then": [
        {
          "type": "run",
          "id": "restart",
          "command": "systemctl restart {{vars.service}}"
        },
        {
          "type": "sleep",
          "seconds": 3
        },
        {
          "type": "run",
          "id": "verify",
          "command": "systemctl is-active {{vars.service}}",
          "continueOnError": true,
          "filter": {
            "trim": true
          }
        },
        {
          "type": "set",
          "name": "action",
          "value": "Neu gestartet"
        },
        {
          "type": "set",
          "name": "finalState",
          "value": "{{verify.stdout}}"
        }
      ],
      "else": [
        {
          "type": "set",
          "name": "action",
          "value": "Keine Aktion nötig"
        },
        {
          "type": "set",
          "name": "finalState",
          "value": "{{check.stdout}}"
        }
      ]
    }
  ],
  "output": {
    "format": "table",
    "headers": [
      "Eigenschaft",
      "Wert"
    ],
    "rows": [
      {
        "label": "Server",
        "value": "{{target.label}} ({{target.ip}})"
      },
      {
        "label": "Dienst",
        "value": "{{vars.service}}"
      },
      {
        "label": "Vorher",
        "value": "{{check.stdout}} (Exit {{check.exitCode}})"
      },
      {
        "label": "Aktion",
        "value": "{{vars.action}}"
      },
      {
        "label": "Aktueller Status",
        "value": "{{vars.finalState}}"
      }
    ]
  }
}"#;
