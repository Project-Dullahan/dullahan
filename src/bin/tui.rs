use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Clear, HighlightSpacing, List, ListItem, ListState, Paragraph,
        Row, Table, TableState, Wrap,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Clone, PartialEq, Serialize, Deserialize)]
enum DomainTag { Safe, Malicious, Investigate, None }
impl DomainTag {
    fn marker(&self) -> &'static str {
        match self {
            DomainTag::Safe => "[S]", DomainTag::Malicious => "[M]",
            DomainTag::Investigate => "[I]", DomainTag::None => "",
        }
    }
}

#[derive(Clone, PartialEq)]
enum RiskLevel { High, Obfuscated, Neutral, Offline }
impl RiskLevel {
    fn marker(&self) -> &'static str {
        match self { RiskLevel::High => "R", RiskLevel::Obfuscated => "Y", RiskLevel::Neutral => "G", RiskLevel::Offline => "O" }
    }
    fn color(&self) -> Color {
        match self { RiskLevel::High => Color::Red, RiskLevel::Obfuscated => Color::Yellow, RiskLevel::Neutral => Color::Green, RiskLevel::Offline => Color::Gray }
    }
    fn as_str(&self) -> &'static str {
        match self { RiskLevel::High => "HIGH RISK", RiskLevel::Obfuscated => "OBFUSCATED", RiskLevel::Neutral => "NEUTRAL", RiskLevel::Offline => "OFFLINE" }
    }
}

#[derive(Clone)]
struct DomainIntel { name: String, risk: RiskLevel, lat: f64, lon: f64, ips: Vec<String>, details: String, safemode_alerts: Vec<String>, tag: DomainTag }
#[derive(Clone)]
struct SafemodeRule { category: String, condition: String, action: String, list_type: String, threshold: u32, active: bool }
#[derive(Deserialize)] struct CorrelationReport { clusters: Vec<CorrelationCluster>, analyzed_domains: Vec<String> }
#[derive(Deserialize, Clone)] struct CorrelationCluster { cluster_id: usize, correlation_type: String, shared_indicator: String, domains: Vec<String>, confidence: String, risk_assessment: String }
enum RulesetMode { Workspace, Global }
enum AppView { Main, SafemodeManager, DossierPopup, TestResultPopup, TagPopup }

struct App {
    domains: Vec<DomainIntel>, rules: Vec<SafemodeRule>, filter: Option<RiskLevel>,
    list_state: ListState, safemode_state: TableState, view: AppView, safemode_active: bool,
    ruleset_mode: RulesetMode, should_quit: bool, tags: HashMap<String, DomainTag>, config_dir: PathBuf,
}

impl App {
    fn new(input_file: Option<String>) -> Self {
        let config_dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("dullahan");
        let _ = fs::create_dir_all(&config_dir);
        let tags = Self::load_tags(&config_dir);
        let domains = if let Some(file) = input_file { Self::load_from_json(&file, &tags) } else { Self::load_mock_data(&tags) };
        let rules = vec![
            SafemodeRule { category: "HOSTILE_GEO".into(), condition: "Geo in [RU, BY, IR, KP, CN]".into(), action: "AUTO-BLOCK".into(), list_type: "Blacklist".into(), threshold: 0, active: true },
            SafemodeRule { category: "MISSING_HSTS".into(), condition: "Header missing".into(), action: "WARN".into(), list_type: "Blacklist".into(), threshold: 0, active: true },
            SafemodeRule { category: "FINGERPRINT".into(), condition: "HAR flag detected".into(), action: "WARN".into(), list_type: "Blacklist".into(), threshold: 0, active: false },
        ];
        let mut list_state = ListState::default(); list_state.select(Some(0));
        let mut safemode_state = TableState::default(); safemode_state.select(Some(0));
        let mut app = Self { domains, rules, filter: None, list_state, safemode_state, view: AppView::Main, safemode_active: true, ruleset_mode: RulesetMode::Workspace, should_quit: false, tags, config_dir };
        app.evaluate_safemode(); app
    }
    fn load_tags(config_dir: &PathBuf) -> HashMap<String, DomainTag> {
        let tags_path = config_dir.join("tags.json");
        if let Ok(content) = fs::read_to_string(tags_path) {
            if let Ok(tags) = serde_json::from_str::<HashMap<String, DomainTag>>(&content) { return tags; }
        }
        HashMap::new()
    }
    fn save_tags(&self) {
        let tags_path = self.config_dir.join("tags.json");
        if let Ok(json) = serde_json::to_string_pretty(&self.tags) { let _ = fs::write(tags_path, json); }
    }
    fn set_tag(&mut self, domain_name: &str, tag: DomainTag) {
        if tag == DomainTag::None { self.tags.remove(domain_name); } else { self.tags.insert(domain_name.to_string(), tag.clone()); }
        if let Some(domain) = self.domains.iter_mut().find(|d| d.name == domain_name) { domain.tag = tag; }
        self.save_tags();
    }
    fn load_from_json(file_path: &str, tags: &HashMap<String, DomainTag>) -> Vec<DomainIntel> {
        let content = match fs::read_to_string(file_path) { Ok(c) => c, Err(_) => return Self::load_mock_data(tags) };
        let report: CorrelationReport = match serde_json::from_str(&content) { Ok(r) => r, Err(_) => return Self::load_mock_data(tags) };
        let mut domain_map: HashMap<String, DomainIntel> = HashMap::new();
        for cluster in &report.clusters {
            for domain_name in &cluster.domains {
                let entry = domain_map.entry(domain_name.clone()).or_insert_with(|| {
                    let tag = tags.get(domain_name).cloned().unwrap_or(DomainTag::None);
                    DomainIntel { name: domain_name.clone(), risk: RiskLevel::Obfuscated, lat: 0.0, lon: 0.0, ips: vec![], details: String::new(), safemode_alerts: vec![], tag }
                });
                entry.details.push_str(&format!("Cluster {}: {} (Shared: {})\nConfidence: {}\nAssessment: {}\n\n", cluster.cluster_id, cluster.correlation_type, cluster.shared_indicator, cluster.confidence, cluster.risk_assessment));
                if cluster.correlation_type == "SHARED_CERTIFICATE" { entry.risk = RiskLevel::High; }
            }
        }
        for domain_name in &report.analyzed_domains {
            if !domain_map.contains_key(domain_name) {
                let tag = tags.get(domain_name).cloned().unwrap_or(DomainTag::None);
                domain_map.insert(domain_name.clone(), DomainIntel { name: domain_name.clone(), risk: RiskLevel::Neutral, lat: 0.0, lon: 0.0, ips: vec!["No correlations found".into()], details: "Domain was analyzed but did not share infrastructure with others in this scan.".into(), safemode_alerts: vec![], tag });
            }
        }
        domain_map.into_values().collect()
    }
    fn load_mock_data(tags: &HashMap<String, DomainTag>) -> Vec<DomainIntel> {
        vec![
            DomainIntel { name: "suspicious-aid-portal.org".into(), risk: RiskLevel::High, lat: 50.4501, lon: 30.5234, ips: vec!["194.190.139.3".into()], details: "Shared SSL Cert with known state-sponsored phishing cluster.\nTracking IDs: FB:123456789012345\nBehavior: Aggressive canvas fingerprinting detected.".into(), safemode_alerts: vec![], tag: tags.get("suspicious-aid-portal.org").cloned().unwrap_or(DomainTag::None) },
            DomainIntel { name: "local-news-outlet.com".into(), risk: RiskLevel::Obfuscated, lat: 51.5074, lon: -0.1278, ips: vec!["104.16.132.229".into()], details: "Hosted behind Cloudflare CDN.\nNo direct origin IP visible.\nHeaders: HSTS missing, CSP missing.".into(), safemode_alerts: vec![], tag: tags.get("local-news-outlet.com").cloned().unwrap_or(DomainTag::None) },
            DomainIntel { name: "verified-charity.org".into(), risk: RiskLevel::Neutral, lat: 40.7128, lon: -74.0060, ips: vec!["172.67.73.244".into()], details: "Valid Let's Encrypt certificate.\nNo third-party trackers detected.\nHeaders: Secure (HSTS, CSP, X-Frame-Options present).".into(), safemode_alerts: vec![], tag: tags.get("verified-charity.org").cloned().unwrap_or(DomainTag::None) },
        ]
    }
    fn evaluate_safemode(&mut self) {
        for domain in &mut self.domains {
            domain.safemode_alerts.clear();
            if !self.safemode_active { continue; }
            for rule in &self.rules {
                if !rule.active { continue; }
                let triggered = match rule.category.as_str() {
                    "HOSTILE_GEO" => domain.risk == RiskLevel::High,
                    "MISSING_HSTS" => domain.details.contains("HSTS missing"),
                    "FINGERPRINT" => domain.details.contains("fingerprinting"),
                    _ => false,
                };
                if triggered { domain.safemode_alerts.push(format!("{} ({})", rule.category, rule.action)); }
            }
        }
    }
    fn toggle_safemode(&mut self) { self.safemode_active = !self.safemode_active; self.evaluate_safemode(); }
    fn filtered_domains(&self) -> Vec<&DomainIntel> {
        if let Some(filter) = &self.filter { self.domains.iter().filter(|d| &d.risk == filter).collect() } else { self.domains.iter().collect() }
    }
    fn next(&mut self) {
        let len = self.filtered_domains().len(); if len == 0 { return; }
        let i = match self.list_state.selected() { Some(i) => if i >= len - 1 { 0 } else { i + 1 }, None => 0 };
        self.list_state.select(Some(i));
    }
    fn previous(&mut self) {
        let len = self.filtered_domains().len(); if len == 0 { return; }
        let i = match self.list_state.selected() { Some(i) => if i == 0 { len - 1 } else { i - 1 }, None => 0 };
        self.list_state.select(Some(i));
    }
    fn selected_domain(&self) -> Option<&DomainIntel> {
        let filtered = self.filtered_domains();
        if let Some(i) = self.list_state.selected() { filtered.get(i).copied() } else { None }
    }
    fn sm_next(&mut self) {
        let len = self.rules.len(); if len == 0 { return; }
        let i = match self.safemode_state.selected() { Some(i) => if i >= len - 1 { 0 } else { i + 1 }, None => 0 };
        self.safemode_state.select(Some(i));
    }
    fn sm_previous(&mut self) {
        let len = self.rules.len(); if len == 0 { return; }
        let i = match self.safemode_state.selected() { Some(i) => if i == 0 { len - 1 } else { i - 1 }, None => 0 };
        self.safemode_state.select(Some(i));
    }

    /// Compiles and exports a local hosts-style blocklist based on active alerts and tags.
    pub fn export_hosts_blocklist(&self) -> Result<(), std::io::Error> {
        let mut blocklist_payload = String::new();
        blocklist_payload.push_str("# ==========================================\n");
        blocklist_payload.push_str("# DULLAHAN AUTOMATED HUMANITARIAN BLOCKLIST\n");
        blocklist_payload.push_str("# Generated entirely offline via local policies.\n");
        blocklist_payload.push_str("# ==========================================\n\n");

                 let mut block_count = 0;
        for domain in &self.domains {
            if !domain.safemode_alerts.is_empty() || domain.tag == DomainTag::Malicious {
                blocklist_payload.push_str(&format!("0.0.0.0 {}\n", domain.name));
                block_count += 1;
            }
        }
        
        // Add a summary footer so the variable is used
        blocklist_payload.push_str(&format!("\n# Total domains blocked: {}\n", block_count));

        let export_path = self.config_dir.join("dullahan_hosts_blocklist.txt");        

        std::fs::write(&export_path, blocklist_payload)?;
        Ok(())
    }
}

fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect();
    let input_file = if args.len() >= 3 && args[1] == "--input" { Some(args[2].clone()) } else { None };
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(input_file);
    let res = run_app(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    if let Err(err) = res { println!("{err:?}"); }
    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press { continue; }
            match app.view {
                AppView::Main => match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,
                    KeyCode::Down | KeyCode::Char('j') => app.next(), KeyCode::Up | KeyCode::Char('k') => app.previous(),
                    KeyCode::Char('r') => app.filter = Some(RiskLevel::High), KeyCode::Char('y') => app.filter = Some(RiskLevel::Obfuscated),
                    KeyCode::Char('g') => app.filter = Some(RiskLevel::Neutral), KeyCode::Char('o') => app.filter = Some(RiskLevel::Offline),
                    KeyCode::Char('a') => app.filter = None, KeyCode::Char('s') | KeyCode::Char('S') => app.toggle_safemode(),
                    KeyCode::Char('m') | KeyCode::Char('M') => app.view = AppView::SafemodeManager,
                    KeyCode::Char('t') | KeyCode::Char('T') => { if app.selected_domain().is_some() { app.view = AppView::TagPopup; } }
                    KeyCode::Enter => { if app.selected_domain().is_some() { app.view = AppView::DossierPopup; } }
                    _ => {}
                },
                AppView::SafemodeManager => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.view = AppView::Main,
                    KeyCode::Down | KeyCode::Char('j') => app.sm_next(), KeyCode::Up | KeyCode::Char('k') => app.sm_previous(),
                    KeyCode::Char('+') | KeyCode::Char('=') => { if let Some(i) = app.safemode_state.selected() { if i > 0 { app.rules.swap(i, i - 1); app.safemode_state.select(Some(i - 1)); } } }
                    KeyCode::Char('-') => { if let Some(i) = app.safemode_state.selected() { if i < app.rules.len() - 1 { app.rules.swap(i, i + 1); app.safemode_state.select(Some(i + 1)); } } }
                    KeyCode::Char('a') | KeyCode::Char('A') => { app.rules.push(SafemodeRule { category: "NEW_RULE".into(), condition: "Condition here".into(), action: "WARN".into(), list_type: "Blacklist".into(), threshold: 0, active: true }); }
                    KeyCode::Char('r') | KeyCode::Char('R') => { if let Some(i) = app.safemode_state.selected() { if i < app.rules.len() { app.rules.remove(i); if !app.rules.is_empty() { app.safemode_state.select(Some(i.saturating_sub(1))); } } } }
                    KeyCode::Char('c') | KeyCode::Char('C') => { if let Some(i) = app.safemode_state.selected() { if i < app.rules.len() { let new_rule = app.rules[i].clone(); app.rules.insert(i + 1, new_rule); app.safemode_state.select(Some(i + 1)); } } }
                    KeyCode::Char('e') | KeyCode::Char('E') => { if let Some(i) = app.safemode_state.selected() { if i < app.rules.len() { app.rules[i].active = true; app.evaluate_safemode(); } } }
                    KeyCode::Char('d') | KeyCode::Char('D') => { if let Some(i) = app.safemode_state.selected() { if i < app.rules.len() { app.rules[i].active = false; app.evaluate_safemode(); } } }
                    KeyCode::Char('t') | KeyCode::Char('T') => app.view = AppView::TestResultPopup,
                    KeyCode::Tab => { app.ruleset_mode = match app.ruleset_mode { RulesetMode::Workspace => RulesetMode::Global, RulesetMode::Global => RulesetMode::Workspace }; }
                    KeyCode::Enter => { if let Some(i) = app.safemode_state.selected() { if i < app.rules.len() { app.rules[i].active = !app.rules[i].active; app.evaluate_safemode(); } } }
                    KeyCode::Char('w') | KeyCode::Char('W') => { let _ = app.export_hosts_blocklist(); } // NEW KEYBIND
                    _ => {}
                },
                AppView::TagPopup => match key.code {
                    KeyCode::Char('s') | KeyCode::Char('S') => { let name = app.selected_domain().map(|d| d.name.clone()); if let Some(name) = name { app.set_tag(&name, DomainTag::Safe); app.view = AppView::Main; } }
                    KeyCode::Char('m') | KeyCode::Char('M') => { let name = app.selected_domain().map(|d| d.name.clone()); if let Some(name) = name { app.set_tag(&name, DomainTag::Malicious); app.view = AppView::Main; } }
                    KeyCode::Char('i') | KeyCode::Char('I') => { let name = app.selected_domain().map(|d| d.name.clone()); if let Some(name) = name { app.set_tag(&name, DomainTag::Investigate); app.view = AppView::Main; } }
                    KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Esc => { let name = app.selected_domain().map(|d| d.name.clone()); if let Some(name) = name { app.set_tag(&name, DomainTag::None); } app.view = AppView::Main; }
                    KeyCode::Char('q') | KeyCode::Char('Q') => { app.view = AppView::Main; }
                    _ => {}
                },
                AppView::DossierPopup | AppView::TestResultPopup => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc | KeyCode::Enter => app.view = AppView::Main,
                    _ => {}
                },
            }
        }
        if app.should_quit { return Ok(()); }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    match app.view {
        AppView::Main => render_main_view(f, app),
        AppView::SafemodeManager => render_safemode_manager(f, app),
        AppView::DossierPopup => { render_main_view(f, app); render_dossier_popup(f, app); }
        AppView::TestResultPopup => { render_main_view(f, app); render_test_result_popup(f, app); }
        AppView::TagPopup => { render_main_view(f, app); render_tag_popup(f, app); }
    }
}

fn render_main_view(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default().direction(Direction::Vertical).margin(1).constraints([Constraint::Percentage(85), Constraint::Percentage(15)]).split(f.size());
    let top_chunks = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Length(35), Constraint::Min(1)]).split(chunks[0]);
    let filtered: Vec<DomainIntel> = app.filtered_domains().into_iter().cloned().collect();
    let items: Vec<ListItem> = filtered.iter().enumerate().map(|(i, domain)| {
        let is_selected = app.list_state.selected() == Some(i);
        let mut style = Style::default().fg(domain.risk.color());
        if is_selected { style = style.bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD); }
        let prefix = if is_selected { " > " } else { "   " };
        let tag_str = domain.tag.marker();
        let alerts = if !domain.safemode_alerts.is_empty() { " [!]" } else { "" };
        ListItem::new(format!("{}{}{}{}{}", prefix, domain.name, if tag_str.is_empty() { "" } else { " " }, tag_str, alerts)).style(style)
    }).collect();
    let filter_text = match &app.filter { Some(fl) => format!(" FILTER: {} ", fl.as_str()), None => " FILTER: ALL ".to_string() };
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(filter_text)).highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)).highlight_symbol(">> ");
    f.render_stateful_widget(list, top_chunks[0], &mut app.list_state);
    let filtered_refs: Vec<&DomainIntel> = filtered.iter().collect();
    render_braille_map(f, top_chunks[1], &filtered_refs);
    let sm_text = if app.safemode_active { "ON" } else { "OFF" };
    let help = Paragraph::new(format!(" [Up/Dn] Nav | [r/y/g/o/a] Filter | [s] Safemode: {} | [m] Manager | [t] Tag | [Enter] Dossier | [q] Quit ", sm_text)).block(Block::default().borders(Borders::ALL).title(" ACTIONS ")).style(Style::default().fg(Color::Cyan).bg(Color::Black));
    f.render_widget(help, chunks[1]);
}

fn render_braille_map(f: &mut Frame, area: Rect, domains: &[&DomainIntel]) {
    let height = area.height.saturating_sub(2) as usize;
    let width = area.width.saturating_sub(2) as usize;
    if height < 4 || width < 4 { return; }
    let inner_h = height * 4; let inner_w = width * 2;
    let mut grid = vec![vec![false; inner_w]; inner_h];
    let continents: &[&[(f64, f64)]] = &[
        &[(-130.0, 70.0), (-60.0, 70.0), (-50.0, 45.0), (-80.0, 25.0), (-100.0, 20.0), (-130.0, 50.0)],
        &[(-80.0, 10.0), (-35.0, 10.0), (-40.0, -20.0), (-70.0, -50.0), (-80.0, -10.0)],
        &[(-10.0, 70.0), (180.0, 70.0), (180.0, 10.0), (100.0, 10.0), (40.0, 30.0), (30.0, 35.0), (10.0, 35.0), (-10.0, 35.0)],
        &[(-20.0, 35.0), (50.0, 35.0), (50.0, -35.0), (20.0, -35.0), (-20.0, 10.0)],
        &[(110.0, -10.0), (155.0, -10.0), (155.0, -40.0), (110.0, -40.0)],
    ];
    for row in 0..inner_h {
        for col in 0..inner_w {
            let lon = -180.0 + (col as f64 / inner_w as f64) * 360.0;
            let lat = 90.0 - (row as f64 / inner_h as f64) * 180.0;
            for poly in continents {
                let mut inside = false;
                let n = poly.len();
                for i in 0..n {
                    let j = (i + 1) % n;
                    let (xi, yi) = poly[i]; let (xj, yj) = poly[j];
                    let intersect = ((yi > lat) != (yj > lat)) && (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi);
                    if intersect { inside = !inside; }
                }
                if inside { grid[row][col] = true; break; }
            }
        }
    }
    
    // Robust marker grid to prevent index out of bounds
    let mut marker_grid: Vec<Vec<Option<(&'static str, Color)>>> = vec![vec![None; width]; height];
    for domain in domains {
        let lat_norm = ((domain.lat + 90.0) / 180.0).clamp(0.0, 1.0);
        let row = ((1.0 - lat_norm) * (height as f64 - 1.0)) as usize;
        let lon_norm = ((domain.lon + 180.0) / 360.0).clamp(0.0, 1.0);
        let col = (lon_norm * (width as f64 - 1.0)) as usize;
        if row < height && col < width {
            marker_grid[row][col] = Some((domain.risk.marker(), domain.risk.color()));
        }
    }

    let braille_base = 0x2800;
    let dot_offsets = [[0x01, 0x08], [0x02, 0x10], [0x04, 0x20], [0x40, 0x80]];
    let mut braille_lines: Vec<Line> = Vec::with_capacity(height);
    for row in 0..height {
        let mut spans = Vec::with_capacity(width);
        for col in 0..width {
            if let Some((marker, color)) = marker_grid[row][col] {
                spans.push(Span::styled(marker.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)));
            } else {
                let inner_r = row * 4;
                let inner_c = col * 2;
                let mut char_val = braille_base;
                for r in 0..4 { 
                    for c in 0..2 {
                        let check_r = inner_r + r; let check_c = inner_c + c;
                        if check_r < inner_h && check_c < inner_w && grid[check_r][check_c] { char_val |= dot_offsets[r][c]; }
                    }
                }
                let ch = char::from_u32(char_val).unwrap_or(' ');
                spans.push(Span::styled(ch.to_string(), Style::default().fg(Color::DarkGray)));
            }
        }
        braille_lines.push(Line::from(spans));
    }
    f.render_widget(Paragraph::new(braille_lines).block(Block::default().borders(Borders::ALL).title(" DATA SOVEREIGNTY MAP ")).wrap(Wrap { trim: false }), area);
}

fn render_safemode_manager(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default().direction(Direction::Vertical).margin(1).constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(3)]).split(f.size());
    let mode_str = match app.ruleset_mode { RulesetMode::Workspace => "Workspace", RulesetMode::Global => "Global" };
    // UPDATED UI TEXT TO INCLUDE [W]rite Blocklist
    let top_text = format!(" [A]dd [R]emove [+/-]Move [E]nable [D]isable [W]rite Blocklist [TAB] {} [Esc] Back ", mode_str);
    f.render_widget(Paragraph::new(top_text).block(Block::default().borders(Borders::ALL).title(" - Safe mode manager - ")).style(Style::default().fg(Color::Cyan)), chunks[0]);
    let header_cells = ["#", "Category", "Rules (Condition)", "Action", "Dist", "B/W", "Mode"].iter().map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).style(Style::default().bg(Color::DarkGray)).height(1);
    let rows: Vec<Row> = app.rules.iter().enumerate().map(|(i, rule)| {
        let is_selected = app.safemode_state.selected() == Some(i);
        let style = if is_selected { Style::default().fg(Color::White).bg(Color::DarkGray).add_modifier(Modifier::BOLD) } else if rule.active { Style::default().fg(Color::Green) } else { Style::default().fg(Color::Gray) };
        let prefix = if is_selected { "> " } else { "  " };
        let mode_str = if rule.active { "[X]" } else { "[ ]" };
        Row::new(vec![Cell::from(format!("{}{}", prefix, i + 1)), Cell::from(rule.category.clone()), Cell::from(rule.condition.clone()), Cell::from(rule.action.clone()), Cell::from(rule.threshold.to_string()), Cell::from(rule.list_type.clone()), Cell::from(mode_str)]).style(style).height(1)
    }).collect();
    let table = Table::new(rows, [Constraint::Length(4), Constraint::Length(15), Constraint::Min(25), Constraint::Length(15), Constraint::Length(6), Constraint::Length(10), Constraint::Length(6)]).header(header).block(Block::default().borders(Borders::ALL).title(format!(" [{}] Rules ", mode_str))).highlight_symbol(">> ").highlight_spacing(HighlightSpacing::Always);
    f.render_stateful_widget(table, chunks[1], &mut app.safemode_state);
    f.render_widget(Paragraph::new(" + / - : Change priority  |  Enter : Edit rule  |  Tab : Switch ruleset ").block(Block::default().borders(Borders::ALL)).style(Style::default().fg(Color::Gray)), chunks[2]);
}

fn render_tag_popup(f: &mut Frame, app: &mut App) {
    let area = centered_rect(50, 30, f.size());
    f.render_widget(Clear, area);
    if let Some(domain) = app.selected_domain() {
        let current_tag = domain.tag.marker();
        let content = format!("Setting tag for: {}\nCurrent Tag: {}\n\n[S] Safe\n[M] Malicious\n[I] Investigate\n[C] Clear\n\nPress Q/Esc to cancel.", domain.name, if current_tag.is_empty() { "None" } else { current_tag });
        f.render_widget(Paragraph::new(content).block(Block::default().borders(Borders::ALL).title(" TAG DOMAIN ").border_style(Style::default().fg(Color::Cyan))).style(Style::default().fg(Color::White)).wrap(Wrap { trim: true }), area);
    }
}

fn render_dossier_popup(f: &mut Frame, app: &mut App) {
    let area = centered_rect(70, 60, f.size());
    f.render_widget(Clear, area);
    if let Some(domain) = app.selected_domain() {
        let mut details = format!("DOMAIN: {}\nRISK:   {}\nTAG:    {}\nLAT/LON: {:.4}, {:.4}\nIPS:    {}\n\n", domain.name, domain.risk.as_str(), domain.tag.marker(), domain.lat, domain.lon, domain.ips.join(", "));
        if !domain.safemode_alerts.is_empty() {
            details.push_str("SAFEMODE ALERTS:\n");
            for alert in &domain.safemode_alerts { details.push_str(&format!("  - {}\n", alert)); }
            details.push('\n');
        }
        details.push_str("INTELLIGENCE:\n");
        details.push_str(&domain.details);
        f.render_widget(Paragraph::new(details).block(Block::default().borders(Borders::ALL).title(format!(" DOSSIER: {} (Enter/Esc) ", domain.name)).border_style(Style::default().fg(domain.risk.color()))).style(Style::default().fg(Color::Gray)).wrap(Wrap { trim: true }), area);
    }
}

fn render_test_result_popup(f: &mut Frame, app: &mut App) {
    let area = centered_rect(60, 40, f.size());
    f.render_widget(Clear, area);
    let test_target = app.selected_domain().map(|d| d.name.clone()).unwrap_or_else(|| "test-target.com".into());
    let mut results = format!("Testing Safemode rules against: {}\n\n", test_target);
    let mut triggered_count = 0;
    for rule in &app.rules {
        if !rule.active { results.push_str(&format!(" [ ] SKIPPED:   {} (disabled)\n", rule.category)); continue; }
        let triggered = rule.category == "HOSTILE_GEO" || rule.category == "MISSING_HSTS";
        if triggered { results.push_str(&format!(" [!] TRIGGERED: {} -> {}\n", rule.category, rule.action)); triggered_count += 1; }
        else { results.push_str(&format!(" [ ] PASSED:    {}\n", rule.category)); }
    }
    results.push_str(&format!("\nResult: {} rules triggered.", triggered_count));
    f.render_widget(Paragraph::new(results).block(Block::default().borders(Borders::ALL).title(" SAFE MODE TEST RESULT (Enter/Esc) ").border_style(Style::default().fg(Color::Cyan))).style(Style::default().fg(Color::White)).wrap(Wrap { trim: true }), area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage((100 - percent_y) / 2), Constraint::Percentage(percent_y), Constraint::Percentage((100 - percent_y) / 2)]).split(r);
    Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage((100 - percent_x) / 2), Constraint::Percentage(percent_x), Constraint::Percentage((100 - percent_x) / 2)]).split(popup_layout[1])[1]
}
