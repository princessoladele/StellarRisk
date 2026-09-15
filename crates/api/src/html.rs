/// Escapes text for safe interpolation into HTML. Every piece of user- or AI-supplied
/// text rendered by the dashboard goes through this — AI advisory content is validated
/// and sanitized in `ai_advisor` before it ever reaches storage, but this is the second,
/// independent layer: nothing reaches the page unescaped, regardless of source.
pub fn esc(input: &str) -> String {
    input.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

pub const STYLE: &str = r#"
:root { color-scheme: light; --bg:#f7f8fa; --card:#ffffff; --border:#e2e5ea; --text:#1a1d23; --muted:#6b7280;
  --accent:#2563eb; --ai:#7c3aed; --human:#059669; --critical:#dc2626; --high:#ea580c; --medium:#d97706; --low:#65a30d; }
* { box-sizing: border-box; }
body { margin:0; padding:0; background:var(--bg); color:var(--text); font-family:-apple-system,Segoe UI,Roboto,sans-serif; }
header.app { padding:14px 24px; background:#111827; color:#fff; display:flex; justify-content:space-between; align-items:center; }
header.app a { color:#fff; text-decoration:none; font-weight:600; }
main { max-width:1100px; margin:0 auto; padding:24px; }
.card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:18px; margin-bottom:16px; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--border); font-size:14px; }
th { color:var(--muted); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:.04em; }
a.rowlink { color:var(--text); text-decoration:none; }
a.rowlink:hover { color:var(--accent); }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; color:#fff; }
.sev-critical { background:var(--critical); } .sev-high { background:var(--high); }
.sev-medium { background:var(--medium); } .sev-low { background:var(--low); }
.status-open { background:#6b7280; } .status-under_investigation { background:var(--accent); }
.status-escalated { background:var(--high); } .status-dismissed { background:#9ca3af; }
.status-confirmed_suspicious { background:var(--critical); }
.section-title { font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin:0 0 10px; }
.ai-panel { border:2px solid var(--ai); border-radius:10px; padding:16px; margin-bottom:16px; background:#faf5ff; }
.ai-panel .tag { background:var(--ai); color:#fff; font-size:11px; font-weight:700; padding:3px 10px; border-radius:999px; text-transform:uppercase; letter-spacing:.05em; }
.ai-disclaimer { font-size:12px; color:#5b21b6; margin-top:10px; font-style:italic; }
.human-panel { border:2px solid var(--human); border-radius:10px; padding:16px; background:#ecfdf5; }
.human-panel .tag { background:var(--human); color:#fff; font-size:11px; font-weight:700; padding:3px 10px; border-radius:999px; text-transform:uppercase; letter-spacing:.05em; }
form.decision label { display:block; margin:10px 0 4px; font-size:13px; font-weight:600; }
form.decision select, form.decision textarea, input[type=text], input[type=password] { width:100%; padding:8px; border:1px solid var(--border); border-radius:6px; font-size:14px; }
button { background:var(--accent); color:#fff; border:none; padding:9px 16px; border-radius:6px; font-weight:600; cursor:pointer; margin-top:12px; }
button:hover { opacity:.9; }
.mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; word-break:break-all; }
.muted { color:var(--muted); }
.rule { border-left:3px solid var(--high); padding:8px 12px; margin-bottom:8px; background:#fff7ed; border-radius:4px; }
.audit-item { border-left:3px solid var(--border); padding:6px 12px; margin-bottom:6px; font-size:13px; }
.login-box { max-width:360px; margin:80px auto; }
"#;

pub fn layout(title: &str, username_and_role: Option<(&str, &str)>, body: &str) -> String {
    let header_right = match username_and_role {
        Some((username, role)) => format!(
            "<span class=\"muted\">{} ({})</span> &nbsp; <a href=\"/logout\">Log out</a>",
            esc(username),
            esc(role)
        ),
        None => "<a href=\"/login\">Log in</a>".to_string(),
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title} · StellarRisk</title><style>{STYLE}</style></head><body>\
         <header class=\"app\"><a href=\"/dashboard\">StellarRisk</a><div>{header_right}</div></header>\
         <main>{body}</main></body></html>"
    )
}
