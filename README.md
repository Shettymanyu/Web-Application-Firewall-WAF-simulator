<!--
  Drop this file in: github.com/Shettymanyu/Web-Application-Firewall-WAF-simulator/README.md
-->

<h1 align="center">Web Application Firewall (WAF) Simulator</h1>

<p align="center">
  <em>A Flask-based playground that demonstrates how a Web Application Firewall detects and blocks common OWASP Top-10 attacks against a sample web app.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/OWASP-Top%2010-000000?style=flat-square&logo=owasp&logoColor=white"/>
  <img src="https://img.shields.io/badge/Security-Educational-1B5E20?style=flat-square"/>
</p>

---

## Why I built this

Most people use a WAF as a black box. I wanted to build a small, transparent one so the detection rules are inspectable and the request/response lifecycle is easy to follow &mdash; useful for learning, demos, and as a base for more serious rule-engine work.

## What it does

- Stands up a **sample vulnerable web app** behind a custom WAF middleware
- Inspects every incoming request against a pluggable set of detection rules
- **Blocks or flags** matches &mdash; SQL injection, XSS, path traversal, suspicious headers, etc.
- Shows the attack surface and the WAF's decisions in a **live web UI**

## Attack patterns covered

- SQL injection (union-based, boolean, comment-evasion variants)
- Reflected and stored XSS
- Path traversal (`../`) and LFI attempts
- Suspicious user-agent / request-method patterns
- *(easy to extend &mdash; rules live in `waf/`)*

## Architecture

```
   client  --->  Flask app  --->  [ WAF middleware ]  --->  vulnerable endpoints
                                          |
                                          v
                                   detection rules
                                  (waf/ blueprint)
                                          |
                                          v
                                  decision: pass / block / log
```

## Tech stack

- **Backend:** Python, Flask, Blueprints
- **Frontend:** HTML, CSS, vanilla JS (server-rendered templates)
- **WAF engine:** custom rules in `waf/`
- **Config:** `config.py`

## Getting started

```bash
git clone https://github.com/Shettymanyu/Web-Application-Firewall-WAF-simulator.git
cd Web-Application-Firewall-WAF-simulator

python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python app.py
```

Then open <http://localhost:5000> in your browser.

## Try an attack (safe, local only)

> Only run these against your own local instance.

```
# SQLi attempt
http://localhost:5000/search?q=' OR 1=1 --

# Reflected XSS attempt
http://localhost:5000/search?q=<script>alert(1)</script>

# Path traversal attempt
http://localhost:5000/file?name=../../etc/passwd
```

The WAF should intercept each request and surface a "blocked" response with the rule that matched.

## Repo layout

```
.
|-- app.py             Flask entrypoint
|-- config.py          App + WAF configuration
|-- blueprints/        Sample vulnerable endpoints
|-- waf/               WAF middleware + detection rules
|-- templates/         Jinja2 HTML templates
|-- static/            CSS, JS, assets
`-- requirements.txt
```

## Roadmap

- [ ] Rule editor in the UI (toggle rules, view match counts)
- [ ] Persist blocked events to SQLite for an audit log
- [ ] Add rate-limiting and IP reputation rules
- [ ] Export rules to ModSecurity-style format

## Disclaimer

This project is **for education and local experimentation only**. Do not point real production traffic at it, and don't run the bundled vulnerable endpoints on a public host.

## Author

Built by **Manyu Shetty** &mdash; <a href="https://github.com/Shettymanyu">@Shettymanyu</a> &middot; <a href="mailto:shettymanyu@gmail.com">shettymanyu@gmail.com</a>
