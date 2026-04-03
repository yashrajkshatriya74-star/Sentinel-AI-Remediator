import os
import sys
import subprocess
import tempfile
import re
import time
from concurrent import futures
from openai import OpenAI
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, session, url_for, request

# ============================================================
# ENVIRONMENT SETUP
# ============================================================

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("SECRET_KEY")

# ============================================================
# AUTH0 CONFIGURATION
# ============================================================

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

# ============================================================
# OPENAI CONFIGURATION
# Model: gpt-4o-mini — cheapest, fastest, works great
# ============================================================

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# ============================================================
# AUTO-FIX ENGINE
# ============================================================

def build_remediation_prompt(user_code: str, bandit_report: str) -> str:
    issues_only = ""
    if ">> Issue:" in bandit_report:
        start = bandit_report.find(">> Issue:")
        end = bandit_report.find("Code scanned:")
        issues_only = bandit_report[start:end].strip() if end != -1 else bandit_report[start:].strip()
    else:
        issues_only = "No issues found."

    return f"""Fix all security issues in this Python code.

Rules:
- Remove hardcoded secrets (use environment variables instead)
- Replace MD5 with hashlib.sha256
- Prevent command injection (use subprocess with list args, shell=False)
- Fix all issues found by Bandit

Bandit found these issues:
{issues_only}

Return ONLY pure Python code.
Do NOT include markdown or ``` blocks.
No explanation text.

Code:
{user_code}
"""


def extract_fixed_code(ai_text: str) -> str:
    match = re.search(r'```(?:python)?\n(.*?)```', ai_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return ai_text.strip()


def call_openai(prompt: str) -> str:
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a professional cyber security engineer. Fix Python code vulnerabilities and return only the fixed code."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=800,
            temperature=0.1
        )
        return response.choices[0].message.content

    except Exception as e:
        print(f"[OpenAI Error] {e}")
        return None


# ============================================================
# ROUTES
# ============================================================

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID")
            },
            quote_via=quote_plus,
        )
    )


@app.route("/")
def index():
    user = session.get("user")

    if not user:
        return '''
        <body style="font-family: 'Segoe UI', sans-serif; background-color: #0e1117;
                     color: white; text-align: center; padding-top: 100px;">
            <div style="background: #161b22; display: inline-block; padding: 50px;
                        border-radius: 15px; border: 1px solid #30363d;">
                <h1 style="color: #58a6ff;">&#128737;&#65039; Sentinel Guard AI</h1>
                <p style="color: #8b949e;">Advanced Python Security Auditing + Auto-Fix Agent</p>
                <br>
                <a href="/login" style="background: #238636; color: white; padding: 15px 30px;
                                        text-decoration: none; border-radius: 5px;
                                        font-weight: bold;">
                    Login with Auth0
                </a>
            </div>
        </body>
        '''

    return f'''
    <body style="font-family: 'Segoe UI', sans-serif; background-color: #0e1117;
                 color: white; text-align: center; padding-top: 50px;">
        <div style="background: #161b22; display: inline-block; padding: 40px;
                    border-radius: 15px; border: 1px solid #30363d;
                    width: 80%; max-width: 850px;">
            <h1 style="color: #58a6ff;">&#128737;&#65039; Sentinel Guard AI</h1>
            <p style="color: #8b949e; font-size: 13px; margin-top: -10px;">
                Autonomous Security Audit + Auto-Remediation Engine
            </p>
            <p>
                Logged in as: <strong style="color: #79c0ff;">{user["userinfo"]["name"]}</strong>
                &nbsp;|&nbsp;
                <a href="/logout" style="color: #ff7b72; text-decoration: none;">Logout</a>
            </p>
            <hr style="border: 0.5px solid #30363d; margin: 20px 0;">
            <form action="/scan" method="post">
                <textarea
                    name="code"
                    rows="14"
                    style="width: 95%; background: #0d1117; color: #d1d5db;
                           padding: 15px; border: 1px solid #30363d; border-radius: 8px;
                           font-family: 'Cascadia Code', monospace; resize: vertical;"
                    placeholder="Paste your Python code here for security analysis and auto-fix...">
                </textarea>
                <br><br>
                <input
                    type="submit"
                    value="&#9889; Run Security Audit + Auto-Fix"
                    style="background-color: #238636; color: white; padding: 12px 30px;
                           border: none; border-radius: 6px; cursor: pointer;
                           font-weight: bold; font-size: 15px;">
            </form>
        </div>
    </body>
    '''


@app.route("/scan", methods=["POST"])
def scan_code():
    if "user" not in session:
        return redirect("/login")

    user_code = request.form["code"][:3000]
    tmp_path = None
    report = ""

    # ----------------------------------------------------------
    # STEP 1: Bandit Static Analysis
    # ----------------------------------------------------------
    try:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(user_code)
            tmp_path = f.name

        result = subprocess.run(
            [sys.executable, "-m", "bandit", tmp_path],
            capture_output=True,
            text=True
        )
        report = result.stdout

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # ----------------------------------------------------------
    # STEP 2: OpenAI Auto-Fix
    # ----------------------------------------------------------
    ai_analysis = "The AI Security Agent is currently unavailable. Please review the Bandit report below."
    fixed_code = ""

    try:
        prompt = build_remediation_prompt(user_code, report)
        result_text = call_openai(prompt)  # FIX: removed timeout_seconds

        if result_text:
            ai_analysis = result_text
            fixed_code = extract_fixed_code(ai_analysis)
        else:
            ai_analysis = "⚠️ OpenAI API error. Please check terminal logs and try again."

    except Exception as e:
        ai_analysis = f"❌ OpenAI Error: {str(e)}"
        print(f"[OpenAI Error] {e}")

    # ----------------------------------------------------------
    # STEP 3: Style Bandit Report
    # ----------------------------------------------------------
    styled_report = (
        report
        .replace("Severity: High",
                 "<span style='color:#ff7b72;font-weight:bold;'>Severity: High (Critical)</span>")
        .replace("Severity: Medium",
                 "<span style='color:#f0883e;font-weight:bold;'>Severity: Medium</span>")
        .replace("Severity: Low",
                 "<span style='color:#d29922;font-weight:bold;'>Severity: Low</span>")
    )

    # ----------------------------------------------------------
    # STEP 4: Auto-Fix HTML Block
    # ----------------------------------------------------------
    if fixed_code:
        safe_fixed_code = (
            fixed_code
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        fixed_code_html = f'''
            <h3 style="color:#7ee787; margin-bottom:10px;">
                &#9889; Auto-Generated Secure Code Patch:
            </h3>
            <div style="position:relative;">
                <button
                    onclick="copyFixedCode()"
                    style="position:absolute; top:10px; right:10px; background:#238636;
                           color:white; border:none; padding:6px 14px; border-radius:5px;
                           cursor:pointer; font-size:12px;">
                    &#128203; Copy Fixed Code
                </button>
                <pre
                    id="fixed-code-block"
                    style="background:#0d1117; padding:20px; padding-top:45px;
                           border-radius:8px; border:1px solid #238636; overflow-x:auto;
                           font-size:13px; color:#7ee787;
                           font-family:'Cascadia Code',monospace; text-align:left;">
{safe_fixed_code}</pre>
            </div>
        '''
    else:
        fixed_code_html = '''
            <div style="background:#1c2128; padding:15px; border-radius:8px;
                        border:1px solid #30363d; color:#8b949e; font-size:13px;">
                No auto-fix code was generated.
                See the AI analysis above for manual remediation guidance.
            </div>
        '''

    # ----------------------------------------------------------
    # STEP 5: Full Results Page
    # ----------------------------------------------------------
    return f'''
    <body style="font-family:'Segoe UI',sans-serif; background-color:#0d1117;
                 color:#c9d1d9; padding:40px; line-height:1.6;">
        <div style="max-width:1050px; margin:auto; background:#161b22; padding:35px;
                    border-radius:12px; border:1px solid #30363d;
                    box-shadow:0 10px 40px rgba(0,0,0,0.6);">

            <h1 style="color:#58a6ff; margin-top:0; border-bottom:2px solid #30363d;
                       padding-bottom:15px;">
                &#128737;&#65039; Sentinel Guard AI — Audit + Auto-Fix Results
            </h1>

            <div style="background:#1c2128; padding:25px; border-radius:10px;
                        border-left:6px solid #238636; margin:25px 0;">
                <h3 style="margin-top:0; color:#7ee787;">
                    &#10024; AI Security Advisor — Vulnerability Analysis + Auto-Fix
                </h3>
                <div style="font-size:1em; color:#e6edf3; white-space:pre-wrap;">
{ai_analysis}
                </div>
            </div>

            <div style="margin:25px 0;">
                {fixed_code_html}
            </div>

            <h3 style="color:#8b949e; margin-bottom:10px;">
                &#128203; Bandit Technical Vulnerability Report:
            </h3>
            <pre style="background:#090c10; padding:20px; border-radius:8px;
                        border:1px solid #30363d; overflow-x:auto; font-size:13px;
                        color:#b1bac4; font-family:'Cascadia Code',monospace;">
{styled_report}</pre>

            <div style="text-align:center; margin-top:35px;
                        border-top:1px solid #30363d; padding-top:25px;">
                <a href="/"
                   style="background:#21262d; color:#c9d1d9; padding:12px 30px;
                          text-decoration:none; border-radius:6px;
                          border:1px solid #f0f6fc1a; font-weight:bold;">
                    &#8592; New Analysis
                </a>
                <button
                    onclick="window.print()"
                    style="margin-left:20px; background:#238636; color:white;
                           padding:12px 30px; border:none; border-radius:6px;
                           font-weight:bold; cursor:pointer;">
                    &#128196; Export PDF Report
                </button>
            </div>

            <p style="text-align:center; color:#484f58; font-size:12px; margin-top:20px;">
                Powered by Bandit Security Engine &amp; OpenAI GPT-4o Mini
            </p>
        </div>

        <script>
            function copyFixedCode() {{
                const code = document.getElementById("fixed-code-block").innerText;
                navigator.clipboard.writeText(code).then(function() {{
                    alert("Fixed code copied to clipboard!");
                }});
            }}
        </script>
    </body>
    '''


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)