# EXAMPLES

Below are three more practical (though still somewhat simplified) double-rendering scenarios 
that could accidentally emerge in production or semi-realistic use cases. The idea is to show how double rendering might slip into a real workflow, rather than just contrived demonstration code.

Important: Even though these are more “realistic,” in a secure production environment, developers should avoid or carefully sandbox any mechanism that re-renders user-supplied templates.

1. Custom Email Template with User-Defined Macros


A small marketing platform lets administrators define email content using custom macros (placeholders), which get expanded when sending out newsletters. 
The macros use Jinja-style syntax, e.g., {{ first_name }}, {{ unsubscribe_link }}, etc.

Admin enters:
```
Subject: Welcome, {{ first_name }}!
Body: 
Hello {{ first_name }}, thanks for joining our platform!
{{ custom_html_footer }}

```

System stores this raw text in a database as a partial template.
Accidental Double Render
First Pass: The platform merges the macros with user data, e.g., {'first_name': 'Alice'}.
Second Pass: The partially rendered template might still contain additional placeholders (like {{ custom_html_footer }}) that get expanded in a subsequent pass with global config or environment variables.
Below is an abbreviated Flask example:


```
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

# A hypothetical "global" config dict
app.config["EMAIL_FOOTER"] = "Thanks for choosing our product!"
app.config["SECRET_TOKEN"] = "SHHH_IT_IS_A_SECRET"

# Simulated database for storing email templates (macro-based)
EMAIL_TEMPLATES_DB = {
    "welcome_email": {
        "subject": "Welcome, {{ first_name }}!",
        "body": """Hello {{ first_name }},
Thanks for joining our platform!

{{ custom_html_footer }}"""
    }
}

@app.route("/send_email", methods=["POST"])
def send_email():
    """
    1) Retrieve a template from the DB.
    2) Render with user data (first pass).
    3) Possibly contain leftover placeholders like {{ custom_html_footer }}.
    4) Render again (second pass), pulling in additional config or environment data.
    """
    template_key = request.form.get("template_key", "welcome_email")
    first_name = request.form.get("first_name", "Friend")

    # In a real scenario, you'd load from an actual DB:
    template_info = EMAIL_TEMPLATES_DB.get(template_key, {})

    # First pass: fill in user-specific placeholders (like {{ first_name }})
    rendered_subject = render_template_string(
        template_info["subject"],
        first_name=first_name
    )
    rendered_body_1stpass = render_template_string(
        template_info["body"],
        first_name=first_name
    )

    # Imagine "custom_html_footer" remains as a placeholder that references some config
    # So we do a second render pass to expand additional placeholders
    # If an attacker can manipulate "custom_html_footer" to contain something like {{config['SECRET_TOKEN']}},
    # we have an SSTI vulnerability
    second_pass_body = render_template_string(
        rendered_body_1stpass,
        custom_html_footer="{{ config['SECRET_TOKEN'] }}",  # This could come from DB or user input
        config=app.config
    )

    # At this point, if 'custom_html_footer' was replaced with a malicious Jinja expression,
    # it would be interpreted in the second pass.
    return f"SUBJECT: {rendered_subject}\n\nBODY:\n{second_pass_body}"

if __name__ == "__main__":
    app.run(port=7777, debug=True)

    ```
    
Why This Could Happen in Real Life
An admin-friendly UI for “email templates” might allow macros that you expand in multiple phases:
Merge user data.
Merge dynamic config, disclaimers, or global footers.
If not sanitized, an attacker with partial DB or admin access might place malicious placeholders that reveal secrets on the second pass.
2. CMS “Snippet” Rendering with Nested Templates
Scenario
A Content Management System (CMS) allows editors to store “snippets” of HTML that can include placeholders. These snippets get inserted into a larger site layout at runtime.

Editor stores a snippet like this in the CMS:


```
<h2>Our Story</h2>
<p>We started with a vision... {{ site_mission_statement }}</p>
<p>{{ next_snippet }}</p>
System merges the snippet with some data to produce “partial HTML.”
System then merges that partial HTML into a main layout (second pass), expanding any leftover placeholders referencing site config or environment variables.


```
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)
app.config["SITE_MISSION_STATEMENT"] = "Bring Joy to the Universe"
app.config["SECRET_KEY"] = "SUPER_SECRET_FOR_DEMO"

# Mock "database" of snippet content
CMS_SNIPPETS = {
    "about_page": """
    <h2>Our Story</h2>
    <p>We started with a vision... {{ site_mission_statement }}</p>
    <p>{{ next_snippet }}</p>
    """
}

@app.route("/render_snippet")
def render_snippet():
    """
    1) Editor saves a snippet with placeholders.
    2) We do a first pass to fill in something like site_mission_statement, but leave next_snippet unfilled.
    3) next_snippet might be filled in the second pass, possibly with malicious content if the user controls it.
    """
    snippet_key = request.args.get("snippet", "about_page")
    next_snippet_content = request.args.get("next_snippet", "{{config['SECRET_KEY']}}")

    snippet_template = CMS_SNIPPETS.get(snippet_key, "")

    # First pass: fill in known placeholders, e.g. site_mission_statement
    first_pass_html = render_template_string(
        snippet_template,
        site_mission_statement=app.config["SITE_MISSION_STATEMENT"]
    )

    # Now we do a second pass, in which leftover placeholders might be replaced 
    # with user-supplied input. If that input contains a Jinja expression, we have an SSTI scenario.
    second_pass_html = render_template_string(
        first_pass_html,
        next_snippet=next_snippet_content,
        config=app.config
    )

    return second_pass_html

if __name__ == "__main__":
    app.run(port=7788, debug=True)
```
    
Realistic Angle
Some CMS solutions let you define small HTML “partials” or “blocks” that contain placeholders (macros).
A legitimate feature: partial placeholders get replaced in multiple steps with different data sources.
If an attacker can modify what’s injected in step 2, they can slip in malicious {{...}}.
3. Report Generation with Nested Sections
Scenario
An internal reporting tool generates PDF or HTML reports using Jinja templates. Each report consists of multiple sections, possibly stored in different files or coming from user input:

Sections: The system merges user-chosen sections (charts, tables, disclaimers) into a single “master template.”
Master template: The system merges this partial template with additional global data or environment info.


```
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

app.config["COMPANY_NAME"] = "Galactic Enterprises"
app.config["SECRET_REPORT_KEY"] = "TopSecretKey"

# Let's pretend we have 2 sections stored somewhere
SECTION_DB = {
    "introduction": "Welcome to {{ company_name }}'s Q4 Report.\n\n{{ disclaimers }}",
    "financials": "<h3>Financials</h3>\n<p>Net revenue grew by 20%...</p>\n{{ disclaimers }}"
}

@app.route("/generate_report")
def generate_report():
    """
    1) Merge multiple sections (introduction, financials) into a bigger template.
    2) Possibly let user define disclaimers, which might include Jinja expressions.
    3) Second render merges the disclaimers with config data, leading to potential secret leakage.
    """
    intro_section = SECTION_DB["introduction"]
    finance_section = SECTION_DB["financials"]

    # Step 1: merge the sections into a "partial" master
    partial_master_template = f"""
    <html>
    <body>
      <h1>Company Quarterly Report</h1>
      <div id="introduction">
        {intro_section}
      </div>
      <div id="financials">
        {finance_section}
      </div>
    </body>
    </html>
    """

    # First pass: we replace placeholders in the introduction/finance sections
    first_pass = render_template_string(
        partial_master_template,
        company_name=app.config["COMPANY_NAME"],
        disclaimers="{{config['SECRET_REPORT_KEY']}}"  # or user-provided disclaimers
    )

    # The disclaimers remain a Jinja expression in the first pass output.
    # Second pass now sees disclaimers with leftover {{config['SECRET_REPORT_KEY']}}.
    second_pass = render_template_string(first_pass, config=app.config)
    return second_pass

if __name__ == "__main__":
    app.run(port=7799, debug=True)
```

    
Why This Could Happen
Large reports or documents might be built from multiple partial templates.
If disclaimers or footers are injected at a later stage, a developer may do a second pass to incorporate them.
If disclaimers are user-controlled or partially user-influenced, you have an SSTI risk.
Key Observations & Lessons
Legitimate Multi-step Template Systems

In real systems, it’s common to store partials/snippets and then combine them. However, this should typically be done without re-parsing the result as a Jinja template again.
Accidental Inheritance of Placeholders

A developer might think, “I’ll just reuse render_template_string to handle all placeholders dynamically,” not realizing user input might contain malicious placeholders.
Security Risk

If any user-supplied string can survive the first pass unrendered (i.e., remain {{...}}), it’s ripe for exploitation on the second pass if the environment or config is available.
Mitigation

If you truly need multi-step merges, consider a different approach:
Use a safe placeholder format (not Jinja2) for user data.
Sanitize user inputs to prevent raw Jinja2 syntax.
Avoid passing sensitive variables to the second pass.
Final Takeaway
Double rendering can appear “naturally” in code that merges partial templates in multiple steps.
These “realistic” examples show how innocent design choices—like user-defined macros, disclaimers, or snippet-based CMS—might turn into an SSTI vulnerability if the developer isn’t careful.
In each example, the second pass receives a string that still contains {{...}}, enabling an attacker to inject code or read secrets if they control the leftover placeholders.
Use these examples to remind yourself:

Check what placeholders remain in your partials after the first render.
Validate or sanitize anything that might lead to a second pass.

# Don’t pass sensitive contexts (config, os.environ, etc.) to templates unless absolutely necessary.

##
##


# How Double Rendering Works


First Render Pass: The application renders a template with user-supplied input, which might include template syntax like {{ ... }}.
Second Render Pass: The output from the first render pass, which still contains {{ ... }} syntax, is rendered again. This second pass interprets the previously inserted template syntax, potentially executing malicious code.
Why Double Rendering Matters
Double rendering is dangerous because it blurs the line between user input and executable code. When user inputs are re-rendered as templates without proper sanitization or restrictions, attackers can inject malicious Jinja2 expressions that the server interprets and executes. This can lead to:

Secret Leakage: Accessing environment variables or application configurations.
Remote Code Execution (RCE): Executing arbitrary code on the server.
Data Manipulation: Altering application data or behavior.
Understanding and preventing double rendering is crucial for maintaining the security and integrity of Flask applications.

Practical Double Rendering Examples
To illustrate double rendering and its potential vulnerabilities, we'll explore three practical scenarios where double rendering might inadvertently occur:

Custom Email Template with User-Defined Macros
CMS “Snippet” Rendering with Nested Templates
Report Generation with Nested Sections
Each example will include a vulnerable implementation followed by a secure, corrected version.

1. Custom Email Template with User-Defined Macros
Vulnerable Implementation
In this scenario, a marketing platform allows administrators to define custom email templates with placeholders (macros) that are expanded when sending newsletters. The system performs double rendering to handle different placeholder layers, inadvertently introducing SSTI vulnerabilities.

```
from flask import Flask, request, render_template_string, jsonify
import os

app = Flask(__name__)

# Hypothetical "global" config dict
app.config["EMAIL_FOOTER"] = "Thank you for choosing our service!"
app.config["SECRET_TOKEN"] = "SuperSecretToken123!"

# Simulated database for storing email templates (macro-based)
EMAIL_TEMPLATES_DB = {
    "welcome_email": {
        "subject": "Welcome, {{ first_name }}!",
        "body": """Hello {{ first_name }},
Thank you for joining our platform!

{{ custom_html_footer }}"""
    }
}

@app.route("/send_email", methods=["POST"])
def send_email():
    """
    Vulnerable send_email endpoint:
    1. Retrieves email template from "database".
    2. First render pass: replaces user-specific placeholders.
    3. Second render pass: replaces remaining placeholders with config.
    """
    template_key = request.form.get("template_key", "welcome_email")
    first_name = request.form.get("first_name", "User")

    # Load template from "database"
    template_info = EMAIL_TEMPLATES_DB.get(template_key, {})
    if not template_info:
        return jsonify({"error": "Invalid template key"}), 400

    # First pass: fill in user-specific placeholders
    rendered_subject = render_template_string(
        template_info["subject"],
        first_name=first_name
    )
    rendered_body_1stpass = render_template_string(
        template_info["body"],
        first_name=first_name
    )

    # Second pass: replace remaining placeholders, potentially injecting SSTI
    # Here, 'custom_html_footer' can be manipulated to include Jinja2 expressions
    custom_footer = request.form.get("custom_html_footer", "{{ config['EMAIL_FOOTER'] }}")
    rendered_body_2ndpass = render_template_string(
        rendered_body_1stpass,
        custom_html_footer=custom_footer,
        config=app.config
    )

    # Simulate sending email by returning the rendered content
    return jsonify({
        "subject": rendered_subject,
        "body": rendered_body_2ndpass
    })

if __name__ == "__main__":
    app.run(port=7777, debug=True)


    
Exploitation Example
An attacker can manipulate the custom_html_footer to inject malicious Jinja2 expressions:

```
curl -X POST http://localhost:7777/send_email \
     -d "template_key=welcome_email" \
     -d "first_name=Attacker" \
     -d "custom_html_footer={{ config['SECRET_TOKEN'] }}"
```

     
Expected Response:

```
{
  "subject": "Welcome, Attacker!",
  "body": "Hello Attacker,\nThank you for joining our platform!\n\nSuperSecretToken123!"
}
```



The SECRET_TOKEN is leaked via the injected Jinja2 expression.

2. CMS “Snippet” Rendering with Nested Templates
Vulnerable Implementation
A Content Management System (CMS) allows editors to store HTML snippets with placeholders. The system performs double rendering to merge these snippets into a main layout, potentially allowing SSTI if user inputs include malicious template syntax.

```
from flask import Flask, request, render_template_string, jsonify
import os

app = Flask(__name__)

app.config["SITE_MISSION_STATEMENT"] = "Deliver Excellence to Our Clients"
app.config["SECRET_KEY"] = "TopSecretKey!"

# Mock "database" of snippet content
CMS_SNIPPETS = {
    "about_page": """
    <h2>Our Story</h2>
    <p>We started with a vision to {{ site_mission_statement }}.</p>
    <p>{{ next_snippet }}</p>
    """
}

@app.route("/render_snippet")
def render_snippet():
    """
    Vulnerable render_snippet endpoint:
    1. Retrieves snippet from "database".
    2. First render pass: fills in known placeholders.
    3. Second render pass: replaces remaining placeholders, potentially injecting SSTI.
    """
    snippet_key = request.args.get("snippet", "about_page")
    next_snippet_content = request.args.get("next_snippet", "{{ config['SITE_MISSION_STATEMENT'] }}")

    snippet_template = CMS_SNIPPETS.get(snippet_key, "")
    if not snippet_template:
        return jsonify({"error": "Invalid snippet key"}), 400

    # First pass: fill in known placeholders
    first_pass_html = render_template_string(
        snippet_template,
        site_mission_statement=app.config["SITE_MISSION_STATEMENT"]
    )

    # Second pass: replace remaining placeholders, possibly injecting SSTI
    second_pass_html = render_template_string(
        first_pass_html,
        next_snippet=next_snippet_content,
        config=app.config
    )

    return second_pass_html

if __name__ == "__main__":
    app.run(port=7788, debug=True)
```


    
Exploitation Example
An attacker can manipulate the next_snippet parameter to inject SSTI:

```
curl "http://localhost:7788/render_snippet?snippet=about_page&next_snippet={{ config['SECRET_KEY'] }}"
```
Expected Response:

```


<h2>Our Story</h2>
<p>We started with a vision to Deliver Excellence to Our Clients.</p>
<p>TopSecretKey!</p>
The SECRET_KEY is exposed through the injected Jinja2 expression.

3. Report Generation with Nested Sections
Vulnerable Implementation
An internal reporting tool generates reports by merging multiple sections. The tool performs double rendering to handle partial templates, inadvertently introducing SSTI vulnerabilities if user inputs include malicious template syntax.

```
from flask import Flask, request, render_template_string, jsonify
import os

app = Flask(__name__)

app.config["COMPANY_NAME"] = "Galactic Enterprises"
app.config["SECRET_REPORT_KEY"] = "UltraSecretReportKey!"

# Mock "database" of report sections
SECTION_DB = {
    "introduction": "Welcome to {{ company_name }}'s quarterly report.\n\n{{ disclaimers }}",
    "financials": "<h3>Financial Overview</h3>\n<p>Net revenue increased by 15%...</p>\n{{ disclaimers }}"
}

@app.route("/generate_report")
def generate_report():
    """
    Vulnerable generate_report endpoint:
    1. Merges multiple report sections into a master template.
    2. First render pass: fills in known placeholders.
    3. Second render pass: replaces remaining placeholders, potentially injecting SSTI.
    """
    intro_section = SECTION_DB["introduction"]
    finance_section = SECTION_DB["financials"]

    # Merge sections into a "partial" master template
    partial_master_template = f"""
    <html>
    <body>
      <h1>Company Quarterly Report</h1>
      <div id="introduction">
        {intro_section}
      </div>
      <div id="financials">
        {finance_section}
      </div>
    </body>
    </html>
    """

    # First pass: fill in known placeholders
    first_pass = render_template_string(
        partial_master_template,
        company_name=app.config["COMPANY_NAME"]
    )

    # Second pass: replace remaining placeholders, potentially injecting SSTI
    # Here, 'disclaimers' can be manipulated to include Jinja2 expressions
    disclaimers_content = request.args.get("disclaimers", "{{ config['SECRET_REPORT_KEY'] }}")
    second_pass = render_template_string(
        first_pass,
        disclaimers=disclaimers_content,
        config=app.config
    )

    return second_pass

if __name__ == "__main__":
    app.run(port=7799, debug=True)
```
    
Exploitation Example
An attacker can manipulate the disclaimers parameter to inject SSTI:


# curl "http://localhost:7799/generate_report?disclaimers={{ config['SECRET_REPORT_KEY'] }}"
Expected Response:



```
<html>
<body>
  <h1>Company Quarterly Report</h1>
  <div id="introduction">
    Welcome to Galactic Enterprises's quarterly report.

    UltraSecretReportKey!
  </div>
  <div id="financials">
    <h3>Financial Overview</h3>
    <p>Net revenue increased by 15%...</p>
    UltraSecretReportKey!
  </div>
</body>
</html>
```


The SECRET_REPORT_KEY is exposed through the injected Jinja2 expression.

##
##


# Corrected Secure Implementations
To prevent double rendering vulnerabilities, it's essential to avoid rendering user-supplied input as templates, especially in a second render pass. Below are the secure versions of the above examples, incorporating best practices to eliminate SSTI risks.

1. Secure Custom Email Template
Corrections Implemented:

Single Render Pass: Only render the template once, filling in all placeholders in one go.
Sanitize Inputs: Ensure that user-supplied inputs do not contain template syntax.
Avoid Passing Config to Templates: Do not pass sensitive configuration data to templates.


```
from flask import Flask, request, render_template_string, jsonify
import os
import html

app = Flask(__name__)

# Securely retrieve the secret from environment variables
app.config["EMAIL_FOOTER"] = "Thank you for choosing our service!"
app.config["SECRET_TOKEN"] = "SuperSecretToken123!"

# Simulated database for storing email templates (macro-based)
EMAIL_TEMPLATES_DB = {
    "welcome_email": {
        "subject": "Welcome, {{ first_name | e }}!",
        "body": """Hello {{ first_name | e }},
Thank you for joining our platform!

{{ custom_html_footer | e }}"""
    }
}

@app.route("/send_email", methods=["POST"])
def send_email():
    """
    Secure send_email endpoint:
    1. Retrieves email template from "database".
    2. Renders template once with sanitized user inputs.
    """
    template_key = request.form.get("template_key", "welcome_email")
    first_name = request.form.get("first_name", "User")
    custom_footer = request.form.get("custom_html_footer", app.config["EMAIL_FOOTER"])

    # Load template from "database"
    template_info = EMAIL_TEMPLATES_DB.get(template_key, {})
    if not template_info:
        return jsonify({"error": "Invalid template key"}), 400

    # Sanitize inputs by escaping HTML
    sanitized_first_name = html.escape(first_name)
    sanitized_custom_footer = html.escape(custom_footer)

    # Single render pass: fill in all placeholders securely
    rendered_subject = render_template_string(
        template_info["subject"],
        first_name=sanitized_first_name
    )
    rendered_body = render_template_string(
        template_info["body"],
        first_name=sanitized_first_name,
        custom_html_footer=sanitized_custom_footer
    )

    # Simulate sending email by returning the rendered content
    return jsonify({
        "subject": rendered_subject,
        "body": rendered_body
    })

if __name__ == "__main__":
    app.run(port=7777, debug=True)
```

    
Key Changes:

Single Render Pass: Both first_name and custom_html_footer are filled in during one render pass.
HTML Escaping (| e): Ensures that any user-supplied input is escaped, preventing injection of template syntax.
No Second Render Pass: Eliminates the opportunity for SSTI by not re-rendering the output.
Testing the Secure Implementation:

Attempting to inject SSTI now results in the template syntax being escaped and displayed as literal text.

```
curl -X POST http://localhost:7777/send_email \
     -d "template_key=welcome_email" \
     -d "first_name=Attacker" \
     -d "custom_html_footer={{ config['SECRET_TOKEN'] }}"
```

     
Expected Secure Response:

```
{
  "subject": "Welcome, Attacker!",
  "body": "Hello Attacker,\nThank you for joining our platform!\n\n{{ config['SECRET_TOKEN'] }}"
}
```
The injected {{ config['SECRET_TOKEN'] }} is escaped and rendered as plain text, not executed.

2. Secure CMS Snippet Rendering
Corrections Implemented:

Single Render Pass: Render the template once, filling in all placeholders securely.
Sanitize Inputs: Escape user-supplied inputs to prevent template syntax injection.
Restrict Template Variables: Do not pass sensitive configuration data to the template.


```
from flask import Flask, request, render_template_string, jsonify
import os
import html

app = Flask(__name__)

app.config["SITE_MISSION_STATEMENT"] = "Deliver Excellence to Our Clients"
app.config["SECRET_KEY"] = "TopSecretKey!"

# Mock "database" of snippet content
CMS_SNIPPETS = {
    "about_page": """
    <h2>Our Story</h2>
    <p>We started with a vision to {{ site_mission_statement | e }}.</p>
    <p>{{ next_snippet | e }}</p>
    """
}

@app.route("/render_snippet")
def render_snippet():
    """
    Secure render_snippet endpoint:
    1. Retrieves snippet from "database".
    2. Renders template once with sanitized user inputs.
    """
    snippet_key = request.args.get("snippet", "about_page")
    next_snippet_content = request.args.get("next_snippet", app.config["SITE_MISSION_STATEMENT"])

    snippet_template = CMS_SNIPPETS.get(snippet_key, "")
    if not snippet_template:
        return jsonify({"error": "Invalid snippet key"}), 400

    # Sanitize inputs by escaping HTML
    sanitized_next_snippet = html.escape(next_snippet_content)

    # Single render pass: fill in all placeholders securely
    rendered_html = render_template_string(
        snippet_template,
        site_mission_statement=app.config["SITE_MISSION_STATEMENT"],
        next_snippet=sanitized_next_snippet
    )

    return rendered_html

if __name__ == "__main__":
    app.run(port=7788, debug=True)

    ```
    
Key Changes:

Single Render Pass: Both site_mission_statement and next_snippet are filled in during one render pass.
HTML Escaping (| e): Ensures that any user-supplied input is escaped, preventing injection of template syntax.
No Second Render Pass: Eliminates the opportunity for SSTI by not re-rendering the output.
Testing the Secure Implementation:

Attempting to inject SSTI now results in the template syntax being escaped and displayed as literal text.

```
curl "http://localhost:7788/render_snippet?snippet=about_page&next_snippet={{ config['SECRET_KEY'] }}"
```



Expected Secure Response:

```
<h2>Our Story</h2>
<p>We started with a vision to Deliver Excellence to Our Clients.</p>
<p>{{ config['SECRET_KEY'] }}</p>
```


The injected {{ config['SECRET_KEY'] }} is escaped and rendered as plain text, not executed.

3. Secure Report Generation
Corrections Implemented:

Single Render Pass: Merge all report sections in one render pass, filling in all placeholders securely.
Sanitize Inputs: Escape user-supplied inputs to prevent template syntax injection.
Avoid Passing Sensitive Config to Templates: Do not expose configuration or environment variables to the templates.


```
from flask import Flask, request, render_template_string, jsonify
import os
import html

app = Flask(__name__)

app.config["COMPANY_NAME"] = "Galactic Enterprises"
app.config["SECRET_REPORT_KEY"] = "UltraSecretReportKey!"

# Mock "database" of report sections
SECTION_DB = {
    "introduction": "Welcome to {{ company_name | e }}'s quarterly report.\n\n{{ disclaimers | e }}",
    "financials": "<h3>Financial Overview</h3>\n<p>Net revenue increased by 15%...</p>\n{{ disclaimers | e }}"
}

@app.route("/generate_report")
def generate_report():
    """
    Secure generate_report endpoint:
    1. Merges multiple report sections into a master template.
    2. Renders template once with sanitized user inputs.
    """
    intro_section = SECTION_DB["introduction"]
    finance_section = SECTION_DB["financials"]

    # Merge sections into a "partial" master template
    partial_master_template = f"""
    <html>
    <body>
      <h1>Company Quarterly Report</h1>
      <div id="introduction">
        {intro_section}
      </div>
      <div id="financials">
        {finance_section}
      </div>
    </body>
    </html>
    """

    # Retrieve disclaimers from user input and sanitize
    disclaimers_content = request.args.get("disclaimers", "Confidential Information")

    sanitized_disclaimers = html.escape(disclaimers_content)

    # Single render pass: fill in all placeholders securely
    rendered_report = render_template_string(
        partial_master_template,
        company_name=app.config["COMPANY_NAME"],
        disclaimers=sanitized_disclaimers
    )

    return rendered_report

if __name__ == "__main__":
    app.run(port=7799, debug=True)

    ```

    
Key Changes:

Single Render Pass: Both company_name and disclaimers are filled in during one render pass.
HTML Escaping (| e): Ensures that any user-supplied input is escaped, preventing injection of template syntax.
No Second Render Pass: Eliminates the opportunity for SSTI by not re-rendering the output.
Testing the Secure Implementation:

Attempting to inject SSTI now results in the template syntax being escaped and displayed as literal text.

```
curl "http://localhost:7799/generate_report?disclaimers={{ config['SECRET_REPORT_KEY'] }}"
```

Expected Secure Response:


```
<html>
<body>
  <h1>Company Quarterly Report</h1>
  <div id="introduction">
    Welcome to Galactic Enterprises's quarterly report.

    {{ config['SECRET_REPORT_KEY'] }}
  </div>
  <div id="financials">
    <h3>Financial Overview</h3>
    <p>Net revenue increased by 15%...</p>
    {{ config['SECRET_REPORT_KEY'] }}
  </div>
</body>
</html>
```
The injected {{ config['SECRET_REPORT_KEY'] }} is escaped and rendered as plain text, not executed.

Security Best Practices & Mitigations
To safeguard Flask applications against double rendering and SSTI vulnerabilities, adhere to the following best practices:

Single Render Pass:

Always aim to render templates in a single pass.
Merge all necessary data and placeholders during this single rendering step.
Sanitize and Escape User Inputs:

Utilize Jinja2's built-in filters like | e (escape) to sanitize user-supplied data.
Avoid disabling auto-escaping unless absolutely necessary, and do so with caution.
Avoid Re-Rendering User Inputs as Templates:

Do not perform multiple render passes on user-supplied input.
If your workflow requires merging templates, ensure that user inputs are not interpreted as template syntax in subsequent passes.
Restrict Template Variables:

Limit the variables and context passed to templates.
Do not expose sensitive configuration data (like config or os.environ) to templates.
Use Template Sandboxing:

If dynamic template rendering is necessary (e.g., allowing admins to create custom templates), employ sandboxing techniques to restrict what can be executed within templates.
Libraries like Jinja Sandbox can help limit the scope of what templates can access.
Regular Code Reviews and Audits:

Regularly review template rendering logic to ensure no double rendering occurs.
Audit for any code that might inadvertently introduce re-rendering of user inputs.
Educate Development Teams:

Ensure that developers understand the risks associated with template rendering.
Provide guidelines and training on secure template practices.
