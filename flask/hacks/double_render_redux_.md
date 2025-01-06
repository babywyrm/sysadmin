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
