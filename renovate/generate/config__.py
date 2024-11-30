import os,sys,re
import json

####
####

# Define a flexible structure for dependency managers and languages
CONFIG_TEMPLATES = {
    "npm": {
        "packageRules": [
            {
                "matchManagers": ["npm"],
                "matchUpdateTypes": ["minor", "patch"],
                "groupName": "Minor and Patch Updates"
            },
            {
                "matchManagers": ["npm"],
                "matchUpdateTypes": ["major"],
                "groupName": "Major Updates",
                "schedule": ["before 9am on monday"]
            }
        ]
    },
    "python": {
        "packageRules": [
            {
                "matchManagers": ["pip"],
                "groupName": "Python Pip Updates"
            }
        ]
    },
    "rust": {
        "packageRules": [
            {
                "matchManagers": ["cargo"],
                "groupName": "Rust Cargo Updates"
            }
        ]
    },
    "go": {
        "packageRules": [
            {
                "matchManagers": ["gomod"],
                "groupName": "Go Modules Updates"
            }
        ]
    },
    "java": {
        "packageRules": [
            {
                "matchManagers": ["maven"],
                "groupName": "Java Maven Updates"
            },
            {
                "matchManagers": ["gradle"],
                "groupName": "Java Gradle Updates"
            }
        ]
    },
    "docker": {
        "packageRules": [
            {
                "matchManagers": ["dockerfile"],
                "groupName": "Docker Updates"
            }
        ]
    },
    "github-actions": {
        "packageRules": [
            {
                "matchManagers": ["github-actions"],
                "groupName": "GitHub Actions Updates"
            }
        ]
    },
    "c_cpp": {
        "packageRules": [
            {
                "matchManagers": ["vcpkg"],
                "groupName": "C/C++ Vcpkg Updates"
            }
        ]
    }
}

# Define file patterns for detection
DETECTION_RULES = {
    "npm": ["package.json"],
    "python": ["requirements.txt", "Pipfile", "pyproject.toml"],
    "rust": ["Cargo.toml"],
    "go": ["go.mod"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "docker": ["Dockerfile"],
    "github-actions": [".github/workflows"],
    "c_cpp": ["CMakeLists.txt", "*.c", "*.cpp", "*.h", "*.hpp"]
}

def detect_managers(repo_path):
    """Detect dependency managers and languages in the repository."""
    detected_managers = set()
    for manager, patterns in DETECTION_RULES.items():
        for pattern in patterns:
            # Match files or directories
            for root, _, files in os.walk(repo_path):
                if pattern.startswith("*."):  # Handle extensions like *.c, *.cpp
                    if any(file.endswith(pattern[1:]) for file in files):
                        detected_managers.add(manager)
                        break
                elif os.path.exists(os.path.join(root, pattern)):
                    detected_managers.add(manager)
                    break
    return detected_managers

def generate_renovate_config(managers):
    """Generate Renovate configuration dynamically."""
    config = {
        "extends": ["config:recommended"],
        "rangeStrategy": "bump",
        "recreateWhen": "always",
        "rebaseStalePrs": True,
        "packageRules": [],
        "ignorePaths": ["**/node_modules/**", "**/artifacts/**", "**/test/**"],
        "forkProcessing": "enabled"
    }
    for manager in managers:
        if manager in CONFIG_TEMPLATES:
            config["packageRules"].extend(CONFIG_TEMPLATES[manager]["packageRules"])
    return config

def save_config(config, output_path="renovate.json"):
    """Save Renovate configuration to a file."""
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"Renovate configuration saved to {output_path}")

def main(repo_path="."):
    """Main function to generate Renovate config for a repository."""
    print(f"Analyzing repository at {repo_path}...")
    managers = detect_managers(repo_path)
    print(f"Detected managers and languages: {', '.join(managers) if managers else 'None'}")
    if not managers:
        print("No dependency managers detected. No config generated.")
        return
    config = generate_renovate_config(managers)
    save_config(config)

if __name__ == "__main__":
    repo_path = input("Enter the path to the repository (default: current directory): ").strip() or "."
    main(repo_path)

######
######
##
##

## To add support for a new language or pipeline:

"new_lang": ["new_file_pattern.ext"]
Add the corresponding Renovate packageRules to CONFIG_TEMPLATES:
python
Copy code
"new_lang": {
    "packageRules": [
        {
            "matchManagers": ["new_manager"],
            "groupName": "New Language Updates"
        }
    ]
}
# Example Output for a Mixed Repo
# For a repository with package.json, requirements.txt, Dockerfile, and Cargo.toml, the output renovate.json might look like:

{
  "extends": ["config:recommended"],
  "rangeStrategy": "bump",
  "recreateWhen": "always",
  "rebaseStalePrs": true,
  "packageRules": [
    {
      "matchManagers": ["npm"],
      "matchUpdateTypes": ["minor", "patch"],
      "groupName": "Minor and Patch Updates"
    },
    {
      "matchManagers": ["npm"],
      "matchUpdateTypes": ["major"],
      "groupName": "Major Updates",
      "schedule": ["before 9am on monday"]
    },
    {
      "matchManagers": ["pip"],
      "groupName": "Python Pip Updates"
    },
    {
      "matchManagers": ["dockerfile"],
      "groupName": "Docker Updates"
    },
    {
      "matchManagers": ["cargo"],
      "groupName": "Rust Cargo Updates"
    }
  ],
  "ignorePaths": ["**/node_modules/**", "**/artifacts/**", "**/test/**"],
  "forkProcessing": "enabled"
}

##
##
