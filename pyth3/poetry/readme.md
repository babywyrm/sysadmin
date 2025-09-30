

# 📝 Poetry Cheat Sheet (Python Dependency & Project Manager)

## 🔧 Basics

* Poetry is a modern tool for **dependency management and packaging** in Python.
* It replaces `requirements.txt` and `setup.py` with a single `pyproject.toml` file.
* It creates reproducible environments with `poetry.lock`.

---

## 📦 Installation

```bash
curl -sSL https://install.python-poetry.org | python3 -
# Or with pipx:
pipx install poetry
```

Check version:

```bash
poetry --version
```

---

## 📂 Create a New Project

```bash
poetry new my_project
# Creates:
# my_project/
# ├── pyproject.toml
# ├── README.md
# ├── my_project/__init__.py
# └── tests/
```

Or init in an existing repo:

```bash
poetry init
```

👉 interactive prompt to set project name, version, dependencies, etc.

---

## 📜 pyproject.toml Example

```toml
[tool.poetry]
name = "my_project"
version = "0.1.0"
description = "Example project"
authors = ["Your Name <you@example.com>"]

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
pandas = "^2.0.0"

[tool.poetry.dev-dependencies]
pytest = "^8.0.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
```

---

## 📥 Adding Dependencies

```bash
# Add main dependency
poetry add requests

# Add dev dependency
poetry add pytest --group dev
# (older versions: --dev)

# Add a specific version
poetry add "django@^5.0"

# Add from Git
poetry add git+https://github.com/org/repo.git
```

---

## 📤 Removing Dependencies

```bash
poetry remove requests
```

---

## 🔒 Lockfile

* `poetry.lock` freezes exact versions.
* Update lockfile:

```bash
poetry lock
poetry update
```

---

## ▶ Running Code

```bash
poetry run python main.py
poetry run pytest
```

Or spawn a shell:

```bash
poetry shell
```

---

## 🧪 Virtualenvs

Poetry automatically manages virtual environments.

```bash
poetry env list
poetry env use python3.11
poetry env remove python3.11
```

---

## 📦 Building & Publishing

```bash
poetry build        # creates .whl and .tar.gz
poetry publish      # upload to PyPI
poetry publish --build --username <user> --password <pass>
```

---

## 📚 Using Modules

Inside your project:

```python
# my_project/main.py
from my_project.utils import helper_func
```

Structure matters:

```
my_project/
  ├── pyproject.toml
  └── my_project/
      ├── __init__.py
      ├── main.py
      └── utils.py
```

When running:

```bash
poetry run python -m my_project.main
```

---

## ⚡ Pro Tips

* `poetry export -f requirements.txt --output requirements.txt`
  (useful if something still needs pip requirements)
* `poetry check` validates pyproject.toml
* `poetry show` lists installed deps
* `poetry show --tree` shows dependency graph
* `poetry version patch|minor|major` bumps version

---

👉 Think of Poetry as **npm for Python**:
`pyproject.toml` = package.json
`poetry.lock` = package-lock.json


##
##
