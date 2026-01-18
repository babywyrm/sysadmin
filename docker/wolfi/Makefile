.PHONY: help install test build run stop clean reinstall all

# Configuration
IMAGE_NAME     := wolfi-webserver
CONTAINER_NAME := wolfi-web
PORT           := 6699

# Colors for output
GREEN  := \033[0;32m
YELLOW := \033[1;33m
RED    := \033[0;31m
NC     := \033[0m

help:
	@echo "$(GREEN)Wolfi Web Server - Management Commands$(NC)"
	@echo ""
	@echo "  make install   - Install local dev dependencies"
	@echo "  make test      - Run pytest suite"
	@echo "  make build     - Build the latest Wolfi Docker image"
	@echo "  make run       - Run the container on port $(PORT)"
	@echo "  make stop      - Stop & remove ANY container on port $(PORT)"
	@echo "  make reinstall - Complete Wipe: Stop, Clean, Build, and Run"
	@echo "  make clean     - Remove python cache and logs"

install:
	@echo "$(YELLOW)Installing dependencies...$(NC)"
	@pip install -q --upgrade pip
	@pip install -q -r requirements.txt -r requirements-dev.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

test:
	@echo "$(YELLOW)Running pytest suite...$(NC)"
	@pytest

build:
	@echo "$(YELLOW)Building Docker image...$(NC)"
	@docker build -t $(IMAGE_NAME):latest .
	@echo "$(GREEN)✓ Image built: $(IMAGE_NAME):latest$(NC)"

stop:
	@echo "$(YELLOW)Cleaning up port $(PORT)...$(NC)"
	@# 1. Attempt to stop by specific name
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@# 2. Find and kill ANY container occupying the target port
	@ID=$$(docker ps -q --filter "publish=$(PORT)"); \
	if [ -n "$$ID" ]; then \
		echo "$(YELLOW)Found container $$ID on port $(PORT). Stopping...$(NC)"; \
		docker stop $$ID && docker rm $$ID; \
	fi
	@echo "$(GREEN)✓ Port $(PORT) is clear$(NC)"

run:
	@echo "$(YELLOW)Starting container on http://localhost:$(PORT)...$(NC)"
	@docker run -d \
		--name $(CONTAINER_NAME) \
		-p $(PORT):$(PORT) \
		--restart unless-stopped \
		$(IMAGE_NAME):latest
	@echo "$(GREEN)✓ Container started: $(CONTAINER_NAME)$(NC)"

clean:
	@echo "$(YELLOW)Cleaning local cache files...$(NC)"
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@rm -rf htmlcov .coverage
	@echo "$(GREEN)✓ Cleaned$(NC)"

reinstall: stop clean build run
	@echo "$(GREEN)✓ Reinstall complete. Application is fresh.$(NC)"

all: install test build run
