# Playwright Configuration for Metasploit Framework
# This file configures Playwright for end-to-end testing

import os
from playwright.sync_api import Playwright, Browser, BrowserContext, Page

# Test configuration
TEST_CONFIG = {
    "base_url": os.getenv("TEST_BASE_URL", "http://localhost:3000"),
    "timeout": int(os.getenv("TEST_TIMEOUT", "30000")),  # 30 seconds
    "headless": os.getenv("TEST_HEADLESS", "true").lower() == "true",
    "slow_mo": int(os.getenv("TEST_SLOW_MO", "0")),  # Slow down by N ms
    "video_dir": os.getenv("TEST_VIDEO_DIR", "test-results/videos"),
    "screenshot_dir": os.getenv("TEST_SCREENSHOT_DIR", "test-results/screenshots"),
    "trace_dir": os.getenv("TEST_TRACE_DIR", "test-results/traces"),
}

# Browser configuration
BROWSER_CONFIG = {
    "chromium": {
        "args": [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-web-security",
            "--allow-running-insecure-content",
        ]
    },
    "firefox": {
        "args": [
            "--no-sandbox",
        ]
    },
    "webkit": {
        "args": []
    }
}

# Test data and fixtures
TEST_DATA = {
    "admin_user": {
        "username": os.getenv("TEST_ADMIN_USER", "admin"),
        "password": os.getenv("TEST_ADMIN_PASS", "password123"),
    },
    "test_user": {
        "username": os.getenv("TEST_USER", "testuser"),
        "password": os.getenv("TEST_USER_PASS", "testpass123"),
    },
    "test_target": {
        "host": os.getenv("TEST_TARGET_HOST", "127.0.0.1"),
        "port": int(os.getenv("TEST_TARGET_PORT", "80")),
    }
}

# Page object patterns and selectors
SELECTORS = {
    "login": {
        "username_field": "#username",
        "password_field": "#password",
        "login_button": "button[type='submit']",
        "error_message": ".error-message",
    },
    "dashboard": {
        "welcome_message": ".welcome",
        "navigation_menu": ".nav-menu",
        "logout_button": "#logout",
    },
    "exploit_console": {
        "command_input": "#command-input",
        "execute_button": "#execute",
        "output_area": "#output",
        "clear_button": "#clear",
    },
    "module_browser": {
        "search_input": "#module-search",
        "module_list": ".module-list",
        "module_item": ".module-item",
        "load_button": ".load-module",
    }
}

# Utility functions for common test operations
def setup_browser_context(browser: Browser) -> BrowserContext:
    """Set up browser context with common configuration."""
    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        record_video_dir=TEST_CONFIG["video_dir"] if TEST_CONFIG.get("record_video") else None,
        record_video_size={"width": 1280, "height": 720},
    )
    
    # Enable tracing for debugging
    context.tracing.start(screenshots=True, snapshots=True, sources=True)
    
    return context

def login_as_admin(page: Page) -> None:
    """Helper function to log in as admin user."""
    page.goto(f"{TEST_CONFIG['base_url']}/login")
    page.fill(SELECTORS["login"]["username_field"], TEST_DATA["admin_user"]["username"])
    page.fill(SELECTORS["login"]["password_field"], TEST_DATA["admin_user"]["password"])
    page.click(SELECTORS["login"]["login_button"])
    page.wait_for_selector(SELECTORS["dashboard"]["welcome_message"])

def wait_for_command_completion(page: Page, timeout: int = 10000) -> None:
    """Wait for command execution to complete in the console."""
    page.wait_for_function(
        "() => !document.querySelector('#execute').disabled",
        timeout=timeout
    )

def capture_console_output(page: Page) -> str:
    """Capture the current console output."""
    return page.text_content(SELECTORS["exploit_console"]["output_area"])

def clear_console(page: Page) -> None:
    """Clear the console output."""
    page.click(SELECTORS["exploit_console"]["clear_button"])

# Test environment setup
def setup_test_environment():
    """Set up test environment variables and directories."""
    os.makedirs(TEST_CONFIG["video_dir"], exist_ok=True)
    os.makedirs(TEST_CONFIG["screenshot_dir"], exist_ok=True)
    os.makedirs(TEST_CONFIG["trace_dir"], exist_ok=True)

# Cleanup utilities
def cleanup_test_artifacts():
    """Clean up test artifacts after test runs."""
    import shutil
    
    for dir_path in [TEST_CONFIG["video_dir"], TEST_CONFIG["screenshot_dir"], TEST_CONFIG["trace_dir"]]:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
            os.makedirs(dir_path, exist_ok=True)