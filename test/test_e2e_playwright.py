"""
End-to-End Tests for Metasploit Framework using Playwright

This module contains comprehensive E2E tests for the Metasploit Framework
web interface, console functionality, and module interactions.
"""

import pytest
import os
from playwright.sync_api import Page, Browser, BrowserContext, expect
from test.playwright_config import (
    TEST_CONFIG, SELECTORS, TEST_DATA,
    setup_browser_context, login_as_admin,
    wait_for_command_completion, capture_console_output
)


class TestMetasploitWebInterface:
    """Test suite for Metasploit web interface functionality."""

    @pytest.fixture(autouse=True)
    def setup_page(self, page: Page):
        """Set up page for each test."""
        page.set_default_timeout(TEST_CONFIG["timeout"])
        yield page

    @pytest.mark.e2e
    def test_login_page_loads(self, page: Page):
        """Test that the login page loads correctly."""
        page.goto(f"{TEST_CONFIG['base_url']}/login")
        
        # Check page title
        expect(page).to_have_title("Metasploit Framework - Login")
        
        # Check login form elements
        expect(page.locator(SELECTORS["login"]["username_field"])).to_be_visible()
        expect(page.locator(SELECTORS["login"]["password_field"])).to_be_visible()
        expect(page.locator(SELECTORS["login"]["login_button"])).to_be_visible()

    @pytest.mark.e2e
    def test_successful_login(self, page: Page):
        """Test successful login with valid credentials."""
        login_as_admin(page)
        
        # Verify successful login
        expect(page.locator(SELECTORS["dashboard"]["welcome_message"])).to_be_visible()
        expect(page.locator(SELECTORS["dashboard"]["navigation_menu"])).to_be_visible()

    @pytest.mark.e2e
    def test_failed_login(self, page: Page):
        """Test login failure with invalid credentials."""
        page.goto(f"{TEST_CONFIG['base_url']}/login")
        
        page.fill(SELECTORS["login"]["username_field"], "invalid_user")
        page.fill(SELECTORS["login"]["password_field"], "invalid_pass")
        page.click(SELECTORS["login"]["login_button"])
        
        # Verify error message appears
        expect(page.locator(SELECTORS["login"]["error_message"])).to_be_visible()
        expect(page.locator(SELECTORS["login"]["error_message"])).to_contain_text("Invalid credentials")

    @pytest.mark.e2e
    def test_logout_functionality(self, page: Page):
        """Test logout functionality."""
        login_as_admin(page)
        
        # Click logout
        page.click(SELECTORS["dashboard"]["logout_button"])
        
        # Verify redirect to login page
        expect(page).to_have_url(f"{TEST_CONFIG['base_url']}/login")


class TestMetasploitConsole:
    """Test suite for Metasploit console functionality."""

    @pytest.fixture(autouse=True)
    def setup_authenticated_page(self, page: Page):
        """Set up authenticated page for console tests."""
        login_as_admin(page)
        page.goto(f"{TEST_CONFIG['base_url']}/console")
        yield page

    @pytest.mark.e2e
    def test_console_interface_loads(self, page: Page):
        """Test that the console interface loads correctly."""
        expect(page.locator(SELECTORS["exploit_console"]["command_input"])).to_be_visible()
        expect(page.locator(SELECTORS["exploit_console"]["execute_button"])).to_be_visible()
        expect(page.locator(SELECTORS["exploit_console"]["output_area"])).to_be_visible()

    @pytest.mark.e2e
    def test_help_command(self, page: Page):
        """Test executing the help command."""
        page.fill(SELECTORS["exploit_console"]["command_input"], "help")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        
        wait_for_command_completion(page)
        
        output = capture_console_output(page)
        assert "Core Commands" in output
        assert "Database Backend Commands" in output

    @pytest.mark.e2e
    def test_version_command(self, page: Page):
        """Test executing the version command."""
        page.fill(SELECTORS["exploit_console"]["command_input"], "version")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        
        wait_for_command_completion(page)
        
        output = capture_console_output(page)
        assert "Framework:" in output
        assert "Console:" in output

    @pytest.mark.e2e
    def test_show_exploits_command(self, page: Page):
        """Test listing available exploits."""
        page.fill(SELECTORS["exploit_console"]["command_input"], "show exploits")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        
        wait_for_command_completion(page, timeout=15000)  # Longer timeout for this command
        
        output = capture_console_output(page)
        assert "Name" in output
        assert "Disclosure Date" in output
        assert "Rank" in output

    @pytest.mark.e2e
    def test_search_command(self, page: Page):
        """Test searching for modules."""
        page.fill(SELECTORS["exploit_console"]["command_input"], "search type:exploit platform:linux")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        
        wait_for_command_completion(page)
        
        output = capture_console_output(page)
        assert "Matching Modules" in output or "exploit/linux" in output

    @pytest.mark.e2e
    def test_invalid_command(self, page: Page):
        """Test handling of invalid commands."""
        page.fill(SELECTORS["exploit_console"]["command_input"], "invalid_command_xyz")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        
        wait_for_command_completion(page)
        
        output = capture_console_output(page)
        assert "Unknown command" in output or "not found" in output


class TestModuleBrowser:
    """Test suite for module browser functionality."""

    @pytest.fixture(autouse=True)
    def setup_module_browser(self, page: Page):
        """Set up module browser page."""
        login_as_admin(page)
        page.goto(f"{TEST_CONFIG['base_url']}/modules")
        yield page

    @pytest.mark.e2e
    def test_module_browser_loads(self, page: Page):
        """Test that the module browser loads correctly."""
        expect(page.locator(SELECTORS["module_browser"]["search_input"])).to_be_visible()
        expect(page.locator(SELECTORS["module_browser"]["module_list"])).to_be_visible()

    @pytest.mark.e2e
    def test_module_search(self, page: Page):
        """Test searching for modules in the browser."""
        page.fill(SELECTORS["module_browser"]["search_input"], "http")
        page.press(SELECTORS["module_browser"]["search_input"], "Enter")
        
        # Wait for search results
        page.wait_for_timeout(2000)
        
        # Check that results contain HTTP-related modules
        module_items = page.locator(SELECTORS["module_browser"]["module_item"])
        expect(module_items.first).to_be_visible()

    @pytest.mark.e2e
    def test_module_details(self, page: Page):
        """Test viewing module details."""
        # Click on first module in the list
        first_module = page.locator(SELECTORS["module_browser"]["module_item"]).first
        first_module.click()
        
        # Check that module details are displayed
        expect(page.locator(".module-details")).to_be_visible()
        expect(page.locator(".module-description")).to_be_visible()
        expect(page.locator(".module-options")).to_be_visible()


class TestExploitExecution:
    """Test suite for exploit execution workflows."""

    @pytest.fixture(autouse=True)
    def setup_exploit_test(self, page: Page):
        """Set up page for exploit testing."""
        login_as_admin(page)
        page.goto(f"{TEST_CONFIG['base_url']}/console")
        yield page

    @pytest.mark.e2e
    @pytest.mark.slow
    def test_load_exploit_module(self, page: Page):
        """Test loading an exploit module."""
        # Use a safe test exploit
        command = "use auxiliary/scanner/http/http_version"
        page.fill(SELECTORS["exploit_console"]["command_input"], command)
        page.click(SELECTORS["exploit_console"]["execute_button"])
        
        wait_for_command_completion(page)
        
        # Check that module is loaded
        page.fill(SELECTORS["exploit_console"]["command_input"], "show options")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        
        wait_for_command_completion(page)
        
        output = capture_console_output(page)
        assert "RHOSTS" in output
        assert "RPORT" in output

    @pytest.mark.e2e
    @pytest.mark.slow
    def test_set_module_options(self, page: Page):
        """Test setting module options."""
        # Load a module first
        page.fill(SELECTORS["exploit_console"]["command_input"], "use auxiliary/scanner/http/http_version")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        wait_for_command_completion(page)
        
        # Set target
        page.fill(SELECTORS["exploit_console"]["command_input"], f"set RHOSTS {TEST_DATA['test_target']['host']}")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        wait_for_command_completion(page)
        
        # Verify option is set
        page.fill(SELECTORS["exploit_console"]["command_input"], "show options")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        wait_for_command_completion(page)
        
        output = capture_console_output(page)
        assert TEST_DATA['test_target']['host'] in output


class TestSecurityFeatures:
    """Test suite for security features and access controls."""

    @pytest.mark.e2e
    def test_unauthorized_access_blocked(self, page: Page):
        """Test that unauthorized access to console is blocked."""
        page.goto(f"{TEST_CONFIG['base_url']}/console")
        
        # Should be redirected to login
        expect(page).to_have_url(f"{TEST_CONFIG['base_url']}/login")

    @pytest.mark.e2e
    def test_session_timeout(self, page: Page):
        """Test session timeout functionality."""
        login_as_admin(page)
        
        # Simulate session timeout by clearing cookies
        page.context.clear_cookies()
        
        # Try to access protected resource
        page.goto(f"{TEST_CONFIG['base_url']}/console")
        
        # Should be redirected to login
        expect(page).to_have_url(f"{TEST_CONFIG['base_url']}/login")


class TestPerformance:
    """Test suite for performance-related tests."""

    @pytest.mark.e2e
    @pytest.mark.performance
    def test_page_load_performance(self, page: Page):
        """Test page load performance."""
        # Measure login page load time
        start_time = page.evaluate("() => performance.now()")
        page.goto(f"{TEST_CONFIG['base_url']}/login")
        page.wait_for_load_state("networkidle")
        end_time = page.evaluate("() => performance.now()")
        
        load_time = end_time - start_time
        assert load_time < 5000, f"Login page took {load_time}ms to load (should be < 5000ms)"

    @pytest.mark.e2e
    @pytest.mark.performance
    def test_console_response_time(self, page: Page):
        """Test console command response time."""
        login_as_admin(page)
        page.goto(f"{TEST_CONFIG['base_url']}/console")
        
        # Measure help command response time
        start_time = page.evaluate("() => performance.now()")
        page.fill(SELECTORS["exploit_console"]["command_input"], "help")
        page.click(SELECTORS["exploit_console"]["execute_button"])
        wait_for_command_completion(page)
        end_time = page.evaluate("() => performance.now()")
        
        response_time = end_time - start_time
        assert response_time < 10000, f"Help command took {response_time}ms (should be < 10000ms)"


# Fixtures for browser setup
@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Configure browser context arguments."""
    return {
        **browser_context_args,
        "viewport": {"width": 1280, "height": 720},
        "ignore_https_errors": True,
    }


@pytest.fixture(scope="function")
def context(browser: Browser):
    """Create a new browser context for each test."""
    context = setup_browser_context(browser)
    yield context
    context.close()


@pytest.fixture(scope="function") 
def page(context: BrowserContext):
    """Create a new page for each test."""
    page = context.new_page()
    yield page
    page.close()