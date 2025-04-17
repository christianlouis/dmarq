/**
 * Setup Wizard functionality
 */

function renderSetup() {
    const appElement = document.getElementById('app');
    
    // Create setup wizard layout
    appElement.innerHTML = `
        <div class="auth-container" style="max-width: 600px;">
            <div class="card">
                <h1>DMARQ Setup Wizard</h1>
                
                <div class="setup-progress">
                    <div class="setup-step active" id="step-1">1. Admin Account</div>
                    <div class="setup-step" id="step-2">2. System Configuration</div>
                    <div class="setup-step" id="step-3">3. Email Configuration</div>
                </div>
                
                <div id="setup-content">
                    <!-- Step 1: Admin Account -->
                    <div id="setup-step-1" class="setup-form">
                        <h2>Create Admin Account</h2>
                        <form id="admin-setup-form">
                            <div>
                                <label for="admin-email">Email</label>
                                <input type="email" id="admin-email" name="admin-email" required>
                            </div>
                            <div>
                                <label for="admin-username">Username</label>
                                <input type="text" id="admin-username" name="admin-username" required>
                            </div>
                            <div>
                                <label for="admin-password">Password</label>
                                <input type="password" id="admin-password" name="admin-password" required>
                            </div>
                            <div>
                                <label for="admin-password-confirm">Confirm Password</label>
                                <input type="password" id="admin-password-confirm" name="admin-password-confirm" required>
                            </div>
                            <div id="admin-error" class="hidden" style="color: red; margin-top: 10px;"></div>
                            <div style="margin-top: 20px;">
                                <button type="submit" id="admin-next-button">Next</button>
                            </div>
                        </form>
                    </div>
                    
                    <!-- Step 2: System Configuration -->
                    <div id="setup-step-2" class="setup-form hidden">
                        <h2>System Configuration</h2>
                        <form id="system-setup-form">
                            <div>
                                <label for="app-name">Application Name</label>
                                <input type="text" id="app-name" name="app-name" value="DMARQ" required>
                            </div>
                            <div>
                                <label for="base-url">Base URL</label>
                                <input type="url" id="base-url" name="base-url" placeholder="https://your-dmarq-instance.com" required>
                            </div>
                            <div>
                                <label>
                                    <input type="checkbox" id="enable-cloudflare" name="enable-cloudflare">
                                    Enable Cloudflare Integration
                                </label>
                            </div>
                            <div id="cloudflare-settings" class="hidden">
                                <div>
                                    <label for="cloudflare-token">Cloudflare API Token</label>
                                    <input type="password" id="cloudflare-token" name="cloudflare-token">
                                </div>
                                <div>
                                    <label for="cloudflare-zone">Cloudflare Zone ID</label>
                                    <input type="text" id="cloudflare-zone" name="cloudflare-zone">
                                </div>
                            </div>
                            <div id="system-error" class="hidden" style="color: red; margin-top: 10px;"></div>
                            <div style="margin-top: 20px; display: flex; justify-content: space-between;">
                                <button type="button" id="system-prev-button">Previous</button>
                                <button type="submit" id="system-next-button">Next</button>
                            </div>
                        </form>
                    </div>
                    
                    <!-- Step 3: Email Configuration -->
                    <div id="setup-step-3" class="setup-form hidden">
                        <h2>Email Configuration</h2>
                        <form id="email-setup-form">
                            <div>
                                <label for="imap-server">IMAP Server</label>
                                <input type="text" id="imap-server" name="imap-server" required>
                            </div>
                            <div>
                                <label for="imap-port">IMAP Port</label>
                                <input type="number" id="imap-port" name="imap-port" value="993" required>
                            </div>
                            <div>
                                <label for="imap-username">IMAP Username</label>
                                <input type="text" id="imap-username" name="imap-username" required>
                            </div>
                            <div>
                                <label for="imap-password">IMAP Password</label>
                                <input type="password" id="imap-password" name="imap-password" required>
                            </div>
                            <div>
                                <button type="button" id="test-imap-button">Test Connection</button>
                                <span id="test-imap-result"></span>
                            </div>
                            <div id="email-error" class="hidden" style="color: red; margin-top: 10px;"></div>
                            <div style="margin-top: 20px; display: flex; justify-content: space-between;">
                                <button type="button" id="email-prev-button">Previous</button>
                                <button type="submit" id="email-finish-button">Finish Setup</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Add event listeners and setup functionality for the wizard
    setupWizardEventListeners();
}

function setupWizardEventListeners() {
    // Step 1: Admin Account setup
    const adminForm = document.getElementById('admin-setup-form');
    if (adminForm) {
        adminForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const email = document.getElementById('admin-email').value;
            const username = document.getElementById('admin-username').value;
            const password = document.getElementById('admin-password').value;
            const confirmPassword = document.getElementById('admin-password-confirm').value;
            const errorElement = document.getElementById('admin-error');
            
            // Simple validation
            if (password !== confirmPassword) {
                errorElement.textContent = 'Passwords do not match';
                errorElement.classList.remove('hidden');
                return;
            }
            
            // Store values (in a real app, you'd save these to the server)
            localStorage.setItem('setup_admin_email', email);
            localStorage.setItem('setup_admin_username', username);
            
            // Move to step 2
            goToStep(2);
        });
    }
    
    // Step 2: System Configuration
    const systemForm = document.getElementById('system-setup-form');
    if (systemForm) {
        // Toggle Cloudflare settings visibility
        const enableCloudflare = document.getElementById('enable-cloudflare');
        const cloudflareSettings = document.getElementById('cloudflare-settings');
        
        enableCloudflare.addEventListener('change', () => {
            if (enableCloudflare.checked) {
                cloudflareSettings.classList.remove('hidden');
            } else {
                cloudflareSettings.classList.add('hidden');
            }
        });
        
        // Previous button
        document.getElementById('system-prev-button').addEventListener('click', () => {
            goToStep(1);
        });
        
        // Next button
        systemForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            // Store values
            const appName = document.getElementById('app-name').value;
            const baseUrl = document.getElementById('base-url').value;
            
            localStorage.setItem('setup_app_name', appName);
            localStorage.setItem('setup_base_url', baseUrl);
            
            if (enableCloudflare.checked) {
                const cloudflareToken = document.getElementById('cloudflare-token').value;
                const cloudflareZone = document.getElementById('cloudflare-zone').value;
                
                localStorage.setItem('setup_cloudflare_enabled', 'true');
                localStorage.setItem('setup_cloudflare_token', cloudflareToken);
                localStorage.setItem('setup_cloudflare_zone', cloudflareZone);
            }
            
            // Move to step 3
            goToStep(3);
        });
    }
    
    // Step 3: Email Configuration
    const emailForm = document.getElementById('email-setup-form');
    if (emailForm) {
        // Previous button
        document.getElementById('email-prev-button').addEventListener('click', () => {
            goToStep(2);
        });
        
        // Test IMAP connection
        document.getElementById('test-imap-button').addEventListener('click', async () => {
            const testButton = document.getElementById('test-imap-button');
            const resultSpan = document.getElementById('test-imap-result');
            
            testButton.disabled = true;
            testButton.textContent = 'Testing...';
            resultSpan.textContent = '';
            
            try {
                // In a real app, you'd make an API call to test the connection
                // Here we'll just simulate it
                await new Promise(resolve => setTimeout(resolve, 1500));
                
                resultSpan.textContent = '✓ Connection successful';
                resultSpan.style.color = 'green';
            } catch (error) {
                resultSpan.textContent = '✗ Connection failed';
                resultSpan.style.color = 'red';
            } finally {
                testButton.disabled = false;
                testButton.textContent = 'Test Connection';
            }
        });
        
        // Finish setup
        emailForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const imapServer = document.getElementById('imap-server').value;
            const imapPort = document.getElementById('imap-port').value;
            const imapUsername = document.getElementById('imap-username').value;
            const imapPassword = document.getElementById('imap-password').value;
            
            const finishButton = document.getElementById('email-finish-button');
            const errorElement = document.getElementById('email-error');
            
            finishButton.disabled = true;
            finishButton.textContent = 'Completing Setup...';
            errorElement.classList.add('hidden');
            
            try {
                // In a real app, you'd send all the setup data to the server
                // For this example, we'll simulate the API call
                await new Promise(resolve => setTimeout(resolve, 2000));
                
                // Update app state
                appState.isSetupComplete = true;
                
                // Redirect to login
                router.navigate('/login');
            } catch (error) {
                errorElement.textContent = 'Setup failed: ' + (error.message || 'Unknown error');
                errorElement.classList.remove('hidden');
                finishButton.disabled = false;
                finishButton.textContent = 'Finish Setup';
            }
        });
    }
}

function goToStep(stepNumber) {
    // Hide all steps
    document.querySelectorAll('.setup-form').forEach(form => {
        form.classList.add('hidden');
    });
    
    // Show selected step
    document.getElementById(`setup-step-${stepNumber}`).classList.remove('hidden');
    
    // Update step indicators
    document.querySelectorAll('.setup-step').forEach((step, index) => {
        if (index + 1 === stepNumber) {
            step.classList.add('active');
        } else if (index + 1 < stepNumber) {
            step.classList.add('completed');
            step.classList.remove('active');
        } else {
            step.classList.remove('active', 'completed');
        }
    });
}