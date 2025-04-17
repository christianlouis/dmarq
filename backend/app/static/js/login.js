/**
 * Login page functionality
 */

function renderLogin() {
    const appElement = document.getElementById('app');
    
    // Create login form HTML
    appElement.innerHTML = `
        <div class="auth-container">
            <div class="card">
                <h1>Login to DMARQ</h1>
                <form id="login-form">
                    <div>
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div>
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <div id="login-error" class="hidden" style="color: red; margin-top: 10px;"></div>
                    <div>
                        <button type="submit" id="login-button">Login</button>
                    </div>
                </form>
            </div>
        </div>
    `;
    
    // Add event listener to the login form
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const loginButton = document.getElementById('login-button');
        const loginError = document.getElementById('login-error');
        
        // Reset UI state
        loginError.classList.add('hidden');
        loginButton.disabled = true;
        loginButton.textContent = 'Logging in...';
        
        try {
            await api.auth.login(username, password);
            appState.isAuthenticated = true;
            router.navigate('/dashboard');
        } catch (error) {
            loginError.textContent = 'Invalid username or password';
            loginError.classList.remove('hidden');
        } finally {
            loginButton.disabled = false;
            loginButton.textContent = 'Login';
        }
    });
}