/**
 * DMARQ Frontend Application
 * Vanilla JS implementation replacing the React frontend
 */

// Global state management
const appState = {
    isAuthenticated: false,
    isSetupComplete: null,
    currentPage: null,
    user: null,
};

// API utility functions
const api = {
    baseUrl: '/api/v1',
    
    async request(endpoint, options = {}) {
        const token = localStorage.getItem('auth_token');
        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {}),
        };
        
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        const config = {
            ...options,
            headers,
        };
        
        const response = await fetch(`${this.baseUrl}${endpoint}`, config);
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'An error occurred' }));
            throw new Error(error.detail || 'API request failed');
        }
        
        return response.json();
    },
    
    // Authentication endpoints
    auth: {
        async login(username, password) {
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);
            
            const response = await fetch(`${api.baseUrl}/auth/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: formData,
            });
            
            if (!response.ok) {
                throw new Error('Login failed');
            }
            
            const data = await response.json();
            localStorage.setItem('auth_token', data.access_token);
            return data;
        },
        
        logout() {
            localStorage.removeItem('auth_token');
            appState.isAuthenticated = false;
            appState.user = null;
            router.navigate('/login');
        }
    },
    
    // System endpoints
    system: {
        async health() {
            return api.request('/health');
        }
    },
    
    // Domain endpoints
    domains: {
        async getAll() {
            return api.request('/domains');
        },
        
        async getById(id) {
            return api.request(`/domains/${id}`);
        }
    },
    
    // Reports endpoints
    reports: {
        async getAll() {
            return api.request('/reports');
        },
        
        async getById(id) {
            return api.request(`/reports/${id}`);
        }
    }
};

// Simple router implementation
const router = {
    routes: {
        '/': () => handleHome(),
        '/login': () => renderLogin(),
        '/dashboard': () => renderDashboard(),
        '/setup': () => renderSetup()
    },
    
    init() {
        // Initial route handling
        window.addEventListener('popstate', () => this.handleRouteChange());
        
        // Handle clicks on links to use client-side routing
        document.addEventListener('click', (e) => {
            if (e.target.matches('a[data-route]')) {
                e.preventDefault();
                this.navigate(e.target.getAttribute('href'));
            }
        });
        
        // Initial route
        this.handleRouteChange();
    },
    
    handleRouteChange() {
        const path = window.location.pathname;
        const route = this.routes[path];
        
        if (route) {
            route();
            appState.currentPage = path;
        } else {
            this.navigate('/');
        }
    },
    
    navigate(path) {
        window.history.pushState(null, null, path);
        this.handleRouteChange();
    }
};

// Handle initial app loading
async function initApp() {
    try {
        // Check if user is authenticated
        const token = localStorage.getItem('auth_token');
        appState.isAuthenticated = !!token;
        
        // Check system setup status
        const healthData = await api.system.health().catch(() => ({ is_setup_complete: false }));
        appState.isSetupComplete = healthData.is_setup_complete;
        
        // Determine which page to show
        handleHome();
    } catch (error) {
        console.error('Error initializing app:', error);
        showError('Failed to initialize the application');
    } finally {
        // Hide loading indicator
        document.getElementById('loading').classList.add('hidden');
    }
}

// Handle the home route based on app state
function handleHome() {
    if (!appState.isSetupComplete) {
        router.navigate('/setup');
    } else if (!appState.isAuthenticated) {
        router.navigate('/login');
    } else {
        router.navigate('/dashboard');
    }
}

// Helper function to show errors
function showError(message) {
    const errorEl = document.createElement('div');
    errorEl.className = 'error-message';
    errorEl.textContent = message;
    errorEl.style.cssText = 'background-color: #fee2e2; color: #b91c1c; padding: 1rem; border-radius: 0.25rem; margin-bottom: 1rem;';
    
    const app = document.getElementById('app');
    app.prepend(errorEl);
    
    setTimeout(() => {
        errorEl.remove();
    }, 5000);
}

// Initialize the app when DOM is fully loaded
document.addEventListener('DOMContentLoaded', initApp);
document.addEventListener('DOMContentLoaded', () => router.init());