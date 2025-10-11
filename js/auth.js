/**
 * Authentication Module for Trinetra Security Scanner
 * Handles JWT token management, authentication state, and API calls
 */

// API Configuration
const API_BASE_URL = 'http://localhost:8000';
const TOKEN_STORAGE_KEY = 'trinetra_auth_token';
const USER_STORAGE_KEY = 'trinetra_user_info';
const TOKEN_CHECK_INTERVAL = 60000; // Check token validity every minute

/**
 * Authentication Manager Class
 */
class AuthManager {
    constructor() {
        this.token = null;
        this.tokenExpiry = null;
        this.user = null;
        this.checkInterval = null;

        // Load token and user from localStorage on initialization
        this.loadFromStorage();

        // Start periodic token validity check
        if (this.isAuthenticated()) {
            this.startTokenCheck();
        }
    }

    /**
     * Load authentication data from localStorage
     */
    loadFromStorage() {
        try {
            const tokenData = localStorage.getItem(TOKEN_STORAGE_KEY);
            if (tokenData) {
                const parsed = JSON.parse(tokenData);
                this.token = parsed.token;
                this.tokenExpiry = parsed.expiry;

                // Check if token is expired
                if (this.isTokenExpired()) {
                    this.clearAuth();
                }
            }

            const userData = localStorage.getItem(USER_STORAGE_KEY);
            if (userData) {
                this.user = JSON.parse(userData);
            }
        } catch (error) {
            console.error('Error loading auth data from storage:', error);
            this.clearAuth();
        }
    }

    /**
     * Save authentication data to localStorage
     * @param {string} token - JWT token
     * @param {number} expiresIn - Token expiry timestamp (milliseconds)
     * @param {object} user - User information
     */
    setAuthToken(token, expiresIn, user = null) {
        this.token = token;
        this.tokenExpiry = expiresIn;

        if (user) {
            this.user = user;
            localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
        }

        localStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify({
            token: token,
            expiry: expiresIn
        }));

        // Start periodic token check
        this.startTokenCheck();
    }

    /**
     * Set user information
     * @param {object} user - User data
     */
    setUserInfo(user) {
        this.user = user;
        localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
    }

    /**
     * Get current authentication token
     * @returns {string|null} JWT token or null if not authenticated
     */
    getToken() {
        if (this.isTokenExpired()) {
            this.clearAuth();
            return null;
        }
        return this.token;
    }

    /**
     * Get current user information
     * @returns {object|null} User data or null if not authenticated
     */
    getUser() {
        return this.user;
    }

    /**
     * Check if token is expired
     * @returns {boolean} True if token is expired or invalid
     */
    isTokenExpired() {
        if (!this.tokenExpiry) {
            return true;
        }

        // Check if current time is past expiry time
        return Date.now() >= this.tokenExpiry;
    }

    /**
     * Check if user is authenticated
     * @returns {boolean} True if authenticated with valid token
     */
    isAuthenticated() {
        return this.token !== null && !this.isTokenExpired();
    }

    /**
     * Clear authentication data (logout)
     */
    clearAuth() {
        this.token = null;
        this.tokenExpiry = null;
        this.user = null;
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        localStorage.removeItem(USER_STORAGE_KEY);

        // Stop token check interval
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
            this.checkInterval = null;
        }
    }

    /**
     * Start periodic token validity check
     * Automatically logs out user when token expires
     */
    startTokenCheck() {
        // Clear existing interval if any
        if (this.checkInterval) {
            clearInterval(this.checkInterval);
        }

        // Check token validity every minute
        this.checkInterval = setInterval(() => {
            if (this.isTokenExpired()) {
                console.warn('Token expired - logging out');
                this.logout(true);
            }
        }, TOKEN_CHECK_INTERVAL);
    }

    /**
     * Login user with credentials
     * @param {object} credentials - Login credentials { userid, password, role_id }
     * @returns {Promise<object>} User data and token
     */
    async login(credentials) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(credentials)
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Login failed');
            }

            // Store authentication data
            this.setAuthToken(data.token, data.expires_in, data.user);

            return data;
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }

    /**
     * Logout user (client-side and optional server-side)
     * @param {boolean} isExpired - Whether logout is due to token expiry
     */
    async logout(isExpired = false) {
        const token = this.token;

        // Clear local authentication data first
        this.clearAuth();

        // Notify server to blacklist token (optional)
        if (token) {
            try {
                await fetch(`${API_BASE_URL}/api/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
            } catch (error) {
                console.error('Server logout notification failed:', error);
                // Continue with client-side logout even if server call fails
            }
        }

        // Redirect to login page
        if (isExpired) {
            alert('Your session has expired. Please login again.');
        }

        window.location.href = '/login';
    }

    /**
     * Verify token with server
     * @returns {Promise<object>} User data if token is valid
     */
    async verifyToken() {
        const token = this.getToken();

        if (!token) {
            throw new Error('No authentication token');
        }

        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/verify`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                // Token is invalid or expired
                this.clearAuth();
                throw new Error('Token verification failed');
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Token verification error:', error);
            this.clearAuth();
            throw error;
        }
    }

    /**
     * Make authenticated API request
     * @param {string} endpoint - API endpoint (relative to base URL)
     * @param {object} options - Fetch options
     * @returns {Promise<object>} Response data
     */
    async authenticatedFetch(endpoint, options = {}) {
        const token = this.getToken();

        if (!token) {
            throw new Error('Not authenticated');
        }

        // Add authorization header
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
            'Authorization': `Bearer ${token}`
        };

        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                ...options,
                headers
            });

            // Check for authentication errors
            if (response.status === 401 || response.status === 403) {
                // Token expired or invalid
                this.clearAuth();
                window.location.href = '/login';
                throw new Error('Authentication failed');
            }

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `Request failed with status ${response.status}`);
            }

            // Handle non-JSON responses (like file downloads)
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }

            return response;
        } catch (error) {
            console.error('Authenticated fetch error:', error);
            throw error;
        }
    }

    /**
     * Check authentication and redirect if not authenticated
     * Call this on protected pages
     */
    requireAuth() {
        if (!this.isAuthenticated()) {
            window.location.href = '/login';
            return false;
        }
        return true;
    }

    /**
     * Update profile section in navbar with user info
     */
    updateNavbarProfile() {
        if (!this.isAuthenticated() || !this.user) {
            return;
        }

        // Show profile section, hide auth buttons
        const authButtons = document.getElementById('authButtons');
        const profileSection = document.getElementById('profileSection');
        const usernameDisplay = document.getElementById('username');

        if (authButtons) {
            authButtons.style.display = 'none';
        }

        if (profileSection) {
            profileSection.classList.remove('hidden');
        }

        if (usernameDisplay) {
            usernameDisplay.textContent = this.user.userid || 'User';
        }

        // Add logout handler
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                this.logout(false);
            });
        }
    }
}

// Create global instance
const Auth = new AuthManager();

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Auth;
}
