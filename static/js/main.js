// Ayurvedic Healthcare Portal - Main JavaScript with Profile Dropdown

document.addEventListener('DOMContentLoaded', function() {
    console.log('Ayurvedic Healthcare Portal loaded');

    // Initialize all components
    initSidebarToggle();
    initUserTypeSelection();
    initFormValidation();
    initCaptcha();
    initPasswordToggle();
    initGoogleAuth();
    initDashboard();
    initMobileResponsive();
    initProfileDropdown();
    initProfileAvatars();
    enhanceProfileDropdown();

    // Auto-hide alerts after 5 seconds
    setTimeout(hideAlerts, 5000);
});

// Profile Dropdown Functionality
function initProfileDropdown() {
    const profileDropdown = document.querySelector('.profile-dropdown');
    const profileTrigger = document.querySelector('.profile-trigger');
    const profileMenu = document.querySelector('.profile-menu');

    if (!profileDropdown || !profileTrigger) return;

    // Toggle dropdown on click
    profileTrigger.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        toggleProfileDropdown();
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (!profileDropdown.contains(e.target)) {
            closeProfileDropdown();
        }
    });

    // Handle keyboard navigation
    profileTrigger.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            toggleProfileDropdown();
        }
        if (e.key === 'Escape') {
            closeProfileDropdown();
        }
    });

    // Handle menu item keyboard navigation
    const menuItems = document.querySelectorAll('.profile-option');
    menuItems.forEach((item, index) => {
        item.addEventListener('keydown', function(e) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                const nextItem = menuItems[index + 1];
                if (nextItem) nextItem.focus();
            }
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                const prevItem = menuItems[index - 1];
                if (prevItem) prevItem.focus();
                else profileTrigger.focus();
            }
            if (e.key === 'Escape') {
                closeProfileDropdown();
                profileTrigger.focus();
            }
        });
    });
}

function toggleProfileDropdown() {
    const profileDropdown = document.querySelector('.profile-dropdown');

    if (profileDropdown.classList.contains('open')) {
        closeProfileDropdown();
    } else {
        openProfileDropdown();
    }
}

function openProfileDropdown() {
    const profileDropdown = document.querySelector('.profile-dropdown');
    const dropdownArrow = document.querySelector('.dropdown-arrow');

    profileDropdown.classList.add('open');
    if (dropdownArrow) {
        dropdownArrow.textContent = '▲';
    }

    // Focus first menu item for keyboard navigation
    const firstMenuItem = document.querySelector('.profile-option');
    if (firstMenuItem) {
        setTimeout(() => firstMenuItem.focus(), 100);
    }
}

function closeProfileDropdown() {
    const profileDropdown = document.querySelector('.profile-dropdown');
    const dropdownArrow = document.querySelector('.dropdown-arrow');

    profileDropdown.classList.remove('open');
    if (dropdownArrow) {
        dropdownArrow.textContent = '▼';
    }
}

// Profile Menu Actions
function viewProfile() {
    closeProfileDropdown();
    AyurvedicPortal.showAlert('Profile page coming soon! Manage your personal information and preferences.', 'info');
}

function viewSettings() {
    closeProfileDropdown();
    AyurvedicPortal.showAlert('Settings page coming soon! Customize your account and privacy settings.', 'info');
}

function viewCart() {
    closeProfileDropdown();
    AyurvedicPortal.showAlert('Shopping cart coming soon! View your selected medicines and treatments.', 'info');
}

// Profile Avatar Color Generator
function generateAvatarColor(name) {
    const colors = [
        '#FF6F00', '#E91E63', '#9C27B0', '#673AB7', '#3F51B5',
        '#2196F3', '#03DAC6', '#4CAF50', '#8BC34A', '#CDDC39',
        '#FFC107', '#FF9800', '#FF5722', '#795548', '#607D8B'
    ];

    let hash = 0;
    for (let i = 0; i < name.length; i++) {
        hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }

    const colorIndex = Math.abs(hash) % colors.length;
    return colors[colorIndex];
}

// Initialize Profile Avatar Colors
function initProfileAvatars() {
    const userName = document.querySelector('.profile-name')?.textContent || 
                    document.querySelector('.profile-name-large')?.textContent;
    if (!userName) return;

    const avatarColor = generateAvatarColor(userName);
    const avatars = document.querySelectorAll('.profile-avatar, .profile-avatar-large');

    avatars.forEach(avatar => {
        avatar.style.background = avatarColor;
    });
}

// Enhanced Profile Dropdown with Animation
function enhanceProfileDropdown() {
    const profileMenu = document.querySelector('.profile-menu');
    if (!profileMenu) return;

    // Add stagger animation to menu items
    const menuItems = document.querySelectorAll('.profile-option');
    menuItems.forEach((item, index) => {
        item.style.opacity = '0';
        item.style.transform = 'translateX(-10px)';
        item.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
        item.style.transitionDelay = `${index * 50}ms`;
    });

    // Show items when dropdown opens
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.target.classList.contains('open')) {
                menuItems.forEach(item => {
                    item.style.opacity = '1';
                    item.style.transform = 'translateX(0)';
                });
            } else {
                menuItems.forEach(item => {
                    item.style.opacity = '0';
                    item.style.transform = 'translateX(-10px)';
                });
            }
        });
    });

    const profileDropdown = document.querySelector('.profile-dropdown');
    if (profileDropdown) {
        observer.observe(profileDropdown, { attributes: true, attributeFilter: ['class'] });
    }
}

// Update Cart Badge
function updateCartBadge(count) {
    const cartBadge = document.querySelector('.cart-badge');
    if (cartBadge) {
        cartBadge.textContent = count;

        // Add animation
        cartBadge.style.transform = 'scale(1.2)';
        setTimeout(() => {
            cartBadge.style.transform = 'scale(1)';
        }, 200);

        // Hide badge if count is 0
        if (count === 0) {
            cartBadge.style.display = 'none';
        } else {
            cartBadge.style.display = 'block';
        }
    }
}

// Sidebar Toggle Functionality
function initSidebarToggle() {
    const sidebar = document.querySelector('.sidebar');
    const dashboard = document.querySelector('.dashboard');
    const sidebarToggle = document.querySelector('.sidebar-toggle');

    if (!sidebar || !sidebarToggle) return;

    // Desktop sidebar toggle
    sidebarToggle.addEventListener('click', function(e) {
        e.preventDefault();
        toggleSidebar();
    });
}

function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const dashboard = document.querySelector('.dashboard');
    const sidebarToggle = document.querySelector('.sidebar-toggle');

    if (!sidebar) return;

    const isCollapsed = sidebar.classList.contains('collapsed');

    if (isCollapsed) {
        // Expand sidebar
        sidebar.classList.remove('collapsed');
        dashboard.classList.remove('sidebar-collapsed');
        sidebarToggle.innerHTML = '◀️';
        sidebarToggle.title = 'Collapse sidebar';
        localStorage.setItem('sidebarCollapsed', 'false');
    } else {
        // Collapse sidebar
        sidebar.classList.add('collapsed');
        dashboard.classList.add('sidebar-collapsed');
        sidebarToggle.innerHTML = '▶️';
        sidebarToggle.title = 'Expand sidebar';
        localStorage.setItem('sidebarCollapsed', 'true');
    }

    // showAlert(isCollapsed ? 'Sidebar expanded!' : 'Sidebar collapsed!', 'info');
}

// User Type Selection Handler
function initUserTypeSelection() {
    const userTypeCards = document.querySelectorAll('.user-type-card');
    const userTypeInput = document.getElementById('user_type');
    const doctorFields = document.getElementById('doctor-fields');

    userTypeCards.forEach(card => {
        card.addEventListener('click', function() {
            userTypeCards.forEach(c => c.classList.remove('selected'));
            this.classList.add('selected');

            const userType = this.dataset.type;
            if (userTypeInput) {
                userTypeInput.value = userType;
            }

            if (doctorFields) {
                if (userType === 'doctor') {
                    doctorFields.style.display = 'block';
                } else {
                    doctorFields.style.display = 'none';
                }
            }
        });
    });
}

// Form Validation
function initFormValidation() {
    const forms = document.querySelectorAll('form');

    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(this)) {
                e.preventDefault();
                return false;
            }
        });
    });
}

function validateForm(form) {
    let isValid = true;
    const inputs = form.querySelectorAll('input[required], select[required]');

    inputs.forEach(input => {
        if (!input.value.trim()) {
            isValid = false;
        }
    });

    return isValid;
}

// Captcha functionality
function initCaptcha() {
    generateCaptcha();

    const refreshBtn = document.getElementById('captcha-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', generateCaptcha);
    }
}

function generateCaptcha() {
    fetch('/generate-captcha')
        .then(response => response.json())
        .then(data => {
            const captchaDisplay = document.getElementById('captcha-display');
            if (captchaDisplay) {
                captchaDisplay.textContent = data.captcha;
            }
        })
        .catch(error => {
            console.error('Error generating captcha:', error);
        });
}

// Password visibility toggle
function initPasswordToggle() {
    // Implementation for password visibility toggle
}

// Google Authentication
function initGoogleAuth() {
    const googleBtn = document.getElementById('google-signin');
    if (googleBtn) {
        googleBtn.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = '/google-login';
        });
    }
}

// Dashboard functionality
function initDashboard() {
    // Load sidebar state from localStorage
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    const sidebar = document.querySelector('.sidebar');
    const dashboard = document.querySelector('.dashboard');
    const sidebarToggle = document.querySelector('.sidebar-toggle');

    if (isCollapsed && sidebar && window.innerWidth > 768) {
        sidebar.classList.add('collapsed');
        dashboard.classList.add('sidebar-collapsed');
        if (sidebarToggle) {
            sidebarToggle.innerHTML = '▶️';
            sidebarToggle.title = 'Expand sidebar';
        }
    }
}

// Mobile responsive functionality
function initMobileResponsive() {
    // Mobile responsive initialization
}

// Mobile Menu Toggle (Updated)
function toggleMobileMenu() {
    const navLinks = document.querySelector('.nav-links');
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');

    navLinks.classList.toggle('show');

    // Update mobile menu button appearance
    if (navLinks.classList.contains('show')) {
        mobileMenuBtn.innerHTML = '<span style="transform: rotate(45deg); transform-origin: center;"></span><span style="opacity: 0;"></span><span style="transform: rotate(-45deg); transform-origin: center;"></span>';
        document.body.style.overflow = 'hidden';
    } else {
        mobileMenuBtn.innerHTML = '<span></span><span></span><span></span>';
        document.body.style.overflow = '';
    }
}

// Alert system
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alert-container') || createAlertContainer();

    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="float: right; background: none; border: none; font-size: 1.2rem; cursor: pointer;">&times;</button>
    `;

    alertContainer.appendChild(alert);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alert.parentNode) {
            alert.remove();
        }
    }, 5000);
}

function createAlertContainer() {
    const container = document.createElement('div');
    container.id = 'alert-container';
    container.style.position = 'fixed';
    container.style.top = '20px';
    container.style.right = '20px';
    container.style.zIndex = '9999';
    container.style.maxWidth = '400px';

    document.body.appendChild(container);
    return container;
}

function hideAlerts() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        alert.style.opacity = '0';
        setTimeout(() => {
            if (alert.parentNode) {
                alert.remove();
            }
        }, 300);
    });
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Toggle sidebar with Ctrl/Cmd + B
    if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
        e.preventDefault();
        if (window.innerWidth > 768) {
            toggleSidebar();
        }
    }

    // Close profile dropdown with Escape
    if (e.key === 'Escape') {
        closeProfileDropdown();
    }
});


// Ayurvedic Healthcare Portal - Complete JavaScript with Navbar Options

document.addEventListener('DOMContentLoaded', function() {
    console.log('Ayurvedic Healthcare Portal loaded');

    // Initialize all components
    initNavbarOptions();
    loadLanguagePreference();
    loadThemePreference();

    // Start demo features
    setTimeout(simulateNotificationUpdates, 5000);
});

// Alert system
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alert-container') || createAlertContainer();

    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="float: right; background: none; border: none; font-size: 1.2rem; cursor: pointer;">&times;</button>
    `;

    alertContainer.appendChild(alert);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alert.parentNode) {
            alert.remove();
        }
    }, 5000);
}

function createAlertContainer() {
    const container = document.createElement('div');
    container.id = 'alert-container';
    container.style.position = 'fixed';
    container.style.top = '20px';
    container.style.right = '20px';
    container.style.zIndex = '9999';
    container.style.maxWidth = '400px';

    document.body.appendChild(container);
    return container;
}

// Export functions
window.AyurvedicPortal = {
    showAlert
};


// Navbar Options Functionality
function initNavbarOptions() {
    initSearchBar();
    initNotifications();
    initLanguageSelector();
    initThemeToggle();

    // Close all dropdowns when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.search-container')) {
            closeSearchBar();
        }
        if (!e.target.closest('.notifications-container')) {
            closeNotifications();
        }
        if (!e.target.closest('.language-container')) {
            closeLanguageSelector();
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Search shortcut: Ctrl/Cmd + K
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            toggleSearchBar();
        }

        // Theme toggle: Ctrl/Cmd + Shift + T
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'T') {
            e.preventDefault();
            toggleTheme();
        }

        // Close dropdowns with Escape
        if (e.key === 'Escape') {
            closeAllDropdowns();
        }
    });
}

// Search Bar Functionality
function initSearchBar() {
    const searchToggle = document.querySelector('.search-toggle');
    const searchBar = document.querySelector('.search-bar');
    const searchInput = document.querySelector('.search-input');
    const searchSubmit = document.querySelector('.search-submit');
    const searchClose = document.querySelector('.search-close');

    if (!searchToggle || !searchBar || !searchInput) return;

    searchToggle.addEventListener('click', function(e) {
        e.preventDefault();
        toggleSearchBar();
    });

    searchClose.addEventListener('click', function(e) {
        e.preventDefault();
        closeSearchBar();
    });

    searchSubmit.addEventListener('click', function(e) {
        e.preventDefault();
        performSearch();
    });

    searchInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            performSearch();
        }
        if (e.key === 'Escape') {
            closeSearchBar();
        }
    });

    // Search as you type (debounced)
    let searchTimeout;
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            if (this.value.length > 2) {
                showSearchSuggestions(this.value);
            }
        }, 300);
    });
}

function toggleSearchBar() {
    const searchBar = document.querySelector('.search-bar');
    const searchInput = document.querySelector('.search-input');

    if (searchBar.classList.contains('active')) {
        closeSearchBar();
    } else {
        openSearchBar();
    }
}

function openSearchBar() {
    const searchBar = document.querySelector('.search-bar');
    const searchInput = document.querySelector('.search-input');

    searchBar.classList.add('active');
    setTimeout(() => {
        searchInput.focus();
    }, 300);
}

function closeSearchBar() {
    const searchBar = document.querySelector('.search-bar');
    const searchInput = document.querySelector('.search-input');

    searchBar.classList.remove('active');
    searchInput.value = '';
    hideSearchSuggestions();
}

function performSearch() {
    const searchInput = document.querySelector('.search-input');
    const query = searchInput.value.trim();

    if (!query) return;

    AyurvedicPortal.showAlert(`Searching for: "${query}". Search functionality coming soon!`, 'info');

    // Here you would implement actual search functionality
    // Example: window.location.href = `/search?q=${encodeURIComponent(query)}`;
}

function showSearchSuggestions(query) {
    // Mock search suggestions
    const suggestions = [
        { icon: '👨‍⚕️', title: 'Dr. Rajesh Kumar', description: 'Ayurvedic Medicine Specialist' },
        { icon: '💊', title: 'Ashwagandha', description: 'Herbal medicine for stress relief' },
        { icon: '🧘', title: 'Meditation Therapy', description: 'Mindfulness and relaxation techniques' },
        { icon: '🌿', title: 'Panchakarma', description: 'Traditional detoxification treatment' }
    ];

    // Filter suggestions based on query
    const filteredSuggestions = suggestions.filter(item => 
        item.title.toLowerCase().includes(query.toLowerCase()) ||
        item.description.toLowerCase().includes(query.toLowerCase())
    );

    if (filteredSuggestions.length > 0) {
        displaySearchSuggestions(filteredSuggestions);
    } else {
        hideSearchSuggestions();
    }
}

function displaySearchSuggestions(suggestions) {
    const searchBar = document.querySelector('.search-bar');
    let searchResults = document.querySelector('.search-results');

    if (!searchResults) {
        searchResults = document.createElement('div');
        searchResults.className = 'search-results';
        searchBar.appendChild(searchResults);
    }

    searchResults.innerHTML = suggestions.map(item => `
        <div class="search-result-item" onclick="selectSearchResult('${item.title}')">
            <div class="search-result-icon">${item.icon}</div>
            <div class="search-result-content">
                <div class="search-result-title">${item.title}</div>
                <div class="search-result-description">${item.description}</div>
            </div>
        </div>
    `).join('');
}

function hideSearchSuggestions() {
    const searchResults = document.querySelector('.search-results');
    if (searchResults) {
        searchResults.remove();
    }
}

function selectSearchResult(title) {
    const searchInput = document.querySelector('.search-input');
    searchInput.value = title;
    performSearch();
    hideSearchSuggestions();
}

// Notifications Functionality
function initNotifications() {
    const notificationsToggle = document.querySelector('.notifications-toggle');
    const notificationsContainer = document.querySelector('.notifications-container');
    const markAllRead = document.querySelector('.mark-all-read');
    const viewAllButton = document.querySelector('.view-all-notifications');

    if (!notificationsToggle) return;

    notificationsToggle.addEventListener('click', function(e) {
        e.preventDefault();
        toggleNotifications();
    });

    if (markAllRead) {
        markAllRead.addEventListener('click', function(e) {
            e.preventDefault();
            markAllNotificationsRead();
        });
    }

    if (viewAllButton) {
        viewAllButton.addEventListener('click', function(e) {
            e.preventDefault();
            viewAllNotifications();
        });
    }

    // Make notification items clickable
    const notificationItems = document.querySelectorAll('.notification-item');
    notificationItems.forEach(item => {
        item.addEventListener('click', function() {
            markNotificationRead(this);
        });
    });
}

function toggleNotifications() {
    const notificationsContainer = document.querySelector('.notifications-container');

    if (notificationsContainer.classList.contains('open')) {
        closeNotifications();
    } else {
        openNotifications();
    }
}

function openNotifications() {
    const notificationsContainer = document.querySelector('.notifications-container');
    notificationsContainer.classList.add('open');

    // Add animation to notification items
    const items = document.querySelectorAll('.notification-item');
    items.forEach((item, index) => {
        item.style.animationDelay = `${index * 50}ms`;
        item.classList.add('fade-in');
    });
}

function closeNotifications() {
    const notificationsContainer = document.querySelector('.notifications-container');
    notificationsContainer.classList.remove('open');
}

function markAllNotificationsRead() {
    const unreadItems = document.querySelectorAll('.notification-item.unread');
    unreadItems.forEach(item => {
        item.classList.remove('unread');
    });

    updateNotificationBadge(0);
    AyurvedicPortal.showAlert('All notifications marked as read!', 'success');
}

function markNotificationRead(item) {
    if (item.classList.contains('unread')) {
        item.classList.remove('unread');
        item.classList.add('notification-bounce');

        // Update badge count
        const badge = document.querySelector('.notification-badge');
        const currentCount = parseInt(badge.textContent) || 0;
        updateNotificationBadge(Math.max(0, currentCount - 1));

        setTimeout(() => {
            item.classList.remove('notification-bounce');
        }, 500);
    }
}

function updateNotificationBadge(count) {
    const badge = document.querySelector('.notification-badge');
    if (badge) {
        if (count > 0) {
            badge.textContent = count;
            badge.style.display = 'block';
        } else {
            badge.style.display = 'none';
        }
    }
}

function addNotification(notification) {
    const notificationsList = document.querySelector('.notifications-list');
    if (!notificationsList) return;

    const notificationElement = document.createElement('div');
    notificationElement.className = 'notification-item unread fade-in';
    notificationElement.innerHTML = `
        <div class="notification-icon-wrapper">${notification.icon}</div>
        <div class="notification-content">
            <div class="notification-title">${notification.title}</div>
            <div class="notification-text">${notification.text}</div>
            <div class="notification-time">Just now</div>
        </div>
    `;

    notificationsList.insertBefore(notificationElement, notificationsList.firstChild);

    // Update badge
    const badge = document.querySelector('.notification-badge');
    const currentCount = parseInt(badge.textContent) || 0;
    updateNotificationBadge(currentCount + 1);

    // Make it clickable
    notificationElement.addEventListener('click', function() {
        markNotificationRead(this);
    });
}

function viewAllNotifications() {
    AyurvedicPortal.showAlert('Full notifications page coming soon!', 'info');
    closeNotifications();
}

// Language Selector Functionality
function initLanguageSelector() {
    const languageToggle = document.querySelector('.language-toggle');
    const languageOptions = document.querySelectorAll('.language-option');

    if (!languageToggle) return;

    languageToggle.addEventListener('click', function(e) {
        e.preventDefault();
        toggleLanguageSelector();
    });

    languageOptions.forEach(option => {
        option.addEventListener('click', function() {
            selectLanguage(this.dataset.lang);
        });
    });
}

function toggleLanguageSelector() {
    const languageContainer = document.querySelector('.language-container');

    if (languageContainer.classList.contains('open')) {
        closeLanguageSelector();
    } else {
        openLanguageSelector();
    }
}

function openLanguageSelector() {
    const languageContainer = document.querySelector('.language-container');
    languageContainer.classList.add('open');
}

function closeLanguageSelector() {
    const languageContainer = document.querySelector('.language-container');
    languageContainer.classList.remove('open');
}

function selectLanguage(langCode) {
    const languageOptions = document.querySelectorAll('.language-option');
    const languageText = document.querySelector('.language-text');

    // Remove active class from all options
    languageOptions.forEach(option => option.classList.remove('active'));

    // Add active class to selected option
    const selectedOption = document.querySelector(`[data-lang="${langCode}"]`);
    if (selectedOption) {
        selectedOption.classList.add('active');

        // Update display text
        const langMap = {
            'en': 'EN',
            'hi': 'हि',
            'sa': 'सं',
            'ta': 'த',
            'bn': 'বা',
            'gu': 'ગુ'
        };

        if (languageText) {
            languageText.textContent = langMap[langCode] || 'EN';
        }

        // Save preference
        localStorage.setItem('selectedLanguage', langCode);

        // Apply translation (mock implementation)
        applyLanguageTranslation(langCode);

        // AyurvedicPortal.showAlert(`Language changed to ${selectedOption.querySelector('.language-name').textContent}`, 'success');
    }

    closeLanguageSelector();
}

function applyLanguageTranslation(langCode) {
    // Mock translation implementation
    // In a real application, you would load translation files and apply them

    const translations = {
        'hi': {
            'Dashboard': 'डैशबोर्ड',
            'Profile': 'प्रोफाइल',
            'Settings': 'सेटिंग्स',
            'Logout': 'लॉग आउट'
        },
        'sa': {
            'Dashboard': 'नियंत्रण-पट्ट',
            'Profile': 'रूपरेखा',
            'Settings': 'व्यवस्था',
            'Logout': 'निर्गम'
        }
        // Add more translations as needed
    };

    if (translations[langCode]) {
        // Apply translations to elements with data-translate attributes
        document.querySelectorAll('[data-translate]').forEach(element => {
            const key = element.getAttribute('data-translate');
            if (translations[langCode][key]) {
                element.textContent = translations[langCode][key];
            }
        });
    }
}

// Load saved language preference
function loadLanguagePreference() {
    const savedLang = localStorage.getItem('selectedLanguage') || 'en';
    selectLanguage(savedLang);
}

// Theme Toggle Functionality
function initThemeToggle() {
    const themeToggle = document.querySelector('.theme-toggle');

    if (!themeToggle) return;

    themeToggle.addEventListener('click', function(e) {
        e.preventDefault();
        toggleTheme();
    });

    // Load saved theme
    loadThemePreference();
}

function toggleTheme() {
    const html = document.documentElement;
    const themeText = document.querySelector('.theme-text');

    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    html.setAttribute('data-theme', newTheme);

    if (themeText) {
        themeText.textContent = newTheme === 'dark' ? 'Dark' : 'Light';
    }

    // Save preference
    localStorage.setItem('theme', newTheme);

    // Add transition effect
    document.body.classList.add('theme-transition');
    setTimeout(() => {
        document.body.classList.remove('theme-transition');
    }, 300);

    AyurvedicPortal.showAlert(`Switched to ${newTheme} theme`, 'info');
}

function loadThemePreference() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    const html = document.documentElement;
    const themeText = document.querySelector('.theme-text');

    html.setAttribute('data-theme', savedTheme);

    if (themeText) {
        themeText.textContent = savedTheme === 'dark' ? 'Dark' : 'Light';
    }
}

// Utility function to close all dropdowns
function closeAllDropdowns() {
    closeSearchBar();
    closeNotifications();
    closeLanguageSelector();
    closeProfileDropdown();
}

// Auto-update notification badge (mock)
function simulateNotificationUpdates() {
    setInterval(() => {
        if (Math.random() < 0.1) { // 10% chance every interval
            const mockNotifications = [
                { icon: '📅', title: 'Appointment Reminder', text: 'Your appointment is in 30 minutes' },
                { icon: '💊', title: 'Medication Reminder', text: 'Time to take your evening medicine' },
                { icon: '🌟', title: 'Wellness Tip', text: 'Remember to practice deep breathing today' },
                { icon: '👨‍⚕️', title: 'Doctor Update', text: 'New treatment plan available' }
            ];

            const randomNotification = mockNotifications[Math.floor(Math.random() * mockNotifications.length)];
            addNotification(randomNotification);
        }
    }, 30000); // Check every 30 seconds
}

// Export navbar functions
window.NavbarOptions = {
    toggleSearch: toggleSearchBar,
    toggleNotifications: toggleNotifications,
    toggleLanguage: toggleLanguageSelector,
    toggleTheme: toggleTheme,
    addNotification: addNotification,
    closeAll: closeAllDropdowns
};

console.log('Navbar options functionality initialized');

// Update the viewProfile function in your JavaScript
function viewProfile() {
    closeProfileDropdown();
    // Redirect to profile page instead of showing alert
    window.location.href = '/normal_profile';
}


// Export functions for global access
window.AyurvedicPortal = {
    showAlert,
    hideAlerts,
    generateCaptcha,
    toggleSidebar
};

window.ProfileDropdown = {
    toggle: toggleProfileDropdown,
    open: openProfileDropdown,
    close: closeProfileDropdown,
    updateCartBadge: updateCartBadge
};

console.log('Ayurvedic Healthcare Portal with Profile Dropdown initialized successfully');
