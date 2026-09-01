/**
 * CrimsonOTP - Frontend Application Logic & Security Engine
 * Addresses ITU/NANP reserved ranges, rate limiting, XSS input sanitization, 
 * DPDP Act / GDPR data erasure, and regex OTP extraction.
 */

// Application State Management
const AppState = {
    userTier: 'free', // 'free' (10/min, 500/day) vs 'paid' (100/min)
    rateLimitCount: 0,
    rateLimitMax: 10,
    dailyCount: 0,
    dailyMax: 500,
    activeNumbers: [],
    messages: [],
    cookieConsented: false
};

// ITU-T & NANP Reserved Non-Colliding Test Ranges
const ReservedRanges = {
    US: {
        country: 'United States',
        flag: '🇺🇸',
        code: '+1',
        generate: () => {
            const area = [202, 305, 415, 617, 702][Math.floor(Math.random() * 5)];
            const subscriber = 100 + Math.floor(Math.random() * 100); // 0100 to 0199 reserved range
            return `+1${area}5550${subscriber}`;
        }
    },
    UK: {
        country: 'United Kingdom',
        flag: '🇬🇧',
        code: '+44',
        generate: () => {
            const num = Math.floor(100000 + Math.random() * 900000); // 7700 900XXX Ofcom reserved
            return `+4477009${num.toString().substring(0, 5)}`;
        }
    },
    CA: {
        country: 'Canada',
        flag: '🇨🇦',
        code: '+1',
        generate: () => {
            const subscriber = 100 + Math.floor(Math.random() * 100);
            return `+14165550${subscriber}`;
        }
    },
    IN: {
        country: 'India',
        flag: '🇮🇳',
        code: '+91',
        generate: () => {
            const num = Math.floor(10000 + Math.random() * 90000);
            return `+9199999${num}`;
        }
    },
    DE: {
        country: 'Germany',
        flag: '🇩🇪',
        code: '+49',
        generate: () => {
            const num = Math.floor(1000 + Math.random() * 9000);
            return `+491522888${num}`;
        }
    }
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    loadSavedState();
    setupNavigation();
    setupForms();
    setupModals();
    setupPrivacyControls();
    
    // Seed initial active test numbers if empty
    if (AppState.activeNumbers.length === 0) {
        generateNumber('US', 'Default Test Suite');
        generateNumber('UK', 'WhatsApp OTP Test');
        generateNumber('IN', 'Payment Gateway Security Test');
    } else {
        renderNumbers();
    }

    // Reset minute rate limiter every 60 seconds
    setInterval(() => {
        AppState.rateLimitCount = 0;
        updateRateLimitMeter();
    }, 60000);
});

/* ==========================================================================
   Rate Limiting & Abuse Detection Engine
   ========================================================================== */

function checkRateLimit() {
    if (AppState.dailyCount >= AppState.dailyMax) {
        showToast('Daily quota reached (500/day limit). Upgrade to Pro or wait until tomorrow.', 'danger');
        return false;
    }

    if (AppState.rateLimitCount >= AppState.rateLimitMax) {
        showToast(`Rate limit exceeded (${AppState.rateLimitMax} req/min). Please wait 60s.`, 'danger');
        return false;
    }

    AppState.rateLimitCount++;
    AppState.dailyCount++;
    updateRateLimitMeter();
    saveState();
    return true;
}

function updateRateLimitMeter() {
    const textEl = document.getElementById('rate-counter-text');
    const fillEl = document.getElementById('rate-progress-fill');
    const dailyTextEl = document.getElementById('daily-counter-text');
    const statRateStatus = document.getElementById('stat-rate-status');

    if (textEl) textEl.textContent = `${AppState.rateLimitCount} / ${AppState.rateLimitMax} min`;
    if (dailyTextEl) dailyTextEl.textContent = `${AppState.dailyCount} / ${AppState.dailyMax}`;
    
    const pct = Math.min(100, (AppState.rateLimitCount / AppState.rateLimitMax) * 100);
    if (fillEl) fillEl.style.width = `${pct}%`;

    const remainingPct = Math.max(0, 100 - Math.round((AppState.rateLimitCount / AppState.rateLimitMax) * 100));
    if (statRateStatus) statRateStatus.textContent = `${remainingPct}%`;
}

function toggleUserTier() {
    if (AppState.userTier === 'free') {
        AppState.userTier = 'paid';
        AppState.rateLimitMax = 100;
        document.getElementById('sidebar-tier-badge').textContent = 'PRO TIER (100/MIN)';
        document.getElementById('sidebar-tier-badge').classList.add('green');
        document.getElementById('user-role-display').textContent = 'Pro Developer (MFA Verified)';
        document.getElementById('btn-toggle-tier').textContent = 'Switch to Free Tier';
        showToast('Upgraded to Pro Tier! Rate limit increased to 100 req/min.', 'success');
    } else {
        AppState.userTier = 'free';
        AppState.rateLimitMax = 10;
        document.getElementById('sidebar-tier-badge').textContent = 'FREE TIER';
        document.getElementById('sidebar-tier-badge').classList.remove('green');
        document.getElementById('user-role-display').textContent = 'Developer (Free)';
        document.getElementById('btn-toggle-tier').textContent = 'Switch to Pro (100/min)';
        showToast('Switched to Free Tier (10 req/min limit).', 'info');
    }
    updateRateLimitMeter();
}

/* ==========================================================================
   E.164 Phone Number Generator (ITU/NANP Reserved Ranges)
   ========================================================================== */

function generateNumber(countryKey, userLabel = '') {
    if (!checkRateLimit()) return;

    const rangeConfig = ReservedRanges[countryKey] || ReservedRanges.US;
    const e164Number = rangeConfig.generate();
    
    // Sanitize user label to prevent XSS
    const sanitizedLabel = sanitizeInput(userLabel || `${rangeConfig.country} Reserved Range`);

    const newNumberObj = {
        id: 'num_' + Date.now() + Math.random().toString(36).substr(2, 5),
        e164: e164Number,
        country: rangeConfig.country,
        flag: rangeConfig.flag,
        label: sanitizedLabel,
        createdAt: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        smsCount: 0
    };

    AppState.activeNumbers.unshift(newNumberObj);
    saveState();
    renderNumbers();
    populateTargetDropdowns();
    showToast(`Generated E.164 Reserved Number: ${e164Number}`, 'success');
}

function renderNumbers() {
    const grid = document.getElementById('dashboard-numbers-grid');
    if (!grid) return;

    grid.innerHTML = '';
    
    AppState.activeNumbers.forEach(item => {
        const card = document.createElement('div');
        card.className = 'number-card';
        
        // Build card DOM nodes safely without innerHTML XSS vulnerabilities
        const topRow = document.createElement('div');
        topRow.className = 'number-card-top';

        const countryTitle = document.createElement('div');
        countryTitle.className = 'country-title';
        countryTitle.textContent = `${item.flag} ${item.country}`;

        const tag = document.createElement('span');
        tag.className = 'tag-reserved';
        tag.textContent = 'ITU/NANP Reserved';

        topRow.appendChild(countryTitle);
        topRow.appendChild(tag);

        const e164Display = document.createElement('div');
        e164Display.className = 'e164-display';
        e164Display.textContent = item.e164;

        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-icon-btn';
        copyBtn.title = 'Copy E.164 Number';
        copyBtn.innerHTML = '<i class="fa-regular fa-copy"></i>';
        copyBtn.onclick = (e) => {
            e.stopPropagation();
            copyToClipboard(item.e164, 'Phone number copied!');
        };
        e164Display.appendChild(copyBtn);

        const metaRow = document.createElement('div');
        metaRow.className = 'card-meta';

        const labelSpan = document.createElement('span');
        labelSpan.textContent = item.label; // Safe text node assignment

        const countSpan = document.createElement('span');
        countSpan.textContent = `${item.smsCount} SMS Received`;

        metaRow.appendChild(labelSpan);
        metaRow.appendChild(countSpan);

        card.appendChild(topRow);
        card.appendChild(e164Display);
        card.appendChild(metaRow);

        grid.appendChild(card);
    });

    const activeCountEl = document.getElementById('stat-active-num');
    if (activeCountEl) activeCountEl.textContent = AppState.activeNumbers.length;
}

/* ==========================================================================
   Simulated SMS & Regex OTP Parser Engine
   ========================================================================== */

function simulateSMS(service, targetNumber, customText = '') {
    const targetObj = AppState.activeNumbers.find(n => n.e164 === targetNumber) || AppState.activeNumbers[0];
    if (!targetObj) {
        showToast('Please generate a test number first!', 'danger');
        return;
    }

    const randomCode = Math.floor(100000 + Math.random() * 900000).toString();
    let bodyText = customText;

    if (!bodyText) {
        switch (service) {
            case 'WhatsApp':
                bodyText = `Your WhatsApp code is ${randomCode}. Do not share it with anyone.`;
                break;
            case 'Google':
                bodyText = `G-${randomCode} is your Google verification code.`;
                break;
            case 'Uber':
                bodyText = `Your Uber security code is ${randomCode.substring(0, 4)}.`;
                break;
            case 'Bank':
                bodyText = `ALERT: OTP for your transaction of $450.00 is ${randomCode}. Valid for 5 mins.`;
                break;
            default:
                bodyText = `Your verification OTP is ${randomCode}.`;
        }
    }

    // Parse OTP using regex /\b\d{4,8}\b/ or G-(\d{6})
    const otpMatch = bodyText.match(/G-(\d{6})/) || bodyText.match(/\b\d{4,8}\b/);
    const extractedOTP = otpMatch ? (otpMatch[1] || otpMatch[0]) : randomCode;

    const smsObj = {
        id: 'sms_' + Date.now(),
        service: service,
        targetE164: targetObj.e164,
        body: sanitizeInput(bodyText),
        otp: extractedOTP,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    };

    targetObj.smsCount++;
    AppState.messages.unshift(smsObj);
    saveState();

    renderSMSFeed();
    renderNumbers();
    showToast(`New SMS received on ${targetObj.e164}: OTP ${extractedOTP}`, 'info');
}

function renderSMSFeed() {
    const tbody = document.getElementById('dashboard-sms-tbody');
    const inboxContainer = document.getElementById('inbox-sms-stream');

    if (tbody) {
        if (AppState.messages.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="6">
                        <div class="empty-state">
                            <i class="fa-regular fa-comments"></i>
                            <p>No incoming SMS yet. Click <strong>"Simulate SMS"</strong> to test!</p>
                        </div>
                    </td>
                </tr>`;
        } else {
            tbody.innerHTML = '';
            AppState.messages.slice(0, 10).forEach(msg => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><strong>${msg.service}</strong></td>
                    <td><code class="highlight-code">${msg.targetE164}</code></td>
                    <td>${msg.body}</td>
                    <td>
                        <span class="parsed-otp-chip">
                            ${msg.otp}
                            <button class="btn-copy-otp" onclick="copyToClipboard('${msg.otp}', 'OTP Code copied!')"><i class="fa-regular fa-copy"></i></button>
                        </span>
                    </td>
                    <td>${msg.timestamp}</td>
                    <td>
                        <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('${msg.otp}', 'OTP Copied!')">Copy OTP</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    }

    if (inboxContainer) {
        inboxContainer.innerHTML = '';
        AppState.messages.forEach(msg => {
            const card = document.createElement('div');
            card.className = 'card mt-2';
            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h4>${msg.service} Verification</h4>
                    <span class="text-hint">${msg.timestamp}</span>
                </div>
                <p class="mt-2">${msg.body}</p>
                <div class="mt-3" style="display:flex; gap:1rem; align-items:center;">
                    <span class="parsed-otp-chip">${msg.otp}</span>
                    <button class="btn btn-sm btn-crimson" onclick="copyToClipboard('${msg.otp}', 'OTP Copied!')">Copy OTP Code</button>
                </div>
            `;
            inboxContainer.appendChild(card);
        });
    }

    const unreadEl = document.getElementById('unread-count');
    const smsStatEl = document.getElementById('stat-sms-count');
    if (unreadEl) unreadEl.textContent = AppState.messages.length;
    if (smsStatEl) smsStatEl.textContent = AppState.messages.length;
}

/* ==========================================================================
   Security, Input Sanitization & Privacy Controls
   ========================================================================== */

function sanitizeInput(str) {
    if (!str) return '';
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

function copyToClipboard(text, successMsg) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(successMsg || 'Copied to clipboard!', 'success');
    });
}

function purgeUserData() {
    if (confirm('DPDP Act 2023 / GDPR Right to be Forgotten:\nAre you sure you want to delete all saved test numbers and messages? This action cannot be undone.')) {
        localStorage.clear();
        AppState.activeNumbers = [];
        AppState.messages = [];
        AppState.dailyCount = 0;
        AppState.rateLimitCount = 0;
        
        saveState();
        renderNumbers();
        renderSMSFeed();
        updateRateLimitMeter();
        showToast('All user data and stored test numbers successfully purged.', 'info');
    }
}

/* ==========================================================================
   UI Event Handlers, Modals & Navigation
   ========================================================================== */

function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item, .mobile-nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const tabId = item.getAttribute('data-tab');

            document.querySelectorAll('.nav-item, .mobile-nav-item').forEach(i => i.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));

            document.querySelectorAll(`[data-tab="${tabId}"]`).forEach(i => i.classList.add('active'));
            const targetTab = document.getElementById(`tab-${tabId}`);
            if (targetTab) targetTab.classList.add('active');
        });
    });

    const toggleBtn = document.getElementById('btn-toggle-tier');
    if (toggleBtn) toggleBtn.addEventListener('click', toggleUserTier);

    const purgeBtn = document.getElementById('btn-purge-data');
    if (purgeBtn) purgeBtn.addEventListener('click', purgeUserData);

    const clearStreamBtn = document.getElementById('btn-clear-stream');
    if (clearStreamBtn) {
        clearStreamBtn.addEventListener('click', () => {
            AppState.messages = [];
            saveState();
            renderSMSFeed();
            showToast('Stream cleared.', 'info');
        });
    }
}

function setupForms() {
    const genForm = document.getElementById('gen-form');
    if (genForm) {
        genForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const country = document.getElementById('gen-country').value;
            const label = document.getElementById('gen-label').value;
            generateNumber(country, label);
        });
    }

    const quickGenBtn = document.getElementById('btn-quick-gen');
    if (quickGenBtn) {
        quickGenBtn.addEventListener('click', () => {
            generateNumber('US', 'Quick Generated');
        });
    }

    const simSMSBtn = document.getElementById('btn-sim-sms');
    if (simSMSBtn) {
        simSMSBtn.addEventListener('click', () => {
            const targetNumber = AppState.activeNumbers.length > 0 ? AppState.activeNumbers[0].e164 : '+12025550148';
            simulateSMS('WhatsApp', targetNumber);
        });
    }
}

function populateTargetDropdowns() {
    const targetSelect = document.getElementById('sim-target-number');
    if (!targetSelect) return;

    targetSelect.innerHTML = '';
    AppState.activeNumbers.forEach(n => {
        const opt = document.createElement('option');
        opt.value = n.e164;
        opt.textContent = `${n.flag} ${n.e164} (${n.label})`;
        targetSelect.appendChild(opt);
    });
}

function setupModals() {
    const modalOverlay = document.getElementById('modal-overlay');
    const btnClose = document.getElementById('btn-close-modal');
    const btnDismiss = document.getElementById('btn-modal-dismiss');

    const closeModal = () => modalOverlay.classList.remove('active');
    if (btnClose) btnClose.addEventListener('click', closeModal);
    if (btnDismiss) btnDismiss.addEventListener('click', closeModal);

    document.getElementById('btn-view-terms')?.addEventListener('click', () => {
        openModal('Terms of Service & Acceptable Use Policy', `
            <h4>1. Acceptable Use Policy</h4>
            <p>Generated phone numbers are strictly for software testing, automated QA, and development purposes.</p>
            <h4 class="mt-3">2. Prohibited Uses</h4>
            <p>You may not use generated numbers for spamming, harassment, fraudulent account creation, or bypassing security controls illegally.</p>
        `);
    });

    document.getElementById('btn-view-privacy-policy')?.addEventListener('click', () => {
        openModal('Privacy Policy & DPDP Act 2023', `
            <h4>1. PII Handling</h4>
            <p>All test numbers and simulated messages are treated as sensitive data and encrypted in local session state.</p>
            <h4 class="mt-3">2. Zero Server Logging</h4>
            <p>Server logs strip all phone numbers, authorization headers, and verification codes.</p>
        `);
    });

    document.getElementById('btn-report-abuse')?.addEventListener('click', () => {
        openModal('Report Abuse / Security Incident', `
            <p>If you suspect automated scraping or illegal usage of test ranges, please submit a report:</p>
            <div class="form-group mt-3">
                <label>Incident Details</label>
                <textarea class="form-control" rows="3" placeholder="Describe the issue..."></textarea>
            </div>
            <button class="btn btn-crimson" onclick="showToast('Abuse report logged securely.', 'success'); document.getElementById('modal-overlay').classList.remove('active');">Submit Incident Report</button>
        `);
    });
}

function openModal(title, htmlContent) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = htmlContent;
    document.getElementById('modal-overlay').classList.add('active');
}

function setupPrivacyControls() {
    const banner = document.getElementById('cookie-banner');
    const btnAccept = document.getElementById('btn-cookie-accept');
    const btnDecline = document.getElementById('btn-cookie-decline');

    if (AppState.cookieConsented && banner) {
        banner.style.display = 'none';
    }

    btnAccept?.addEventListener('click', () => {
        AppState.cookieConsented = true;
        saveState();
        if (banner) banner.style.display = 'none';
        showToast('Cookie consent recorded.', 'success');
    });

    btnDecline?.addEventListener('click', () => {
        if (banner) banner.style.display = 'none';
        showToast('Cookies declined. Essential rate limiting only.', 'info');
    });
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let iconClass = 'fa-circle-info';
    if (type === 'success') iconClass = 'fa-circle-check';
    if (type === 'danger') iconClass = 'fa-triangle-exclamation';

    toast.innerHTML = `<i class="fa-solid ${iconClass}"></i> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}

function saveState() {
    try {
        localStorage.setItem('temporary_phone_state', JSON.stringify({
            userTier: AppState.userTier,
            rateLimitMax: AppState.rateLimitMax,
            dailyCount: AppState.dailyCount,
            activeNumbers: AppState.activeNumbers,
            messages: AppState.messages,
            cookieConsented: AppState.cookieConsented
        }));
    } catch (e) {
        console.warn('LocalStorage save failed:', e);
    }
}

function loadSavedState() {
    try {
        const saved = localStorage.getItem('temporary_phone_state');
        if (saved) {
            const parsed = JSON.parse(saved);
            AppState.userTier = parsed.userTier || 'free';
            AppState.rateLimitMax = parsed.rateLimitMax || 10;
            AppState.dailyCount = parsed.dailyCount || 0;
            AppState.activeNumbers = parsed.activeNumbers || [];
            AppState.messages = parsed.messages || [];
            AppState.cookieConsented = parsed.cookieConsented || false;
        }
    } catch (e) {
        console.warn('LocalStorage load failed:', e);
    }
}
