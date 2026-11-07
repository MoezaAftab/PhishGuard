/**
 * PhishGuard - Frontend Interaction & Sample Scenarios
 */

function switchTab(tabId) {
    // Hide all tabs
    const contents = document.querySelectorAll('.tab-content');
    contents.forEach(content => content.classList.remove('active'));

    // Deactivate all buttons
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => btn.classList.remove('active'));

    // Activate selected tab
    const target = document.getElementById(tabId);
    if (target) {
        target.classList.add('active');
    }

    // Activate corresponding button
    const activeBtn = Array.from(buttons).find(btn => btn.getAttribute('onclick').includes(tabId));
    if (activeBtn) {
        activeBtn.classList.add('active');
    }
}

function loadSample(scenario) {
    if (scenario === 'banking_phish') {
        switchTab('email-tab');
        document.getElementById('sender_input').value = 'PayPal Security Alert <support@paypa1-security-desk.xyz>';
        document.getElementById('subject_input').value = 'URGENT NOTICE: Your account has been suspended due to unauthorized access';
        document.getElementById('auth_input').value = 'spf=fail (IP 185.220.101.5 unauthorized) dkim=fail';
        document.getElementById('body_input').value = 
`Dear Customer,

We have detected multiple suspicious and unauthorized login attempts to your account. 

For your security, your account access has been restricted immediately. To restore access and avoid permanent termination within 24 hours, you are required to confirm your credentials and update billing information now:

Please click here to verify your account:
http://192.168.1.15/paypal-auth/verify-account?token=98afc103

Failure to complete this verification promptly will result in permanent forfeiture of your account balance.

Thank you,
PayPal Security Team`;
    } else if (scenario === 'malicious_url') {
        switchTab('url-tab');
        document.getElementById('url_input').value = 'http://secure-login.paypa1-update.xyz/verify-account?auth=login&token=981240';
    } else if (scenario === 'threat_intel_dns') {
        switchTab('url-tab');
        document.getElementById('url_input').value = 'https://emergency-banking-restore.duckdns.org/auth/login';
    } else if (scenario === 'safe_email') {
        switchTab('email-tab');
        document.getElementById('sender_input').value = 'Jane Miller <jane.miller@company.org>';
        document.getElementById('subject_input').value = 'Meeting Notes: Q4 Infrastructure & Security Architecture Roadmap';
        document.getElementById('auth_input').value = 'spf=pass (IP 198.51.100.1 verified) dkim=pass (signature ok) dmarc=pass';
        document.getElementById('body_input').value = 
`Hi Alex,

Thank you for participating in today's review of the Q4 infrastructure and cloud security roadmap.

I have updated the collaborative documentation with our action items and assigned ownership for the initial proof of concepts. 

Please review the notes when you have a moment before our sync next Tuesday. Have a great rest of your week!

Best regards,
Jane Miller
Engineering Lead`;
    }
}

function copyReportLink() {
    navigator.clipboard.writeText(window.location.href).then(() => {
        alert("Report link copied to clipboard!");
    }).catch(err => {
        console.error("Could not copy link: ", err);
    });
}
