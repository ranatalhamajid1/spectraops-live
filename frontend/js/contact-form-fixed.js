// FIXED CONTACT FORM - NO SYNTAX ERRORS - 2025-06-11 09:35:59 UTC
console.log('📞 Loading FIXED Contact Form (No Syntax Errors)...');

// Constants
const CURRENT_TIME = '2025-06-11T09:35:59Z';
const CURRENT_USER = 'ranatalhamajid1';

console.log('📅 Current Time: ' + CURRENT_TIME);
console.log('👤 Current User: ' + CURRENT_USER);
console.log('🌍 Location: Islamabad, Pakistan');

// FIXED form validation function
function validateContactFormFixed() {
    console.log('🔍 Starting FIXED contact form validation...');
    
    var formData = {};
    
    try {
        var fullNameField = document.getElementById('fullName');
        var emailField = document.getElementById('email');
        var phoneField = document.getElementById('phoneNumber');
        var companyField = document.getElementById('companyName');
        var serviceField = document.getElementById('serviceInterest');
        var subjectField = document.getElementById('subject');
        var messageField = document.getElementById('message');
        var mathField = document.getElementById('mathAnswer');
        
        formData.fullName = fullNameField ? fullNameField.value.trim() : '';
        formData.email = emailField ? emailField.value.trim() : '';
        formData.phoneNumber = phoneField ? phoneField.value.trim() : '';
        formData.companyName = companyField ? companyField.value.trim() : '';
        formData.serviceInterest = serviceField ? serviceField.value.trim() : '';
        formData.subject = subjectField ? subjectField.value.trim() : '';
        formData.message = messageField ? messageField.value.trim() : '';
        formData.mathAnswer = mathField ? mathField.value.trim() : '';
        formData.mathProblem = '1 + 5';
    } catch (error) {
        console.error('❌ Error getting form data:', error);
        return {
            isValid: false,
            errors: ['Error reading form data. Please try again.'],
            data: formData
        };
    }
    
    console.log('📋 FIXED Form Data Retrieved:');
    console.log('   fullName: "' + formData.fullName + '"');
    console.log('   email: "' + formData.email + '"');
    console.log('   phoneNumber: "' + formData.phoneNumber + '"');
    console.log('   companyName: "' + formData.companyName + '"');
    console.log('   serviceInterest: "' + formData.serviceInterest + '"');
    console.log('   subject: "' + formData.subject + '"');
    console.log('   message: "' + formData.message + '"');
    console.log('   mathAnswer: "' + formData.mathAnswer + '"');

    // Validation rules
    var errors = [];
    
    // Full name validation
    if (!formData.fullName || formData.fullName.length < 1) {
        errors.push('Full Name is required');
        console.log('❌ Full name validation failed: empty or missing');
    } else if (formData.fullName.length < 2) {
        errors.push('Full Name must be at least 2 characters');
        console.log('❌ Full name validation failed: too short (' + formData.fullName.length + ' chars)');
    } else {
        console.log('✅ Full name validation passed: "' + formData.fullName + '"');
    }
    
    // Email validation
    if (!formData.email || !isValidEmailFixed(formData.email)) {
        errors.push('Valid Email Address is required');
        console.log('❌ Email validation failed: "' + formData.email + '"');
    } else {
        console.log('✅ Email validation passed: ' + formData.email);
    }
    
    // Subject validation
    if (!formData.subject || formData.subject.length < 1) {
        errors.push('Subject is required');
        console.log('❌ Subject validation failed: empty or missing');
    } else {
        console.log('✅ Subject validation passed: "' + formData.subject + '"');
    }
    
    // Message validation
    if (!formData.message || formData.message.length < 1) {
        errors.push('Message is required');
        console.log('❌ Message validation failed: empty or missing');
    } else {
        console.log('✅ Message validation passed: "' + formData.message + '"');
    }
    
    // Math validation (1 + 5 = 6)
    var expectedAnswer = 6;
    var providedAnswer = parseInt(formData.mathAnswer);
    
    if (!formData.mathAnswer) {
        errors.push('Please solve the math problem: 1 + 5 = ?');
        console.log('❌ Math answer missing');
    } else if (isNaN(providedAnswer) || providedAnswer !== expectedAnswer) {
        errors.push('Math problem incorrect. 1 + 5 = 6, you entered: ' + formData.mathAnswer);
        console.log('❌ Math validation failed: Expected 6, got ' + providedAnswer);
    } else {
        console.log('✅ Math validation passed: 1 + 5 = ' + providedAnswer);
    }

    console.log('🔍 Validation Results: ' + (errors.length === 0 ? 'PASSED ✅' : 'FAILED ❌'));
    if (errors.length > 0) {
        console.log('❌ Validation Errors:');
        for (var i = 0; i < errors.length; i++) {
            console.log('   ' + (i + 1) + '. ' + errors[i]);
        }
    }

    return {
        isValid: errors.length === 0,
        errors: errors,
        data: formData
    };
}

// Email validation function
function isValidEmailFixed(email) {
    var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// FIXED form submission - PREVENTS AUTO REFRESH
function submitContactFormFixed(event) {
    // CRITICAL: Prevent default form submission and page refresh
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    console.log('🚀 FIXED CONTACT FORM SUBMISSION STARTED (NO REFRESH)');
    console.log('   Timestamp: ' + CURRENT_TIME);
    console.log('   User: ' + CURRENT_USER);
    console.log('   Event prevented: ✅');
    
    // Clear previous messages
    clearMessagesFixed();
    
    // Validate form
    var validation = validateContactFormFixed();
    
    if (!validation.isValid) {
        console.log('❌ Form validation failed - showing error message');
        showMessageFixed(validation.errors[0], 'error');
        return false;
    }
    
    console.log('✅ Form validation passed - submitting to server...');
    
    // Show loading state
    showLoadingFixed(true);
    
    var requestData = {
        fullName: validation.data.fullName,
        email: validation.data.email,
        phoneNumber: validation.data.phoneNumber,
        companyName: validation.data.companyName,
        serviceInterest: validation.data.serviceInterest,
        subject: validation.data.subject,
        message: validation.data.message,
        mathAnswer: validation.data.mathAnswer,
        mathProblem: validation.data.mathProblem,
        timestamp: CURRENT_TIME,
        currentUser: CURRENT_USER,
        location: 'Islamabad, Pakistan',
        source: 'fixed_no_syntax_errors_v9',
        userAgent: navigator.userAgent,
        referrer: document.referrer || 'direct'
    };
    
    console.log('📤 FIXED Request Data being sent:');
    console.log(JSON.stringify(requestData, null, 2));
    
    // Make the API request
    fetch('/api/contact', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-User': CURRENT_USER,
            'X-Timestamp': CURRENT_TIME,
            'X-Location': 'Islamabad, Pakistan'
        },
        body: JSON.stringify(requestData)
    })
    .then(function(response) {
        console.log('📥 Response Status: ' + response.status + ' ' + response.statusText);
        
        if (!response.ok) {
            throw new Error('HTTP ' + response.status + ': ' + response.statusText);
        }
        
        return response.json();
    })
    .then(function(result) {
        console.log('📥 FIXED Response Data:');
        console.log(JSON.stringify(result, null, 2));
        
        if (result.success) {
            console.log('✅ CONTACT FORM SUBMITTED SUCCESSFULLY! 🎉');
            console.log('   Contact ID: ' + result.contactId);
            console.log('   Reference: ' + result.referenceNumber);
            console.log('   Priority: ' + result.priority);
            
            showMessageFixed(
                '✅ Message sent successfully!\n\n📋 Reference: ' + result.referenceNumber + '\n⏱️ Response Time: ' + result.estimatedResponse + '\n🎯 Priority: ' + result.priority + '\n\nThank you for contacting SpectraOps!',
                'success'
            );
            resetFormFixed();
            
            // Scroll to success message
            var messageContainer = document.getElementById('messageContainer');
            if (messageContainer) {
                messageContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        } else {
            console.error('❌ Server returned error:');
            console.error(result);
            showMessageFixed(result.message || 'Failed to send message. Please try again.', 'error');
        }
    })
    .catch(function(error) {
        console.error('❌ Network/Request error:');
        console.error(error);
        showMessageFixed('Network error: ' + error.message + '. Please check your connection and try again.', 'error');
    })
    .finally(function() {
        showLoadingFixed(false);
        console.log('🏁 Contact form submission process completed (NO REFRESH)');
    });
    
    return false; // Ensure no form submission
}

// UI Helper Functions
function showMessageFixed(message, type) {
    var container = document.getElementById('messageContainer');
    if (container) {
        container.innerHTML = '<div class="message ' + type + '">' + message.replace(/\n/g, '<br>') + '</div>';
        console.log('📢 Message displayed: ' + type + ' - ' + message);
    } else {
        console.error('❌ Message container not found');
        alert(type.toUpperCase() + ': ' + message);
    }
}

function clearMessagesFixed() {
    var container = document.getElementById('messageContainer');
    if (container) {
        container.innerHTML = '';
    }
}

function showLoadingFixed(loading) {
    var submitBtn = document.getElementById('submitBtn');
    if (submitBtn) {
        if (loading) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sending...';
            console.log('⏳ Loading state activated');
        } else {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Send Message';
            console.log('✅ Loading state deactivated');
        }
    } else {
        console.error('❌ Submit button not found');
    }
}

function resetFormFixed() {
    var form = document.getElementById('contactForm');
    if (form) {
        var fields = ['fullName', 'email', 'phoneNumber', 'companyName', 'serviceInterest', 'subject', 'message', 'mathAnswer'];
        for (var i = 0; i < fields.length; i++) {
            var field = document.getElementById(fields[i]);
            if (field) {
                field.value = '';
            }
        }
        console.log('🔄 Form reset successfully (no page refresh)');
    } else {
        console.error('❌ Contact form not found for reset');
    }
}

// FIXED Initialize contact form - PREVENT AUTO REFRESH
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 FIXED Contact Form initializing (No Auto-Refresh)...');
    
    // Find the contact form
    var contactForm = document.getElementById('contactForm');
    if (contactForm) {
        // CRITICAL: Remove any existing event listeners and prevent default submission
        contactForm.onsubmit = function(event) {
            event.preventDefault();
            event.stopPropagation();
            submitContactFormFixed(event);
            return false;
        };
        
        // Also bind to submit event
        contactForm.addEventListener('submit', function(event) {
            event.preventDefault();
            event.stopPropagation();
            submitContactFormFixed(event);
            return false;
        });
        
        console.log('✅ Contact form submission bound (NO REFRESH)');
        
        // Bind to submit button click
        var submitBtn = document.getElementById('submitBtn');
        if (submitBtn) {
            submitBtn.onclick = function(event) {
                event.preventDefault();
                event.stopPropagation();
                submitContactFormFixed(event);
                return false;
            };
            console.log('✅ Submit button click bound (NO REFRESH)');
        }
        
        // Set math answer hint
        var mathInput = document.getElementById('mathAnswer');
        if (mathInput) {
            mathInput.placeholder = 'Answer: 6';
            mathInput.setAttribute('data-expected-answer', '6');
            console.log('✅ Math input configured');
        }
        
        console.log('✅ FIXED Contact Form ready - NO AUTO REFRESH! 🚫🔄');
    } else {
        console.error('❌ Contact form not found in DOM');
    }
});

// Test functions for debugging
window.testContactFormFixed = function() {
    console.log('🧪 Testing FIXED contact form (no refresh)...');
    var validation = validateContactFormFixed();
    console.log('Test Results:', validation);
    return validation;
};

window.manualSubmitFixed = function() {
    console.log('🧪 Manual submit test...');
    submitContactFormFixed();
};

console.log('✅ FIXED Contact Form script loaded - NO AUTO REFRESH, NO SYNTAX ERRORS! 🚫🔄');