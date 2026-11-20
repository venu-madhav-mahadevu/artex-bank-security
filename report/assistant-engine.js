/* Venu Assistant retrieval engine — shared by the chat page and the floating widget.
   Pure client-side RAG-over-docs: TF-IDF retrieval with synonyms, light stemming,
   typo tolerance, related-topic suggestions, and multi-topic answers. No external AI. */
(function () {
  "use strict";

  // ---- Knowledge base -------------------------------------------------------
  var KB = [
    {id:"what", title:"What ARTEX is", tags:"what is artex define definition overview tool framework explain",
     a:"<b>ARTEX</b> is an open-source, AI-driven autonomous penetration-testing framework. Released on GitHub on 26 July 2026 by a developer called Autumn-27 under the AGPL-3.0 licence, it uses LLM agents to run security tests end to end — reconnaissance through exploitation — with a web dashboard.", s:"Report"},
    {id:"who", title:"Who built ARTEX", tags:"who made created developer author built autumn li puhua owner china chinese",
     a:"ARTEX was built by a developer known as <b>Autumn-27</b> (reported to be security engineer Li Puhua) as a side project for organisations to test their own networks. The same author also made <code>ScopeSentry</code>, used for recon. It was made closed-source on 8 Oct 2026 after being linked to attacks.", s:"Report"},
    {id:"when", title:"When ARTEX was released", tags:"when released date july 2026 launched closed source timeline history",
     a:"ARTEX was published on <b>26 July 2026</b> and spread quickly. After being tied to real intrusions, the author took it <b>closed-source on 8 October 2026</b> — but copies and forks were already circulating.", s:"Report"},
    {id:"license", title:"ARTEX licence", tags:"license licence agpl open source free cost legal",
     a:"ARTEX was released under the <b>AGPL-3.0</b> open-source licence, so it was free to download and modify. The tool itself costs nothing; running it needs an LLM API key, which can cost money per use.", s:"Report"},
    {id:"how", title:"How ARTEX works", tags:"how work works working loop agents planner worker architecture operate mechanism",
     a:"An operator sets a plain-language <b>goal</b>. A <b>Planner</b> agent breaks it into steps ('intents'); <b>Worker</b> agents (about 3 per task) run real tools like Nmap, curl and sqlmap. They loop — explore, decide, execute — until the goal is met, a human steps in, or the token budget runs out. State lives in PostgreSQL.", s:"Report → How it operates"},
    {id:"scopesentry", title:"ScopeSentry", tags:"scopesentry recon reconnaissance asset discovery sync",
     a:"<b>ScopeSentry</b> is an asset-discovery platform by the same author. ARTEX uses it as its recon foundation — mapping subdomains, ports and services — and can sync assets from it automatically.", s:"Report"},
    {id:"models", title:"Which AI models ARTEX uses", tags:"models llm claude gpt deepseek gemini which ai model openai",
     a:"ARTEX is <b>model-agnostic</b> — it works with Anthropic Claude, OpenAI GPT, or any OpenAI-compatible endpoint, including DeepSeek, GLM, Grok and Kimi. It is a harness, not a model.", s:"Report"},
    {id:"requirements", title:"Requirements to run ARTEX", tags:"requirements run install setup need docker postgres go node deploy host prerequisites",
     a:"You need an <b>isolated host</b>, Docker + Docker Compose (or Go 1.26.3+, Node 20+, Git), a <b>PostgreSQL</b> database, and an <b>LLM API key</b>. The console runs on port <code>8787</code>. Authorized lower environment only.", s:"Report → Requirements"},
    {id:"legal", title:"Is it legal to use ARTEX", tags:"legal illegal allowed authorization authorized permission lawful crime jail safe",
     a:"Running ARTEX against systems you don't own or aren't explicitly authorised to test is <b>illegal</b>, regardless of intent. Use it only on your own or approved systems, in an isolated lower environment, with security-team sign-off and written scope.", s:"Guidance"},
    {id:"zeroday", title:"Did ARTEX use zero-days", tags:"zero day zeroday new vulnerability headline finding novel unknown exploit",
     a:"No. ARTEX used <b>no zero-days</b> in any documented attack. It chained known, preventable weaknesses at machine speed. Speed, scale and a lower skill floor are what changed, not the vulnerabilities.", s:"Report → Headline finding"},
    {id:"chain", title:"The attack chain", tags:"attack chain how attacked stages flow kill chain steps phases sequence",
     a:"The chain: <b>operator sets a goal → planner + worker agents loop →</b> 1) Recon, 2) Initial access, 3) Exploit &amp; chain, 4) Privilege &amp; lateral, 5) Exfiltrate &amp; persist. The loop repeats until the goal is met.", s:"Report → The attack chain"},
    {id:"types", title:"The eight attack types", tags:"types how many categories list of attacks methods eight 8 kinds",
     a:"<b>8 types:</b> 1) reconnaissance, 2) credential attacks, 3) exploitation &amp; chaining, 4) supply-chain, 5) secret harvesting, 6) identity/deepfake bypass, 7) data exfiltration, 8) post-access operations. Six are ways in; two are what it does after access.", s:"Report → The eight types"},
    {id:"cred", title:"Credential spraying & rate limiting", tags:"credential spray spraying stuffing password brute force login rate limit lockout mfa authentication",
     a:"<b>Credential spraying:</b> the agent tries thousands of passwords against logins with no lockout (151,000+ in one case, peak 2,900/min). <b>Fix:</b> rate-limit per account/IP, burst lockout, and phishing-resistant MFA (passkeys), especially for payments.", s:"Fixes → §1"},
    {id:"sqli", title:"SQL injection", tags:"sql injection sqli database query inject union select",
     a:"<b>SQL injection:</b> user input pasted into a database query lets the agent rewrite it to read any data — the Korean banks' entry point. <b>Fix:</b> parameterised queries, never concatenate input, least-privilege DB account.", s:"Fixes → §2"},
    {id:"authbypass", title:"Authentication / SAML bypass", tags:"auth authentication bypass saml signature sso unsigned token assertion login",
     a:"<b>Auth bypass:</b> the app trusts a login token (e.g. an unsigned SAML assertion) without properly checking it. <b>Fix:</b> verify the signature before trusting any assertion, reject unsigned ones, and never trust client headers for auth.", s:"Fixes → §3"},
    {id:"idor", title:"IDOR (broken object authorization)", tags:"idor object authorization ownership access control id enumerate broken",
     a:"<b>IDOR:</b> the app checks you're logged in but not whether a record is yours, so changing an ID shows another user's data. <b>Fix:</b> check ownership on every request and return 404 if it isn't yours.", s:"Fixes → §4"},
    {id:"ssrf", title:"SSRF & XXE (cloud metadata)", tags:"ssrf xxe metadata imds cloud credentials fetch url server side request forgery xml",
     a:"<b>SSRF/XXE:</b> the app is tricked into fetching an internal address (like 169.254.169.254) to steal cloud credentials. <b>Fix:</b> allow-list outbound hosts, block internal ranges, require IMDSv2, and disable XML external entities.", s:"Fixes → §5"},
    {id:"upload", title:"File upload to web shell", tags:"file upload web shell rce remote code execution malicious attachment",
     a:"<b>File upload → web shell:</b> an uploaded 'image' is actually code the server runs. <b>Fix:</b> validate the real file type by content, store with a random name outside the web root, and execute nothing in upload paths.", s:"Fixes → §6"},
    {id:"secrets", title:"Secret / API-key harvesting", tags:"secret secrets api key keys vault leaked github env hardcoded credentials token",
     a:"<b>Secret harvesting:</b> keys left in code, JavaScript or GitHub are found in minutes — one case went from a GitHub search to emptying a Key Vault in 5 minutes. <b>Fix:</b> vault secrets, short-lived keys, CI scanning, rotate on exposure.", s:"Fixes → §7"},
    {id:"admin", title:"Exposed admin / debug pages", tags:"admin debug page exposed default credentials panel console grafana test",
     a:"<b>Exposed admin/debug:</b> forgotten panels with default passwords are an open door (Chainstack fell through a test Grafana). <b>Fix:</b> remove debug routes, gate admin behind MFA + IP allow-list, change every default.", s:"Fixes → §8"},
    {id:"session", title:"Weak session tokens", tags:"session sessions cookie token weak hijack guessable",
     a:"<b>Weak session tokens:</b> guessable session cookies let the agent hijack a session. <b>Fix:</b> strong random tokens, short idle expiry, secure host-locked cookies (<code>__Host-</code>), rotate on privilege change.", s:"Fixes → §9"},
    {id:"payment", title:"Payment / disbursement API abuse", tags:"payment api disbursal fund transfer money cert-in maker checker kyc loan limit",
     a:"<b>Payment-API abuse:</b> disbursal APIs called directly skip KYC, sanction and limit checks (CERT-In incidents). <b>Fix:</b> enforce the sequence as a server-side state machine, add maker-checker (two-person) approval and per-transaction ceilings.", s:"Fixes → §10"},
    {id:"oauth", title:"Over-privileged OAuth / vendor apps", tags:"oauth app vendor connectwise service principal consent over-privileged supply chain token",
     a:"<b>Over-privileged OAuth apps:</b> a trusted vendor app is abused to sign in as the app itself — bypassing user MFA (ConnectWise: 2,250+ tenants). <b>Fix:</b> least-privilege consent, monitor service-principal sign-ins, alert on new app credentials.", s:"Fixes → §11"},
    {id:"deepfake", title:"Deepfake / liveness bypass", tags:"deepfake liveness kyc identity verification face selfie synthetic video",
     a:"<b>Deepfake liveness bypass:</b> agents try real-time deepfakes and forged IDs against liveness checks — rejected when the verdict was computed server-side. <b>Fix:</b> compute liveness server-side, never trust a client 'passed' flag, detect injection.", s:"Fixes → §12"},
    {id:"detection", title:"Detecting an autonomous agent", tags:"detection detect monitor siem alert machine speed hunt soc behavioural anomaly",
     a:"<b>Detection:</b> human-paced monitoring misses a second-scale agent. <b>Fix:</b> alert on login bursts, sequential ID access, sub-second permission probing, new app credentials and odd egress — and require human confirmation for irreversible actions.", s:"Fixes → §13"},
    {id:"headers", title:"Security headers & error leakage", tags:"headers error leak hsts csp nosniff information disclosure stack trace",
     a:"<b>Headers &amp; errors:</b> verbose errors and missing headers hand an agent free recon. <b>Fix:</b> set strict headers (HSTS, CSP, X-Content-Type-Options), return generic errors to unauthenticated users, log stack traces server-side only.", s:"Fixes → §14"},
    {id:"start", title:"Where to start (fix-first order)", tags:"where start first priority fix order do first roadmap prioritise plan",
     a:"<b>Fix first:</b> 1) MFA + rate limiting on every login, 2) rotate &amp; vault secrets, 3) kill default creds and exposed admin/debug, 4) parameterise queries, 5) payment-API state machine + maker-checker, 6) vendor-app review, 7) SSRF/IMDSv2/XXE, 8) server-side liveness, 9) machine-speed detection.", s:"Report → Fix-first order"},
    {id:"korea", title:"Korean banks incident", tags:"korea korean banks shinhan kookmin hana incident breach data exposed",
     a:"<b>Korean banks:</b> breached via SQL injection and auth bypass in <i>peripheral</i> systems (loan-agent, employee, sales-support) — not customer banking. About 67,000 people's data was exposed; no money was taken.", s:"Report → Incidents"},
    {id:"connectwise", title:"ConnectWise / Storm-0940", tags:"connectwise storm 0940 microsoft tenants oauth incident vendor",
     a:"<b>ConnectWise / Storm-0940:</b> after a large password spray, the actor authenticated as the vendor apps across 2,250+ tenants with stolen app credentials — no user MFA prompt — and in one case the app made itself Global Administrator.", s:"Report → Incidents"},
    {id:"certin", title:"CERT-In payment incidents", tags:"cert-in india payment disbursal fund mule loan advisory incident",
     a:"<b>CERT-In incidents:</b> Indian advisories described disbursal APIs invoked directly from whitelisted infrastructure, skipping KYC/limit checks and sending funds to mule accounts. The fix is a server-side state machine plus maker-checker.", s:"Report → Incidents"},
    {id:"exposed", title:"Exposed ARTEX consoles", tags:"exposed consoles 800 1600 open internet unauthenticated public servers found",
     a:"Researchers found <b>hundreds to 1,600+ ARTEX consoles exposed</b> to the internet with no authentication, meaning anyone could drive powerful offensive tooling. If you run it, keep it behind authentication and off the public internet.", s:"Report → Incidents"},
    {id:"value", title:"How ARTEX helps defenders", tags:"help defence benefit use good value authorized testing regression",
     a:"Used with authorization on your <b>own</b> systems, ARTEX can find vulnerabilities earlier, cover more surface faster, test logged-in flows, keep an evidence trail for audits, and run as repeatable regression security testing each release.", s:"Report"},
    {id:"disclaimer", title:"About this site", tags:"disclaimer site about defensive purpose source references report who",
     a:"This is a <b>defensive</b> brief: public-source research on ARTEX plus remediation, with code examples. No testing was performed against any live system. It's meant to help teams defend systems they own or are authorized to protect.", s:"Report → Sources"},
  ];

  // ---- Indexing (TF-IDF) ----------------------------------------------------
  var STOP = new Set("the a an of to in on for and or is are was how do does what why with your you it its that this can i me my about using use used get give show tell explain please".split(" "));
  var SYN = { // normalise synonyms to a canonical token
    hack:"attack", hacking:"attack", hacked:"attack", attacker:"attack", attacks:"attack",
    fix:"fix", fixes:"fix", solve:"fix", solution:"fix", remediate:"fix", remediation:"fix", prevent:"fix", protect:"fix", defend:"fix", defence:"fix", defense:"fix", mitigate:"fix",
    vuln:"weakness", vulnerability:"weakness", vulnerabilities:"weakness", weaknesses:"weakness", flaw:"weakness", bug:"weakness", issue:"weakness",
    login:"login", logon:"login", signin:"login", "sign-in":"login", auth:"authentication",
    ai:"ai", llm:"ai", model:"ai", gpt:"ai", gemini:"ai", claude:"ai",
    db:"database", pwd:"password", creds:"credential", cred:"credential", credentials:"credential",
    bank:"bank", banks:"bank", banking:"bank", site:"site", website:"site",
    cost:"cost", price:"cost", pricing:"cost", free:"cost",
    setup:"install", deploy:"install", installation:"install", requirement:"requirements", "require":"requirements"
  };
  function stem(w){ return w.replace(/(ings?|ed|es|s)$/,"").replace(/^$/,w) || w; }
  function norm(s){
    return String(s).toLowerCase().replace(/[^a-z0-9 ]/g," ").split(/\s+/)
      .filter(function(w){return w && !STOP.has(w);})
      .map(function(w){ w = SYN[w] || w; return SYN[stem(w)] || stem(w); })
      .filter(Boolean);
  }
  var N = KB.length, df = {};
  KB.forEach(function(e){
    var text = e.title + " " + e.tags + " " + e.a.replace(/<[^>]+>/g," ");
    e._tf = {}; e._titleTokens = new Set(norm(e.title + " " + e.tags));
    var toks = norm(text), seen = {};
    toks.forEach(function(t){ e._tf[t] = (e._tf[t]||0)+1; });
    Object.keys(e._tf).forEach(function(t){ if(!seen[t]){ df[t]=(df[t]||0)+1; seen[t]=1; } });
  });
  function idf(t){ return Math.log((N+1)/((df[t]||0)+1)) + 1; }

  // typo tolerance: 1-edit match against known vocabulary
  var VOCAB = Object.keys(df);
  function edit1(a,b){ if(Math.abs(a.length-b.length)>1) return false; var i=0,j=0,d=0;
    while(i<a.length&&j<b.length){ if(a[i]===b[j]){i++;j++;} else { if(++d>1) return false;
      if(a.length>b.length)i++; else if(a.length<b.length)j++; else {i++;j++;} } }
    return d + (a.length-i) + (b.length-j) <= 1; }
  function fixToken(t){ if(df[t]) return t; for(var k=0;k<VOCAB.length;k++){ if(VOCAB[k].length>3 && edit1(t,VOCAB[k])) return VOCAB[k]; } return t; }

  // ---- Retrieval ------------------------------------------------------------
  function score(qtokens){
    var results = KB.map(function(e){
      var sc = 0;
      qtokens.forEach(function(t){
        if(e._tf[t]){ sc += e._tf[t] * idf(t); if(e._titleTokens.has(t)) sc += 2.5*idf(t); }
      });
      return {e:e, sc:sc};
    }).filter(function(r){return r.sc>0;});
    results.sort(function(a,b){return b.sc-a.sc;});
    return results;
  }

  function answer(query){
    var q = String(query||"").toLowerCase().trim();
    if(!q) return null;
    if(/^(hi|hey|hello|yo|hiya|good (morning|evening|afternoon))\b/.test(q))
      return {a:"Hi! I'm <b>Venu Assistant</b>. Ask me about ARTEX — what it is, how it attacked, the 8 attack types, or how to fix any weakness.", s:null, related:["What ARTEX is","The eight attack types","Where to start (fix-first order)"]};
    if(/\b(thanks|thank you|thx|great|cool|nice|awesome)\b/.test(q))
      return {a:"Glad it helped. Ask me anything else about ARTEX or its defenses.", s:null, related:[]};
    if(/\b(help|what can you|who are you|options)\b/.test(q))
      return {a:"I answer from a knowledge base on ARTEX and how to defend against it. Try: what it is, how it works, the attack types, a specific attack (SQL injection, SSRF, secrets…), or where to start.", s:null, related:["What ARTEX is","How ARTEX works","The eight attack types"]};

    var qt = norm(q).map(fixToken);
    if(!qt.length) return null;
    var ranked = score(qt);
    if(!ranked.length) return null;
    var top = ranked[0], second = ranked[1];
    var body = top.e.a;
    // broad query → blend the top two if close in score and different topics
    if(second && second.sc > top.sc*0.6 && qt.length>=3){
      body += "<br><br>" + second.e.a;
    }
    var related = ranked.slice(1,5).map(function(r){return r.e.title;});
    // ensure related has at least a few suggestions
    if(related.length < 3){
      ["What ARTEX is","The eight attack types","Where to start (fix-first order)"].forEach(function(t){
        if(related.indexOf(t)<0 && t!==top.e.title && related.length<3) related.push(t);
      });
    }
    return {a:body, s:top.e.s, related:related};
  }

  function answerByTitle(title){
    for(var i=0;i<KB.length;i++) if(KB[i].title===title) return {a:KB[i].a, s:KB[i].s,
      related: KB.filter(function(e){return e.title!==title;}).slice(0,0).map(function(e){return e.title;})};
    return null;
  }

  window.VenuAssistant = {
    answer: answer,
    answerByTitle: answerByTitle,
    suggestions: ["What is ARTEX?","How does it work?","What are the attack types?","How do I fix SQL injection?","How did it attack the banks?","Where should I start?"],
    topics: KB.map(function(e){return e.title;})
  };
})();
