import { shannonEntropy } from "../util/entropy.js";
import { sha256Hex } from "../util/hash.js";
const PEM_RE = /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----[\s\S]{16,16384}?-----END \1-----/g;
/** A real PEM body is base64; templates such as `${base64Key}` are not. */
function plausiblePemBody(value) {
    const body = canonicalSecret(value);
    return body.length >= 64 && /^[A-Za-z0-9+/=]+$/.test(body);
}
/** `(?<!…)` boundary shared by token formats: not glued to a longer identifier. */
const B = "(?<![A-Za-z0-9_])";
const E = "(?![A-Za-z0-9_])";
const fmt = (id, title, severity, source, extra = {}) => ({
    id,
    title,
    kind: "format",
    severity,
    re: new RegExp(source, "g"),
    ...extra,
});
const FORMAT_DETECTORS = [
    { id: "pem-private-key", title: "PEM private key block", kind: "format", severity: "critical", re: PEM_RE, accept: plausiblePemBody },
    fmt("putty-private-key", "PuTTY private key file", "critical", "PuTTY-User-Key-File-[23]: [\\s\\S]{20,16384}?Private-MAC: [0-9a-f]{40,64}"),
    fmt("age-secret-key", "age encryption secret key", "critical", "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"),
    fmt("aws-access-key-id", "AWS access key id", "high", `${B}(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![0-9A-Za-z])`),
    fmt("github-token", "GitHub token", "high", `${B}gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9])`),
    fmt("github-fine-grained-pat", "GitHub fine-grained token", "high", `${B}github_pat_[A-Za-z0-9_]{60,255}${E}`),
    fmt("gitlab-token", "GitLab token", "high", `${B}gl(?:pat|dt|rt|ptt|cbt|oas|soat|ft|imt|agent|ffct)-[A-Za-z0-9_-]{20,64}(?![A-Za-z0-9_-])`),
    fmt("slack-token", "Slack token", "high", `${B}xox[abposre]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])`),
    fmt("slack-webhook", "Slack incoming webhook URL", "high", "https://hooks\\.slack\\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]{30,}"),
    fmt("discord-webhook", "Discord webhook URL", "high", "https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d{5,30}/[A-Za-z0-9_-]{60,}"),
    fmt("stripe-secret-key", "Stripe live secret key", "critical", `${B}[sr]k_live_[A-Za-z0-9]{16,}(?![A-Za-z0-9])`),
    fmt("npm-token", "npm access token", "high", `${B}npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])`),
    fmt("pypi-token", "PyPI upload token", "high", `${B}pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}`),
    fmt("sendgrid-api-key", "SendGrid API key", "high", `${B}SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])`),
    fmt("huggingface-token", "Hugging Face access token", "high", `${B}hf_[A-Za-z]{34}(?![A-Za-z0-9])`),
    fmt("shopify-token", "Shopify access token or shared secret", "high", `${B}shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}(?![A-Za-z0-9])`),
    fmt("digitalocean-token", "DigitalOcean token", "high", `${B}do[opr]_v1_[a-f0-9]{64}(?![A-Za-z0-9])`),
    fmt("anthropic-api-key", "Anthropic API key", "critical", `${B}sk-ant-(?:api|admin)\\d{2}-[A-Za-z0-9_-]{80,}`),
    fmt("openai-api-key", "OpenAI API key", "critical", `${B}sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20})T3BlbkFJ[A-Za-z0-9_-]{20,}`),
    fmt("twilio-api-key", "Twilio API key SID", "high", `${B}SK[0-9a-f]{32}(?![A-Za-z0-9])`),
    fmt("mailgun-api-key", "Mailgun API key", "high", `${B}key-[0-9a-f]{32}(?![A-Za-z0-9])`),
    fmt("postman-api-key", "Postman API key", "high", `${B}PMAK-[a-f0-9]{24}-[a-f0-9]{34}(?![A-Za-z0-9])`),
    fmt("databricks-token", "Databricks access token", "high", `${B}dapi[a-f0-9]{32}(?:-\\d)?(?![A-Za-z0-9])`),
    fmt("atlassian-api-token", "Atlassian API token", "high", `${B}ATATT3[A-Za-z0-9_=-]{180,}`),
    fmt("linear-api-key", "Linear API key", "high", `${B}lin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9])`),
    fmt("sentry-auth-token", "Sentry auth token", "high", `${B}sntry[su]_[A-Za-z0-9+/=_-]{40,}`),
    fmt("grafana-token", "Grafana service-account or cloud token", "high", `${B}(?:glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}|glc_[A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9])`),
    fmt("vault-token", "HashiCorp Vault token", "high", `${B}hv[sb]\\.[A-Za-z0-9_-]{90,}`),
    fmt("terraform-cloud-token", "Terraform Cloud API token", "high", `${B}[A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9_=-]{60,70}(?![A-Za-z0-9_=-])`),
    fmt("doppler-token", "Doppler token", "high", `${B}dp\\.(?:pt|st|sa|ct|scim|audit)\\.[A-Za-z0-9]{40,44}(?![A-Za-z0-9])`),
    fmt("pulumi-token", "Pulumi access token", "high", `${B}pul-[a-f0-9]{40}(?![A-Za-z0-9])`),
    fmt("google-oauth-client-secret", "Google OAuth client secret", "high", `${B}GOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])`),
    fmt("mapbox-secret-token", "Mapbox secret token", "high", `${B}sk\\.eyJ[A-Za-z0-9_-]{50,}\\.[A-Za-z0-9_-]{20,}`),
    fmt("square-oauth-secret", "Square OAuth secret", "high", `${B}sq0csp-[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])`),
    fmt("telegram-bot-token", "Telegram bot token", "high", `${B}\\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])`),
    fmt("azure-storage-key", "Azure storage account key", "critical", "AccountKey=([A-Za-z0-9+/]{86}==)", { group: 1 }),
];
const HEURISTIC_DETECTORS = [
    {
        id: "google-api-key",
        title: "Google API key (often public-by-design; check restrictions)",
        kind: "heuristic",
        severity: "medium",
        re: /(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
    },
    {
        id: "jwt",
        title: "JSON Web Token",
        kind: "heuristic",
        severity: "medium",
        re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    },
    {
        id: "test-mode-secret-key",
        title: "Test-mode secret key (no production authority by design)",
        kind: "heuristic",
        severity: "low",
        re: /(?<![A-Za-z0-9_])[sr]k_test_[A-Za-z0-9]{16,}(?![A-Za-z0-9])/g,
    },
    {
        id: "url-embedded-password",
        title: "Password embedded in a URL",
        kind: "heuristic",
        severity: "medium",
        re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/'"`<>]{1,64}:([^\s:@/'"`<>]{6,128})@[A-Za-z0-9.-]+/g,
        group: 1,
        accept: (v) => !/[${}%]|^(?:password|passwd|pass|secret|xxx+|\*+)$/i.test(v),
    },
];
/**
 * Key names that end in a credential noun. The noun must END the key: `token`
 * matches `ACCESS_TOKEN` and `"token"` but not `tokenizer` or `tokens`.
 */
const KEYED_RE = new RegExp(String.raw `(?<![A-Za-z0-9])([A-Za-z0-9_.-]{0,40}?(?:api[_.-]?(?:key|token|secret)|apikey|access[_.-]?(?:key|token)|auth[_.-]?token|bearer[_.-]?token|refresh[_.-]?token|secret[_.-]?(?:key|token)?|client[_.-]?secret|write[_.-]?key|sdk[_.-]?key|admin[_.-]?key|credentials?|private[_.-]?key|signing[_.-]?key|master[_.-]?key|service[_.-]?(?:key|token)|license[_.-]?key|encryption[_.-]?key|password|passwd|pwd|token))["']?\s*(?:=|:|=>)\s*(["'\x60]?)([A-Za-z0-9_\-+/=~]{16,256})\2(?![A-Za-z0-9_\-+/=.~])`, "gi");
const PLACEHOLDER = /your|example|placeholder|change[_-]?me|dummy|sample|redacted|insert|replace|fake|mock|todo|undefined|null|true|false|^x+$|^\*+$|^0+$/i;
/**
 * Is a keyed value generated (a credential) rather than a word, path, enum or
 * template? Calibration showed credential-named keys mostly hold editor-theme
 * scopes (`token: "markup.bold.markdown"`) and enum names; those are excluded.
 */
/**
 * A value in which some 4-character sequence occurs 3+ times is a pattern, not randomness
 * (v0.4, validation set D: `udp6PWD=AAAAAaaaAaaaAaaa…` in a native binary). For a uniformly
 * random 40-character base62 value this essentially never happens (p < 1e-9).
 */
function repetitive(core) {
    const counts = new Map();
    for (let i = 0; i + 4 <= core.length; i++) {
        const g = core.slice(i, i + 4);
        const n = (counts.get(g) ?? 0) + 1;
        if (n >= 3)
            return true;
        counts.set(g, n);
    }
    return false;
}
export function generatedValue(v) {
    if (PLACEHOLDER.test(v))
        return false;
    // v0.4 calibration: `sdkKey: "client-…"` (Statsig) is public by the issuer's own naming. A value whose
    // prefix marks it public (client-, pk_, pub_, publishable_) is not a credential lead under any key.
    if (/^(?:client|pk|pub|public|publishable)(?:_(?:live|test))?[_-]/i.test(v))
        return false;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v))
        return true; // UUID-form keys (e.g. Heroku)
    const hex = /^([0-9a-f]{32,128}|[0-9A-F]{32,128})(?:-[a-z]{2}\d{1,2})?$/.exec(v); // hex keys, optional Mailchimp-style dc suffix
    if (hex) {
        const h = hex[1];
        const digits = h.replace(/[^0-9]/g, "").length;
        return digits >= 4 && h.length - digits >= 4 && shannonEntropy(h) >= 3.0;
    }
    if (v.includes("~"))
        return false;
    // A value that base64-decodes to readable prose is an encoded phrase (calibration: a README's
    // `password: '<base64 of "not my real password">'`). Generated keys decode to random bytes.
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(v) && v.length % 4 === 0) {
        const text = Buffer.from(v, "base64").toString("latin1");
        if (/ /.test(text) && /^[\x20-\x7e\t\r\n]+$/.test(text))
            return false;
    }
    const core = v.replace(/[-_+/=]/g, "");
    if (core.length < 16)
        return false;
    if (repetitive(core))
        return false;
    // CamelCase identifiers (`…PortAddrSpanHostTime…`): validation set D found 11 consecutive
    // capitalised short words under `udp6PWD`. The word-run check below needs 4+ lowercase letters
    // per word, so it misses them. Random base62 values do not consist mostly of such words.
    let camel = 0;
    for (const w of v.match(/[A-Z][a-z]{2,}/g) ?? [])
        camel += w.length;
    if (camel / core.length >= 0.6)
        return false;
    let upper = 0;
    let lower = 0;
    let digit = 0;
    for (const ch of core) {
        if (ch >= "A" && ch <= "Z")
            upper++;
        else if (ch >= "a" && ch <= "z")
            lower++;
        else
            digit++;
    }
    if (upper < 1 || lower < 1 || digit < 1)
        return false;
    let inRuns = 0;
    for (const run of v.match(/[A-Z]{4,}|[A-Z]?[a-z]{4,}/g) ?? [])
        inRuns += run.length;
    if (inRuns / core.length > 0.45)
        return false;
    return shannonEntropy(core) >= 3.5;
}
const KEYED = {
    id: "keyed-credential",
    title: "Generated value assigned to a credential-named key",
    kind: "keyed",
    severity: "high",
    re: KEYED_RE,
    group: 3,
    accept: (v) => generatedValue(v),
};
/**
 * v0.4: CONSTANT_CASE names ending in `_KEY` (`SEGMENT_WRITE_KEY`, `DD_APP_KEY`,
 * `ALGOLIA_ADMIN_KEY`). Provider env-var names follow `<PROVIDER>_<…>_KEY`
 * whatever the noun before KEY is, so the noun list above cannot enumerate them.
 * Case-sensitive on purpose: camelCase `…Key` names (`cacheKey`, `storageKey`)
 * are mostly not credentials. The value must still look generated.
 */
const KEYED_CONST = {
    id: "keyed-constant-credential",
    title: "Generated value assigned to a CONSTANT_CASE *_KEY name",
    kind: "keyed",
    severity: "high",
    re: /(?<![A-Za-z0-9_])([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_KEY)["']?\s*(?:=|:|=>)\s*(["'\x60]?)([A-Za-z0-9_\-+/=~]{16,256})\2(?![A-Za-z0-9_\-+/=.~])/g,
    group: 3,
    accept: (v) => generatedValue(v),
};
/**
 * v0.4: credentials passed to code instead of assigned to a key: the v3
 * benchmark's untested "call" blind spot. Two conventions from provider SDK
 * documentation, each requiring a generated-looking first string argument:
 *  - a function or method whose NAME ends in a credential noun
 *    (`sgMail.setApiKey("…")`, `client.setAccessToken("…")`, `withToken("…")`);
 *  - a constructor of an API client class (`new postmark.ServerClient("…")`,
 *    `new XClient("…")`, `new FooApi("…")`, `new BarSDK("…")`).
 * A bare factory call (`Stripe("…")`, `connect("…")`) carries no such signal and
 * is NOT detected unless the value has a recognised format.
 */
const CALL_NAMED_RE = new RegExp(String.raw `(?<![A-Za-z0-9_$])([A-Za-z_$][\w$]{0,40}?(?:api[_]?key|apikey|access[_]?token|auth[_]?token|bearer[_]?token|refresh[_]?token|write[_]?key|license[_]?key|secret[_]?key|client[_]?secret|token|secret|password|credentials?))\s*\(\s*(["'\x60])([A-Za-z0-9_\-+/=~]{16,256})\2`, "gi");
const CALL_NAMED = {
    id: "credential-call-argument",
    title: "Generated value passed to a credential-named function",
    kind: "keyed",
    severity: "high",
    re: CALL_NAMED_RE,
    group: 3,
    accept: (v, m) => !/^(?:get|has|remove|delete|clear|is|validate|verify|parse|decode|hash)/i.test(m[1].replace(/^.*[.]/, "")) && generatedValue(v),
};
const CLIENT_CTOR = {
    id: "client-constructor-argument",
    title: "Generated value passed to an API client constructor",
    kind: "keyed",
    severity: "high",
    re: /(?<![A-Za-z0-9_$])new\s+(?:[A-Za-z_$][\w$]*\.){0,3}((?:[A-Z][\w$]{0,40}?)?(?:Client|Api|API|SDK|Sdk))\s*\(\s*(["'\x60])([A-Za-z0-9_\-+/=~]{16,256})\2/g,
    group: 3,
    accept: (v) => generatedValue(v),
};
/**
 * Token prefixes that providers document as PUBLIC (safe to ship): they are
 * not leads, and they suppress the structural rule for the same span.
 */
const PUBLIC_PREFIX = /^(?:pk_(?:live|test)|sb_publishable|pub|public|publishable)$/i;
/** Prefixes of identifiers that are high-entropy but are not credentials (hashes, ids, build artefacts). */
const NON_SECRET_PREFIX = /^(?:sha\d*|md5|sri|hash|digest|checksum|integrity|commit|rev|revision|uuid|guid|id|ref|nonce|etag|crc\d*|build|chunk|bundle|asset|data|base64|b64|sig|signature|cid|ipfs|bafy|qm|v\d+|x\d+|u\d+|lib|mod|fn|var|tmp|test|mock|fake|dummy|example|sample)$/i;
// Vendor prefixes in the modern convention are short and lowercase (GitHub's 2021 format: ghp_, and
// most vendors since). Uppercase "prefixes" in real code were C++/Swift mangled names and cipher-suite
// names during calibration, so they are not accepted.
const STRUCTURAL_RE = /(?<![A-Za-z0-9_.+/=-])([a-z][a-z0-9]{1,11})([_-])([A-Za-z0-9][A-Za-z0-9_-]{19,199})(?![A-Za-z0-9+/=_-])/g;
/**
 * Prefix segments that mark a token as SECRET by the issuer's own naming
 * (Stripe sk_/pk_, Statsig secret-/client-, Supabase sb_secret_/sb_publishable_,
 * PlanetScale pscale_tkn_, Groq gsk_, Notion secret_). Calibration on real apps
 * found random-looking *public* identifiers with other prefixes (client-, app_,
 * env_, connector_), so only these block.
 */
const SECRET_MARKER = /(?:^|[_-])(?:[a-z]*sk|secret|sec|key|token|tkn|tok|pat|pw|pwd|pass|passwd|priv|private|api|auth|svc|srv|server|admin|root|master)(?:[_-]|$)/;
/** Unpadded base64url lengths of 16/20/32/48/64-byte digests (the length of the whole matched token). */
const DIGEST_B64_LENGTHS = new Set([22, 27, 43, 64, 86]);
/** Does the body look like generated randomness rather than words, paths or ids? */
function randomBody(body) {
    const core = body.replace(/[_-]/g, "");
    if (core.length < 20)
        return false;
    if (/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(body))
        return false; // UUID
    // Embedded hex runs are hashes (Swift/C++ symbol hashes, content digests). A uniformly random
    // alphanumeric body essentially never contains 16 consecutive hex characters of one case.
    if (/[0-9A-F]{16,}|[0-9a-f]{16,}/.test(body))
        return false;
    let upper = 0;
    let lower = 0;
    let digit = 0;
    for (const ch of core) {
        if (ch >= "A" && ch <= "Z")
            upper++;
        else if (ch >= "a" && ch <= "z")
            lower++;
        else
            digit++;
    }
    if (upper < 2 || lower < 2 || digit < 2)
        return false;
    // Words (camelCase, snake_case, CONSTANT_CASE identifiers, mangled symbols) put most characters in
    // word-shaped runs; uniformly random alphanumerics put few there.
    let inRuns = 0;
    for (const run of body.match(/[A-Z]{4,}|[A-Z]?[a-z]{4,}/g) ?? [])
        inRuns += run.length;
    // Threshold 0.45: about 97% of uniformly random 32–56 character bodies pass; snake_case and
    // camelCase identifiers measured 0.48–0.61 (docs/research/CALIBRATION.md).
    if (inRuns / core.length > 0.45)
        return false;
    return shannonEntropy(core) >= 3.7;
}
/**
 * v0.4: a hex body behind a STRONG secret marker (`sk_<48 hex>`, `sk-or-v1-<64 hex>`).
 * randomBody() rejects hex because unmarked `<prefix>_<hex>` tokens were digests in
 * calibration (`diff-<sha256>`, Swift `err33_<hash>`); a key-like marker as the
 * whole prefix is the issuer saying it is a secret.
 */
const STRONG_MARKER = /^(?:[a-z]{0,4}sk|secret|key|token|api|apikey|pat|priv)$/;
function markedHexBody(prefix, body) {
    if (!STRONG_MARKER.test(prefix))
        return false;
    const m = /^(?:[a-z][a-z0-9]{0,5}[_-]){0,3}([0-9a-f]{32,128})$/.exec(body);
    if (!m)
        return false;
    const h = m[1];
    const digits = h.replace(/[^0-9]/g, "").length;
    return digits >= 4 && h.length - digits >= 4 && shannonEntropy(h) >= 3.0;
}
/**
 * v0.4 (validation set C): BoringSSL/Swift symbol names in native code (`…_key_list…_ssl_session_st…`)
 * are snake_case runs: many separators, several all-lowercase word segments. A random token body
 * has few separators and almost never a lowercase-only segment of 3+ characters.
 */
function snakeIdentifier(token) {
    const segs = token.split(/[_-]/);
    return segs.length >= 5 && segs.filter((x) => /^[a-z]{3,}$/.test(x)).length >= 2;
}
const STRUCTURAL = {
    id: "prefixed-secret-token",
    title: "Secret-marked prefixed token of an unrecognised provider",
    kind: "structural",
    severity: "high",
    re: STRUCTURAL_RE,
    accept: (value, m) => {
        if (DIGEST_B64_LENGTHS.has(m[0].length))
            return false;
        if (snakeIdentifier(m[0]))
            return false;
        const prefix = m[1];
        const qualified = `${prefix}${m[2]}${/^[A-Za-z0-9]+/.exec(m[3])?.[0] ?? ""}`; // e.g. pk_live
        // `<x>_test_…` is the test-mode convention (Stripe and others): no production authority,
        // reported by the test-mode heuristic instead.
        const testMode = /^[a-z0-9]{1,12}[_-]test$/i.test(qualified);
        // v0.3: a prefix that does not mark the token secret yields NO lead. In v0.2 these were warnings;
        // on the calibration apps 75/75 were public ids or identifiers, and on v2 they were 217 spurious
        // warnings. Such a token is still caught when it is assigned to a credential-named key (KEYED).
        const marked = SECRET_MARKER.test(prefix) || SECRET_MARKER.test(qualified);
        if (!marked || testMode || PUBLIC_PREFIX.test(prefix) || PUBLIC_PREFIX.test(qualified) || NON_SECRET_PREFIX.test(prefix))
            return false;
        return randomBody(m[3]) || markedHexBody(prefix, m[3]);
    },
};
// Order matters: a span explained by a specific format is not reported again by the
// structural rule, and neither is reported again by a heuristic.
const DETECTORS = [...FORMAT_DETECTORS, STRUCTURAL, KEYED, KEYED_CONST, CALL_NAMED, CLIENT_CTOR, ...HEURISTIC_DETECTORS];
const CONFIDENCE = { format: "high", structural: "medium", keyed: "medium", heuristic: "low" };
export function detectorIds() {
    return DETECTORS.map((d) => d.id);
}
export function runDetectors(text) {
    const out = [];
    const claimed = []; // spans already explained by a specific detector
    const overlaps = (a, b) => claimed.some(([x, y]) => a < y && x < b);
    for (const d of DETECTORS) {
        for (const m of text.matchAll(d.re)) {
            const value = d.group ? m[d.group] : m[0];
            if (!value)
                continue;
            const start = m.index ?? 0;
            const end = start + m[0].length;
            if (d.kind !== "format" && overlaps(start, end))
                continue;
            if (d.accept && !d.accept(value, m))
                continue;
            const index = start + (d.group ? m[0].indexOf(value) : 0);
            claimed.push([start, end]);
            const confidence = d.id === "google-api-key" || d.id === "jwt" ? "medium" : CONFIDENCE[d.kind];
            out.push({ detector: d.id, title: d.title, kind: d.kind, severity: d.severity, confidence, value, index });
        }
    }
    return out;
}
/**
 * Credentials published as examples in official documentation (AWS's
 * AKIAIOSFODNN7EXAMPLE family, Stripe's documented test keys, the Azure
 * Storage Emulator key). Suppressed as
 * leads and counted in the evidence record; a DECLARED fingerprint still
 * matches them.
 */
const DOCUMENTED_EXAMPLES = new Set([
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc", // Stripe API reference
    "pk_test_TYooMQauvdEDq54NiTphI7jx", // Stripe API reference
    // Azure Storage Emulator / Azurite well-known development key (account devstoreaccount1), published by Microsoft.
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
    // Supabase CLI local-development default keys (`supabase start`), published in Supabase's documentation
    // and embedded in the CLI binary (v0.4 validation set D).
    "sb_secret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz",
    "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH",
]);
export function isKnownExample(c) {
    if (DOCUMENTED_EXAMPLES.has(c.value))
        return true;
    return /EXAMPLE(KEY)?$/.test(c.value) && /^(?:aws-access-key-id|keyed-credential|keyed-constant-credential|credential-call-argument|client-constructor-argument|prefixed-secret-token)$/.test(c.detector);
}
/**
 * Canonical form used for fingerprints. PEM blocks reduce to their base64 body
 * (headers, whitespace and literal `\n` / `\r` escapes removed) so the same key
 * matches whether shipped as a file or embedded in a source string.
 */
export function canonicalSecret(value) {
    const v = value.trim();
    if (/-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----/.test(v)) {
        return v
            .replace(/-----(BEGIN|END) [A-Z ]+-----/g, "")
            .replace(/\\[nrt]/g, "\n")
            .replace(/^[A-Za-z-]+:.*$/gm, "") // PEM headers such as Proc-Type
            .replace(/\s+/g, "");
    }
    return v;
}
export function fingerprintOf(value) {
    return sha256Hex(canonicalSecret(value));
}
/** Redacted preview — never enough to reconstruct the secret. */
export function witnessOf(value) {
    const canon = canonicalSecret(value);
    const head = value.startsWith("-----BEGIN") ? value.slice(0, value.indexOf("-----", 5) + 5) : canon.slice(0, Math.min(4, Math.floor(canon.length / 4)));
    return { sha256: sha256Hex(canon), preview: `${head}…[redacted ${canon.length} chars]`, length: canon.length };
}
/**
 * Candidate strings for the fingerprint sweep. Two tokenizations:
 *  - credential charset runs (base64/url-safe/JWT), the common case;
 *  - broad runs of any non-delimiter printable characters, split again on `=`/`:`,
 *    so declared passwords containing symbols (`!@#$%^&*`) are still found.
 * Declared secrets shorter than 8 characters cannot be swept.
 */
const TOKEN_RE = /[A-Za-z0-9_\-+/.~]{12,}={0,2}/g;
// Printable ASCII minus quotes, brackets, separators and backslash. Restricting to ASCII keeps
// binaries (whose Latin-1 view is mostly high bytes) from producing huge token sets.
const BROAD_RE = /[\x21\x23-\x26\x2a\x2b\x2d-\x3a\x3d\x3f-\x5a\x5e\x5f\x61-\x7a\x7e]{8,512}/g;
export function* tokens(text) {
    for (const m of text.matchAll(TOKEN_RE))
        yield { value: m[0], index: m.index ?? 0 };
    for (const m of text.matchAll(BROAD_RE)) {
        const v = m[0];
        const at = m.index ?? 0;
        yield { value: v, index: at };
        let off = 0;
        for (const part of v.split(/[=:]/)) {
            if (part.length >= 8 && part !== v)
                yield { value: part, index: at + off };
            off += part.length + 1;
        }
    }
}
