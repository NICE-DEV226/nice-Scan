package fingerprint

import "regexp"

func hdr(k, v string) map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{k: regexp.MustCompile(v)}
}
func cook(k, v string) map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{k: regexp.MustCompile(v)}
}
func html(p ...string) []*regexp.Regexp {
	r := make([]*regexp.Regexp, len(p))
	for i, s := range p {
		r[i] = regexp.MustCompile(s)
	}
	return r
}
func one(p string) []*regexp.Regexp {
	return []*regexp.Regexp{regexp.MustCompile(p)}
}
func vhdr(k, v string) map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{k: regexp.MustCompile(v)}
}
func vhtml(p ...string) []*regexp.Regexp {
	r := make([]*regexp.Regexp, len(p))
	for i, s := range p {
		r[i] = regexp.MustCompile(s)
	}
	return r
}

func (f *Fingerprinter) loadSignatures() {
	f.signatures = []Signature{

		// ──────────────────────────────────────────────────
		// WEB SERVERS
		// ──────────────────────────────────────────────────

		{
			Name: "nginx", Type: "web_server", Category: "Web Server",
			Confidence: 0.97,
			Headers:    hdr("Server", `(?i)nginx(?:/([\d.]+))?`),
			VersionHeaders: vhdr("Server", `nginx/([\d.]+)`),
		},
		{
			Name: "Apache HTTP Server", Type: "web_server", Category: "Web Server",
			Confidence: 0.97,
			Headers:    hdr("Server", `(?i)Apache(?:/([\d.]+))?(?: \(.*?\))?`),
			VersionHeaders: vhdr("Server", `Apache/([\d.]+)`),
		},
		{
			Name: "IIS", Type: "web_server", Category: "Web Server",
			Confidence: 0.95,
			Headers:    hdr("Server", `(?i)Microsoft-IIS(?:/([\d.]+))?`),
			VersionHeaders: vhdr("Server", `Microsoft-IIS/([\d.]+)`),
		},
		{
			Name: "Tomcat", Type: "web_server", Category: "Web Server",
			Confidence: 0.9,
			Headers: hdr("Server", `(?i)Apache-Coyote|Apache Tomcat(?:/([\d.]+))?`),
			VersionHeaders: vhdr("Server", `Apache Tomcat/([\d.]+)`),
		},
		{
			Name: "Caddy", Type: "web_server", Category: "Web Server",
			Confidence: 0.9,
			Headers:    hdr("Server", `(?i)Caddy(?:/([\d.]+))?(?:\s|$)`),
			VersionHeaders: vhdr("Server", `Caddy/([\d.]+)`),
		},
		{
			Name: "LiteSpeed", Type: "web_server", Category: "Web Server",
			Confidence: 0.9,
			Headers:    hdr("Server", `(?i)LiteSpeed(?:/([\d.]+))?`),
			VersionHeaders: vhdr("Server", `LiteSpeed/([\d.]+)`),
		},
		{
			Name: "Lighttpd", Type: "web_server", Category: "Web Server",
			Confidence: 0.9,
			Headers:    hdr("Server", `(?i)lighttpd(?:/([\d.]+))?`),
			VersionHeaders: vhdr("Server", `lighttpd/([\d.]+)`),
		},
		{
			Name: "Traefik", Type: "web_server", Category: "Reverse Proxy",
			Confidence: 0.85,
			Headers:    hdr("Server", `(?i)traefik`),
		},
		{
			Name: "HAProxy", Type: "web_server", Category: "Reverse Proxy",
			Confidence: 0.85,
			Headers:    hdr("Server", `(?i)HAProxy(?:/([\d.]+))?`),
			VersionHeaders: vhdr("Server", `HAProxy/([\d.]+)`),
		},
		{
			Name: "Envoy", Type: "web_server", Category: "Reverse Proxy",
			Confidence: 0.8,
			Headers: hdr("Server", `(?i)envoy`),
		},
		{
			Name: "OpenResty", Type: "web_server", Category: "Web Server",
			Confidence: 0.85,
			Headers: hdr("Server", `(?i)openresty(?:/([\d.]+))?`),
			VersionHeaders: vhdr("Server", `openresty/([\d.]+)`),
		},
		{
			Name: "Jetty", Type: "web_server", Category: "Web Server",
			Confidence: 0.85,
			Headers: hdr("Server", `(?i)Jetty(?:\(([\d.]+)\))?`),
			VersionHeaders: vhdr("Server", `Jetty\(([\d.]+)\)`),
		},
		{
			Name: "JBoss / WildFly", Type: "web_server", Category: "Application Server",
			Confidence: 0.8,
			Headers: hdr("Server", `(?i)JBoss|WildFly`),
		},

		// ──────────────────────────────────────────────────
		// CDNs
		// ──────────────────────────────────────────────────

		{
			Name: "Cloudflare", Type: "cdn", Category: "CDN",
			Confidence: 0.97,
			Headers:    merge(hdr("Server", `(?i)cloudflare`), hdr("CF-Ray", `.+`)),
		},
		{
			Name: "Akamai", Type: "cdn", Category: "CDN",
			Confidence: 0.9,
			Headers: hdr("Server", `(?i)Akamai(?:GHost)?`),
		},
		{
			Name: "Fastly", Type: "cdn", Category: "CDN",
			Confidence: 0.9,
			Headers: hdr("Fastly-Debug-Path|X-Served-By|X-Cache-Hits", `(?i)fastly`),
		},
		{
			Name: "Amazon CloudFront", Type: "cdn", Category: "CDN",
			Confidence: 0.9,
			Headers: hdr("X-Amz-Cf-Id|X-Amz-Cf-Pop", `.+`),
		},
		{
			Name: "StackPath", Type: "cdn", Category: "CDN",
			Confidence: 0.7,
			Headers: hdr("Server", `(?i)stackpath`),
		},
		{
			Name: "KeyCDN", Type: "cdn", Category: "CDN",
			Confidence: 0.7,
			Headers: hdr("X-Edge-Connect-Key|X-Cache", `(?i)keycdn`),
		},
		{
			Name: "BunnyCDN", Type: "cdn", Category: "CDN",
			Confidence: 0.8,
			Headers: hdr("Server", `(?i)BunnyCDN`),
		},
		{
			Name: "Imperva Incapsula", Type: "cdn", Category: "CDN/WAF",
			Confidence: 0.85,
			Headers: hdr("X-CDN|X-Iinfo", `(?i)Incapsula`),
		},
		{
			Name: "Sucuri", Type: "cdn", Category: "CDN/WAF",
			Confidence: 0.8,
			Headers: hdr("X-Sucuri-ID|X-Sucuri-Cache", `.+`),
		},
		{
			Name: "Azure CDN", Type: "cdn", Category: "CDN",
			Confidence: 0.7,
			Headers: hdr("Server", `(?i)Azure-CDN`),
		},
		{
			Name: "CacheFly", Type: "cdn", Category: "CDN",
			Confidence: 0.65,
			Headers: hdr("Server", `(?i)CacheFly`),
		},

		// ──────────────────────────────────────────────────
		// WAFs
		// ──────────────────────────────────────────────────

		{
			Name: "Cloudflare WAF", Type: "waf", Category: "WAF",
			Confidence: 0.85,
			Headers: hdr("CF-Cache-Status|CF-Worker", `.+`),
		},
		{
			Name: "AWS WAF", Type: "waf", Category: "WAF",
			Confidence: 0.75,
			Headers: merge(hdr("x-amzn-RequestId", `.+`), hdr("x-amzn-WAF", `.+`)),
		},
		{
			Name: "ModSecurity", Type: "waf", Category: "WAF",
			Confidence: 0.75,
			Headers: hdr("Server", `(?i)ModSecurity`)},
		{
			Name: "NAXSI", Type: "waf", Category: "WAF",
			Confidence: 0.7,
			Headers: hdr("X-Naxsi", `.+`),
		},
		{
			Name: "F5 BIG-IP ASM", Type: "waf", Category: "WAF",
			Confidence: 0.8,
			Headers: hdr("X-ASM|X-ASM-Policy|X-BIG-IP", `.+`),
		},
		{
			Name: "Fortinet FortiWeb", Type: "waf", Category: "WAF",
			Confidence: 0.7,
			Headers: hdr("X-FortiWeb|X-FW-Server", `.+`),
		},
		{
			Name: "Barracuda WAF", Type: "waf", Category: "WAF",
			Confidence: 0.7,
			Headers: hdr("X-Barracuda|X-BWAF", `.+`),
		},
		{
			Name: "Radware WAF", Type: "waf", Category: "WAF",
			Confidence: 0.65,
			Headers: hdr("X-RWAF|X-SL-CompState", `.+`),
		},
		{
			Name: "Akamai Kona", Type: "waf", Category: "WAF",
			Confidence: 0.75,
			Headers: hdr("X-Akamai-Staging|X-Akamai-RequestHeader", `.+`),
		},
		{
			Name: "Google Cloud Armor", Type: "waf", Category: "WAF",
			Confidence: 0.6,
			Headers: hdr("Via|X-Cloud-Trace-Context", `(?i)google`),
		},

		// ──────────────────────────────────────────────────
		// HOSTING
		// ──────────────────────────────────────────────────

		{
			Name: "Vercel", Type: "hosting", Category: "Hosting",
			Confidence: 0.92,
			Headers:    merge(hdr("Server", `(?i)vercel`), hdr("x-vercel-id|x-vercel-cache", `.+`)),
		},
		{
			Name: "Netlify", Type: "hosting", Category: "Hosting",
			Confidence: 0.92,
			Headers:    hdr("Server", `(?i)Netlify`),
		},
		{
			Name: "GitHub Pages", Type: "hosting", Category: "Hosting",
			Confidence: 0.9,
			Headers:    hdr("Server", `(?i)GitHub\.com`),
		},
		{
			Name: "Heroku", Type: "hosting", Category: "Hosting",
			Confidence: 0.85,
			Headers: hdr("Via|Server", `(?i)heroku`),
		},
		{
			Name: "Firebase Hosting", Type: "hosting", Category: "Hosting",
			Confidence: 0.85,
			Headers: hdr("Server", `(?i)Firebase`),
		},
		{
			Name: "Render", Type: "hosting", Category: "Hosting",
			Confidence: 0.75,
			Headers: hdr("Server", `(?i)render`),
		},
		{
			Name: "Railway", Type: "hosting", Category: "Hosting",
			Confidence: 0.65,
			Headers: hdr("Server", `(?i)railway`),
		},
		{
			Name: "Fly.io", Type: "hosting", Category: "Hosting",
			Confidence: 0.7,
			Headers: hdr("Server", `(?i)Fly`),
		},
		{
			Name: "DigitalOcean App Platform", Type: "hosting", Category: "Hosting",
			Confidence: 0.7,
			Headers: hdr("Server", `(?i)DigitalOcean`),
		},
		{
			Name: "AWS EC2", Type: "hosting", Category: "Cloud Hosting",
			Confidence: 0.7,
			Headers: merge(hdr("Server", `(?i)Amazon(?:S3|EC2)?`), hdr("x-amz-request-id", `.+`)),
		},
		{
			Name: "AWS S3", Type: "hosting", Category: "Cloud Storage",
			Confidence: 0.92,
			Headers: hdr("Server", `(?i)AmazonS3`),
		},
		{
			Name: "AWS Lambda", Type: "hosting", Category: "Serverless",
			Confidence: 0.65,
			Headers: hdr("x-amz-invocation-type|x-amz-log-type", `.+`),
		},

		// ──────────────────────────────────────────────────
		// FRONTEND FRAMEWORKS
		// ──────────────────────────────────────────────────

		{
			Name: "React", Type: "frontend", Category: "UI Library",
			Confidence: 0.8,
			HTML:       html(`react\.js`, `__REACT_DEVTOOLS`),
			Script:     html(`React\.createElement`, `_react2\b`),
		},
		{
			Name: "Next.js", Type: "framework", Category: "React Framework",
			Confidence: 0.9,
			Headers:    hdr("x-nextjs-cache|x-middleware-next", `.+`),
			HTML:       html(`__NEXT_DATA__`, `/_next/static`),
		},
		{
			Name: "Gatsby", Type: "framework", Category: "React Framework",
			Confidence: 0.85,
			HTML: html(`___gatsby`, `gatsby-`, `gatsby\.js`),
		},
		{
			Name: "Remix", Type: "framework", Category: "React Framework",
			Confidence: 0.8,
			HTML: html(`__remixContext`, `remix:route`),
		},
		{
			Name: "Vue.js", Type: "frontend", Category: "UI Library",
			Confidence: 0.85,
			HTML:       html(`(?i)vue\.js`, `__VUE__`, `data-v-[a-f0-9]+`),
			Script:     html(`createApp|Vue\.create`),
		},
		{
			Name: "Nuxt.js", Type: "framework", Category: "Vue Framework",
			Confidence: 0.85,
			HTML:       html(`__NUXT__`, `_nuxt/`),
		},
		{
			Name: "Angular", Type: "frontend", Category: "UI Library",
			Confidence: 0.85,
			HTML:       html(`ng-version`, `ng-app`, `_ngcontent`),
			VersionHTML: vhtml(`ng-version="([\d.]+)"`),
		},
		{
			Name: "Svelte", Type: "frontend", Category: "UI Library",
			Confidence: 0.8,
			HTML:       html(`svelte-[\w-]+`, `__svelte`),
			Script:     html(`svelte\.js`),
		},
		{
			Name: "SvelteKit", Type: "framework", Category: "Svelte Framework",
			Confidence: 0.8,
			HTML:       html(`__sveltekit`, `svelte-kit`),
		},
		{
			Name: "Astro", Type: "framework", Category: "Frontend Framework",
			Confidence: 0.85,
			Headers:    hdr("Server", `(?i)astro`),
			HTML:       html(`__astro`, `astro-[\w]{6}`),
		},
		{
			Name: "Preact", Type: "frontend", Category: "UI Library",
			Confidence: 0.75,
			HTML:       html(`preact\.js`, `__PREACT_DEVTOOLS__`),
			Script:     html(`createElement`),
		},
		{
			Name: "Solid.js", Type: "frontend", Category: "UI Library",
			Confidence: 0.7,
			HTML:       html(`solid\.js`, `__SOLID__`),
		},
		{
			Name: "Qwik", Type: "framework", Category: "Frontend Framework",
			Confidence: 0.75,
			HTML:       html(`qwikloader\.js`, `qwik\.js`),
		},
		{
			Name: "Alpine.js", Type: "frontend", Category: "UI Library",
			Confidence: 0.8,
			HTML:       html(`x-data`, `x-init`, `x-show`, `x-bind`, `x-on`),
			Script:     html(`alpine\.js`),
		},
		{
			Name: "HTMX", Type: "frontend", Category: "UI Library",
			Confidence: 0.85,
			HTML:       html(`htmx\.js`, `hx-get`, `hx-post`, `hx-target`, `hx-swap`),
		},
		{
			Name: "Lit", Type: "frontend", Category: "Web Components",
			Confidence: 0.7,
			HTML:       html(`lit\.js`, `lit-html`),
		},
		{
			Name: "Ember.js", Type: "frontend", Category: "UI Library",
			Confidence: 0.75,
			HTML:       html(`Ember\.Application`, `data-ember-extension`),
		},
		{
			Name: "Mithril.js", Type: "frontend", Category: "UI Library",
			Confidence: 0.6,
			Script:     html(`m\.render|m\.mount|Mithril`),
		},
		{
			Name: "Stencil.js", Type: "frontend", Category: "Web Components",
			Confidence: 0.65,
			HTML:       html(`stencil\.js|stencil\.core|s-id`),
		},

		// ──────────────────────────────────────────────────
		// BACKEND FRAMEWORKS
		// ──────────────────────────────────────────────────

		{
			Name: "Express", Type: "framework", Category: "Node.js Backend",
			Confidence: 0.7,
			Headers:    hdr("X-Powered-By", `(?i)express`),
		},
		{
			Name: "Django", Type: "framework", Category: "Python Backend",
			Confidence: 0.88,
			Headers:    hdr("Server", `(?i)WSGIServer`),
			Cookies:    merge(cook("csrftoken", `.+`), cook("sessionid", `.+`)),
		},
		{
			Name: "Flask", Type: "framework", Category: "Python Backend",
			Confidence: 0.8,
			Headers:    hdr("Server", `(?i)Werkzeug(?:/([\d.]+))?`),
			Cookies:    cook("session", `\.eJ`),
			VersionHeaders: vhdr("Server", `Werkzeug/([\d.]+)`),
		},
		{
			Name: "FastAPI", Type: "framework", Category: "Python Backend",
			Confidence: 0.8,
			Headers:    hdr("Server", `(?i)uvicorn`),
			HTML:       html(`fastapi`),
		},
		{
			Name: "Spring Boot", Type: "framework", Category: "Java Backend",
			Confidence: 0.8,
			Headers:    hdr("X-Application-Context", `.+`),
			Cookies:    cook("JSESSIONID", `.+`),
		},
		{
			Name: "ASP.NET", Type: "framework", Category: ".NET Backend",
			Confidence: 0.8,
			Headers:    hdr("X-AspNet-Version", `(.+)`),
			VersionHeaders: vhdr("X-AspNet-Version", `(.+)`),
		},
		{
			Name: "ASP.NET Core", Type: "framework", Category: ".NET Backend",
			Confidence: 0.8,
			Headers:    hdr("X-AspNet-Version|X-Powered-By", `(?i)ASP\.NET`),
		},
		{
			Name: "Ruby on Rails", Type: "framework", Category: "Ruby Backend",
			Confidence: 0.85,
			Headers:    hdr("X-Powered-By", `(?i)Phusion`),
			Cookies:    cook("_session", `.+`),
		},
		{
			Name: "Laravel", Type: "framework", Category: "PHP Backend",
			Confidence: 0.82,
			Cookies:    merge(cook("laravel_session", `.+`), cook("XSRF-TOKEN", `.+`)),
		},
		{
			Name: "Symfony", Type: "framework", Category: "PHP Backend",
			Confidence: 0.8,
			Cookies:    merge(cook("symfony", `.+`), cook("sf_redirect", `.+`)),
		},
		{
			Name: "CakePHP", Type: "framework", Category: "PHP Backend",
			Confidence: 0.7,
			Cookies:    cook("CAKEPHP", `.+`),
		},
		{
			Name: "CodeIgniter", Type: "framework", Category: "PHP Backend",
			Confidence: 0.7,
			Cookies:    cook("ci_session", `.+`),
		},
		{
			Name: "Yii", Type: "framework", Category: "PHP Backend",
			Confidence: 0.7,
			Cookies:    cook("_csrf|YII_CSRF_TOKEN", `.+`),
		},
		{
			Name: "Koa", Type: "framework", Category: "Node.js Backend",
			Confidence: 0.6,
			Headers:    hdr("X-Powered-By", `(?i)koa`),
		},
		{
			Name: "Fastify", Type: "framework", Category: "Node.js Backend",
			Confidence: 0.6,
			Headers:    hdr("X-Powered-By", `(?i)fastify`),
		},
		{
			Name: "NestJS", Type: "framework", Category: "Node.js Backend",
			Confidence: 0.7,
			Headers:    hdr("X-Powered-By", `(?i)NestJS`),
		},
		{
			Name: "Phoenix", Type: "framework", Category: "Elixir Backend",
			Confidence: 0.75,
			Headers:    hdr("Server", `(?i)Phoenix`),
		},
		{
			Name: "Play Framework", Type: "framework", Category: "Scala/Java Backend",
			Confidence: 0.7,
			Headers:    hdr("X-Powered-By", `(?i)Play`),
		},
		{
			Name: "Gin", Type: "framework", Category: "Go Backend",
			Confidence: 0.7,
			Headers:    hdr("Server|X-Powered-By", `(?i)Gin`),
		},
		{
			Name: "Echo", Type: "framework", Category: "Go Backend",
			Confidence: 0.65,
			Headers:    hdr("Server|X-Powered-By", `(?i)Echo`),
		},
		{
			Name: "Fiber", Type: "framework", Category: "Go Backend",
			Confidence: 0.65,
			Headers:    hdr("Server", `(?i)Fiber`),
		},

		// ──────────────────────────────────────────────────
		// CMS PLATFORMS
		// ──────────────────────────────────────────────────

		{
			Name: "WordPress", Type: "cms", Category: "CMS",
			Confidence: 0.95,
			HTML:       html(`(?i)wp-content`, `(?i)wp-includes`, `<generator[^>]+WordPress`),
			VersionHTML: vhtml(`generator[^>]+WordPress\s*([\d.]+)`),
		},
		{
			Name: "Drupal", Type: "cms", Category: "CMS",
			Confidence: 0.85,
			HTML:       html(`drupal\.js`, `Drupal\.settings`, `Drupal\.behaviors`, `sites/default`),
		},
		{
			Name: "Joomla", Type: "cms", Category: "CMS",
			Confidence: 0.85,
			HTML:       html(`(?i)/components/`, `(?i)/modules/`, `(?i)/templates/`),
			URL:        one(`/component/`),
		},
		{
			Name: "Magento", Type: "cms", Category: "E-commerce",
			Confidence: 0.85,
			HTML:       html(`Magento`, `mage\s*:`, `var\s+BASE_URL`),
			Cookies:    cook("frontend", `.+`),
		},
		{
			Name: "Shopify", Type: "cms", Category: "E-commerce",
			Confidence: 0.9,
			Headers:    hdr("X-ShopId|X-Shopify-Shop-Api-Call-Limit", `.+`),
			Cookies:    cook("_shopify_y|_shopify_s", `.+`),
		},
		{
			Name: "Squarespace", Type: "cms", Category: "Website Builder",
			Confidence: 0.8,
			HTML:       html(`squarespace\.com`, `static1\.squarespace`),
		},
		{
			Name: "Wix", Type: "cms", Category: "Website Builder",
			Confidence: 0.85,
			HTML:       html(`wix\.com`, `Wix\.js`, `static\.wixstatic`),
		},
		{
			Name: "TYPO3", Type: "cms", Category: "CMS",
			Confidence: 0.8,
			Headers:    hdr("X-TYPO3-Parsetime|X-TYPO3-Sitename", `.+`),
			HTML:       html(`typo3`),
		},
		{
			Name: "Umbraco", Type: "cms", Category: "CMS",
			Confidence: 0.75,
			HTML:       html(`umbraco`, `/umbraco/`),
			Cookies:    cook("UMB_UCONTEXT|UMB_UCONTEXT2", `.+`),
		},
		{
			Name: "Contentful", Type: "cms", Category: "Headless CMS",
			Confidence: 0.75,
			HTML:       html(`contentful\.com`, `ctfassets\.net`),
		},
		{
			Name: "Strapi", Type: "cms", Category: "Headless CMS",
			Confidence: 0.8,
			Headers:    hdr("X-Powered-By", `(?i)Strapi`),
		},
		{
			Name: "Ghost", Type: "cms", Category: "Blogging Platform",
			Confidence: 0.85,
			HTML:       html(`Ghost`, `ghost\.io`),
		},
		{
			Name: "Sitecore", Type: "cms", Category: "CMS",
			Confidence: 0.7,
			Headers:    hdr("X-Sitecore|X-Client-Referrer", `.+`),
		},
		{
			Name: "Adobe Experience Manager", Type: "cms", Category: "CMS",
			Confidence: 0.7,
			Headers:    hdr("Server|X-Powered-By", `(?i)AEM|Day\s?Software`),
		},
		{
			Name: "DNN (DotNetNuke)", Type: "cms", Category: "CMS",
			Confidence: 0.7,
			HTML:       html(`DNNPlatform|DotNetNuke`),
			Cookies:    cook(".DNN|DotNetNukeAnonymous", `.+`),
		},
		{
			Name: "PrestaShop", Type: "cms", Category: "E-commerce",
			Confidence: 0.7,
			HTML:       html(`PrestaShop`, `/themes/prestashop`),
		},
		{
			Name: "OpenCart", Type: "cms", Category: "E-commerce",
			Confidence: 0.65,
			HTML:       html(`OpenCart`, `route=common/home`),
		},

		// ──────────────────────────────────────────────────
		// CLOUD PROVIDERS
		// ──────────────────────────────────────────────────

		{
			Name: "Amazon Web Services", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.8,
			Headers:    merge(hdr("x-amz-request-id", `.+`), hdr("x-amz-id-2", `.+`)),
		},
		{
			Name: "Google Cloud Platform", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.75,
			Headers:    hdr("Via|X-Cloud-Trace-Context", `(?i)google`),
		},
		{
			Name: "Microsoft Azure", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.75,
			Headers:    hdr("X-Azure-Ref|X-Azure-RequestId|X-MS-RequestId", `.+`),
		},
		{
			Name: "Oracle Cloud", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.6,
			Headers:    hdr("Server", `(?i)Oracle`),
		},
		{
			Name: "IBM Cloud", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.5,
			Headers:    hdr("X-Backside|X-Global-Transaction-ID", `.+`),
		},
		{
			Name: "DigitalOcean", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.6,
			Headers:    hdr("Server", `(?i)DigitalOcean`),
		},
		{
			Name: "Vultr", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.4,
			HTML:       html(`vultr\.com`),
		},
		{
			Name: "Hetzner", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.5,
			Headers: hdr("Server", `(?i)Hetzner`),
		},
		{
			Name: "OVHcloud", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.5,
			Headers: hdr("Server|X-OVH", `(?i)OVH`),
		},
		{
			Name: "Linode", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.4,
			Headers: hdr("Server", `(?i)Linode`),
		},
		{
			Name: "Alibaba Cloud", Type: "cloud", Category: "Cloud Provider",
			Confidence: 0.6,
			Headers: hdr("Server|X-Alibaba", `(?i)Alibaba`),
		},

		// ──────────────────────────────────────────────────
		// DATABASES & DATA STORES
		// ──────────────────────────────────────────────────

		{
			Name: "MySQL", Type: "database", Category: "Database",
			Confidence: 0.5,
			HTML:       html(`(?i)mysql`, `SQL\s+error`),
		},
		{
			Name: "PostgreSQL", Type: "database", Category: "Database",
			Confidence: 0.5,
			HTML:       html(`(?i)postgresql`, `PostgreSQL`),
		},
		{
			Name: "MongoDB", Type: "database", Category: "NoSQL Database",
			Confidence: 0.5,
			HTML:       html(`(?i)mongodb`, `MongoDB`),
		},
		{
			Name: "Redis", Type: "database", Category: "In-Memory Store",
			Confidence: 0.5,
			HTML:       html(`(?i)redis`),
		},
		{
			Name: "Elasticsearch", Type: "database", Category: "Search Engine",
			Confidence: 0.6,
			URL:        one(`/_search|/_cat|/_cluster`),
		},
		{
			Name: "Cassandra", Type: "database", Category: "NoSQL Database",
			Confidence: 0.4,
			HTML:       html(`(?i)cassandra`),
		},
		{
			Name: "MariaDB", Type: "database", Category: "Database",
			Confidence: 0.5,
			Headers:    hdr("Server", `(?i)MariaDB`),
		},

		// ──────────────────────────────────────────────────
		// ANALYTICS & MONITORING
		// ──────────────────────────────────────────────────

		{
			Name: "Google Analytics", Type: "analytics", Category: "Analytics",
			Confidence: 0.9,
			Script:     html(`google-analytics\.com/analytics\.js`, `googletagmanager\.com/gtag/js`, `ga\s*\(|gtag\s*\(`),
		},
		{
			Name: "Google Tag Manager", Type: "analytics", Category: "Tag Manager",
			Confidence: 0.9,
			Script:     html(`googletagmanager\.com/gtm\.js`),
		},
		{
			Name: "Hotjar", Type: "analytics", Category: "Analytics",
			Confidence: 0.85,
			Script:     html(`hotjar\.com`, `_hjSettings|hjSettings`),
		},
		{
			Name: "Mixpanel", Type: "analytics", Category: "Analytics",
			Confidence: 0.8,
			Script:     html(`cdn\.mxpnl\.com`, `mixpanel\.init`),
		},
		{
			Name: "Amplitude", Type: "analytics", Category: "Analytics",
			Confidence: 0.8,
			Script:     html(`amplitude\.com`, `amplitude\.init`),
		},
		{
			Name: "Segment", Type: "analytics", Category: "Analytics",
			Confidence: 0.8,
			Script:     html(`cdn\.segment\.com`, `analytics\.load\s*\(`),
		},
		{
			Name: "Plausible", Type: "analytics", Category: "Analytics",
			Confidence: 0.85,
			Script:     html(`plausible\.io`),
		},
		{
			Name: "Matomo (Piwik)", Type: "analytics", Category: "Analytics",
			Confidence: 0.85,
			Script:     html(`matomo\.js`, `piwik\.js`, `_paq\.push`),
		},
		{
			Name: "Fullstory", Type: "analytics", Category: "Analytics",
			Confidence: 0.8,
			Script:     html(`fullstory\.com`, `FS\(\)|_fs_`),
		},
		{
			Name: "Sentry", Type: "monitoring", Category: "Error Tracking",
			Confidence: 0.85,
			Script:     html(`sentry\.min\.js`, `Sentry\.init`, `browser\.sentry\.cdn`),
		},
		{
			Name: "Datadog", Type: "monitoring", Category: "Monitoring",
			Confidence: 0.8,
			Headers:    hdr("X-Datadog|DD-", `.+`),
			Script:     html(`datadog-rum\.js`, `DD_RUM`),
		},
		{
			Name: "New Relic", Type: "monitoring", Category: "Monitoring",
			Confidence: 0.85,
			Script:     html(`newrelic\.com`, `NREUM`),
		},
		{
			Name: "Grafana", Type: "monitoring", Category: "Monitoring",
			Confidence: 0.7,
			Headers:    hdr("X-Grafana-", `.+`),
			URL:        one(`/grafana/|/grafana`),
		},
		{
			Name: "Prometheus", Type: "monitoring", Category: "Monitoring",
			Confidence: 0.75,
			URL:        one(`/metrics|/prometheus`),
		},
		{
			Name: "Heap", Type: "analytics", Category: "Analytics",
			Confidence: 0.7,
			Script:     html(`heapanalytics\.com`, `heap\.load`),
		},
		{
			Name: "HubSpot", Type: "analytics", Category: "CRM/Analytics",
			Confidence: 0.75,
			Script:     html(`js\.hs-scripts\.com`, `HubSpot`),
		},

		// ──────────────────────────────────────────────────
		// JAVASCRIPT LIBRARIES
		// ──────────────────────────────────────────────────

		{
			Name: "jQuery", Type: "js_lib", Category: "JavaScript Library",
			Confidence: 0.9,
			Script:     html(`jquery[.-]min\.js`, `jQuery\.|jquery`),
		},
		{
			Name: "Lodash", Type: "js_lib", Category: "JavaScript Library",
			Confidence: 0.8,
			Script:     html(`lodash\.js`, `\.\_\.`),
		},
		{
			Name: "Moment.js", Type: "js_lib", Category: "JavaScript Library",
			Confidence: 0.8,
			Script:     html(`moment\.js`, `moment\.min`),
		},
		{
			Name: "Axios", Type: "js_lib", Category: "HTTP Client",
			Confidence: 0.7,
			Script:     html(`axios\.js`, `axios\.min`),
		},
		{
			Name: "D3.js", Type: "js_lib", Category: "Data Visualization",
			Confidence: 0.85,
			Script:     html(`d3\.js`, `d3\.min`),
		},
		{
			Name: "Three.js", Type: "js_lib", Category: "3D Library",
			Confidence: 0.85,
			Script:     html(`three\.js`, `three\.min`),
		},
		{
			Name: "Chart.js", Type: "js_lib", Category: "Charting Library",
			Confidence: 0.85,
			Script:     html(`chart\.js`, `Chart\.min\.js`),
		},
		{
			Name: "Bootstrap", Type: "css_lib", Category: "CSS Framework",
			Confidence: 0.9,
			HTML:       html(`bootstrap\.min\.css`, `bootstrap\.css`, `bootstrap\.bundle`),
		},
		{
			Name: "Tailwind CSS", Type: "css_lib", Category: "CSS Framework",
			Confidence: 0.9,
			HTML:       html(`tailwindcss`, `tw-`, `tailwind\.min\.css`),
		},
		{
			Name: "Material UI", Type: "css_lib", Category: "React UI Library",
			Confidence: 0.75,
			HTML:       html(`Mui`, `material-ui`, `@mui`),
		},
		{
			Name: "Font Awesome", Type: "js_lib", Category: "Icon Library",
			Confidence: 0.85,
			HTML:       html(`font-awesome`, `fa[srldb]?\s+fa-`, `fontawesome\.com`),
		},

		// ──────────────────────────────────────────────────
		// PROXIES & LOAD BALANCERS
		// ──────────────────────────────────────────────────

		{
			Name: "Varnish", Type: "proxy", Category: "HTTP Cache",
			Confidence: 0.8,
			Headers:    hdr("X-Varnish|Via", `(?i)varnish`),
		},
		{
			Name: "Squid", Type: "proxy", Category: "Forward Proxy",
			Confidence: 0.7,
			Headers:    hdr("Server|X-Squid", `(?i)squid`),
		},
		{
			Name: "F5 BIG-IP", Type: "proxy", Category: "Load Balancer",
			Confidence: 0.8,
			Headers:    hdr("X-BIG-IP|X-F5", `.+`),
		},
		{
			Name: "AWS ELB", Type: "proxy", Category: "Load Balancer",
			Confidence: 0.7,
			Headers:    hdr("Server", `(?i)awselb`),
		},
		{
			Name: "Citrix ADC (NetScaler)", Type: "proxy", Category: "Load Balancer",
			Confidence: 0.7,
			Headers:    hdr("X-NetScaler|Via", `(?i)NetScaler`),
		},

		// ──────────────────────────────────────────────────
		// API & PROTOCOL
		// ──────────────────────────────────────────────────

		{
			Name: "GraphQL", Type: "api", Category: "API Protocol",
			Confidence: 0.8,
			URL:        one(`/graphql|/gql`),
			HTML:       html(`graphql`),
		},
		{
			Name: "REST API", Type: "api", Category: "API Protocol",
			Confidence: 0.6,
			URL:        one(`/api/v[12]|/rest/`),
		},
		{
			Name: "WebSocket", Type: "protocol", Category: "Protocol",
			Confidence: 0.7,
			Headers:    hdr("Upgrade|Sec-WebSocket-Version", `(?i)websocket`),
		},
		{
			Name: "gRPC", Type: "protocol", Category: "RPC Framework",
			Confidence: 0.6,
			Headers:    hdr("Content-Type", `application/grpc`),
		},
		{
			Name: "JSON API", Type: "api", Category: "API Format",
			Confidence: 0.5,
			Headers:    hdr("Content-Type", `application/vnd\.api\+json`),
		},

		// ──────────────────────────────────────────────────
		// SECURITY TOOLS
		// ──────────────────────────────────────────────────

		{
			Name: "Let's Encrypt", Type: "certificate", Category: "TLS Certificate",
			Confidence: 0.9,
			Headers:    hdr("X-Certificate-Info|Server", `(?i)Let'?s Encrypt`),
		},
		{
			Name: "reCAPTCHA", Type: "security", Category: "Bot Protection",
			Confidence: 0.9,
			Script:     html(`google\.com/recaptcha`, `g-recaptcha`),
		},
		{
			Name: "hCaptcha", Type: "security", Category: "Bot Protection",
			Confidence: 0.85,
			Script:     html(`hcaptcha\.com`, `h-captcha`),
		},
		{
			Name: "Auth0", Type: "auth", Category: "Authentication",
			Confidence: 0.8,
			Script:     html(`auth0\.com`, `auth0\.js`),
		},
		{
			Name: "Okta", Type: "auth", Category: "Authentication",
			Confidence: 0.7,
			Headers:    hdr("X-Okta-", `.+`),
			URL:        one(`/oauth2/default`),
		},
		{
			Name: "Firebase Auth", Type: "auth", Category: "Authentication",
			Confidence: 0.8,
			Script:     html(`firebase\.js|firebase-app\.js`, `__FIREBASE`),
		},
		{
			Name: "Clerk", Type: "auth", Category: "Authentication",
			Confidence: 0.7,
			Script:     html(`clerk\.js`, `__CLERK`),
		},
	}
}

func merge[T any](a, b map[string]T) map[string]T {
	for k, v := range b {
		a[k] = v
	}
	return a
}
