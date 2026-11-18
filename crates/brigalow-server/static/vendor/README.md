htmx v4.0.1, vendored from https://github.com/bigskysoftware/htmx/tree/v4.0.1/dist .

SHA-256: `a0abb04f2f45a1f89d1d4844023245537e5e6014c87b144553e0607b4cc32130`. Licence retained in htmx-LICENSE. No Node build step. htmx 4 removes eval-dependent features; indicator CSS is disabled. CSP permits same-origin scripts and connections only.

UI SDK `@ui-sdk/core` v0.1.0-beta.6 `dist/web.css`, vendored from https://registry.npmjs.org/@ui-sdk/core/-/core-0.1.0-beta.6.tgz (registry integrity `sha512-4JDArOSaTDRArUs+XXojXVNS1kf1D/aOMan6GIp8J9+cwAdijCypbClApS2jBc4SxgZbJCIDHsMlFOIPyEv8+g==`). Source: https://github.com/vercel-labs/ui.

SHA-256: `8875896ee97567435d260a81428f73cb491f6caf0b9da56b61b831b6e13ec103`. Apache-2.0 licence retained in ui-sdk-LICENSE. Stylesheet only; no UI SDK JavaScript is shipped. Templates opt in with `data-slot` attributes. Its icon masks are `data:` URLs that only load for components Brigalow does not use; CSP is unchanged (`style-src 'self'`, no `img-src`).
