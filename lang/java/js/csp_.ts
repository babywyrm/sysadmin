
type Directive =
  | 'child-src'
  | 'connect-src'
  | 'default-src'
  | 'font-src'
  | 'frame-src'
  | 'img-src'
  | 'manifest-src'
  | 'media-src'
  | 'object-src'
  | 'prefetch-src'
  | 'script-src'
  | 'script-src-elem'
  | 'script-src-attr'
  | 'style-src'
  | 'style-src-elem'
  | 'style-src-attr'
  | 'worker-src'
  | 'base-uri'
  | 'plugin-types'
  | 'sandbox'
  | 'form-action'
  | 'frame-ancestors'
  | 'navigate-to'
  | 'report-uri'
  | 'report-to'
  | 'block-all-mixed-content'
  | 'referrer'
  | 'require-sri-for'
  | 'require-trusted-types-for'
  | 'trusted-types'
  | 'upgrade-insecure-requests';



//
//

//
// https://github.com/entur/csp
//

@entur/csp

Generate CSP headers with help from TypeScript.

The Content-Security-Policy is an important security feature. But it can get pretty long and cumbersome to update. This nifty tool lets you generate the header string from a JavaScript (or TypeScript) object.

If you are using TypeScript you can use our enums to get help in the form of type coverage and autocomplete in your editor.

npm install @entur/csp

// myCsp.ts

import { stringifyCSP, Directive, PolicyValue } from '@entur/csp'

const myDomains = [
    PolicyValue.SELF,
    'example.com',
    '*.example.com',
]

const policyString = stringifyCSP({
    [Directive.DEFAULT_SRC]: [SELF],
    [Directive.CONNECT_SRC]: [
        ...MY_DOMAINS,
    ],
    [Directive.SCRIPT_SRC]: [
        PolicyValue.SELF,
        PolicyValue.UNSAFE_INLINE,
        PolicyValue.UNSAFE_EVAL,
        PolicyValue.BLOB,
        'https://www.googletagmanager.com',
        'https://tagmanager.google.com',
    ],
    [Directive.IMG_SRC]: [
        ...MY_DOMAINS,
        PolicyValue.DATA,
        PolicyValue.BLOB,
        'https://www.google-analytics.com',
    ],
    [Directive.STYLE_SRC]: [
        PolicyValue.SELF,
        PolicyValue.UNSAFE_INLINE,
    ],
})
