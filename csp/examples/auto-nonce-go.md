# Auto-noncing in Go html/template

## Background

[CSP](https://csp.withgoogle.com/docs/index.html) mitigates many client-side security vulnerabilities.
A policy is a whitelist of locations from which JavaScript, Styles, and other content can be loaded.
CSP allows [nonces](https://www.w3.org/TR/CSP/#grammardef-nonce-source) &
[hashes](https://www.w3.org/TR/CSP/#grammardef-hash-source) to make it easy for a policy to allow
some inline content without allowing all inline content.

[html/template](https://golang.org/pkg/html/template/) makes it easy to produce HTML that preserves the
template author's intent in the face of untrusted inputs.

The upcoming `safehtml/template` builds on `html/template` to, among other things, distinguish between
URLs that load code into the documents origin (*TrustedResourceUrls*) and those that do not (*SafeUrl*),
like link target URLs and media src URLs.

### Using CSP

Right now, a server can pass a nonce into a template.

```html
<script nonce="{{.CSPNonce}}">
...
</script>
```

and this is fine since the autoescaper ensures that any third-party content interpolated into the
script tag is side-effect-free at evaluation time.

There is a risk though in some other constructs

```html
<link rel="script" href="{{.ScriptSrc}}" />
```

In this case, the same script would have to end up in the CSP policy.
Alternatively, the template maintainer could add a nonce

```html
<link rel="script" href="{{.ScriptSrc}}" nonce="{{.CSPNonce}} />
```

adding a nonce is implicitly saying that whatever `{{.}}` evaluates to is a safe
script source.  This avoids the type-safety-based security around *SafeURL* in Hugo
and in the upcoming *safehtml/template*.

There is also a maintenance risk when something like

```html
<link rel="script" href="{{.BaseUrl}}/script/foo.js" nonce="{{.CSPNonce}}" />
```

is edited to make the *href* more general.


## Problem

There are two problems

1.  Without nonces the code that generates CSP policy headers needs to be tightly integrated with
    the html/template that produces the HTML.
2.  If template authors have to sprinkle `nonce="..."` around their templates they make mistakes
    with security consequences.

## Related Work

For the [Closure Templates language](https://developers.google.com/closure/templates/docs/security#content_security_policy)
we got template authors out of the business of adding nonces to code.

## Proposal

Augment `html/template` to inject `{{if $.CSPNonce}} nonce="{{$.CSPNonce}}"{{end}}` in the following contexts:

A *script* element with no `src` attribute.

```html
<script HERE>...</script>
```

A *style* element.

```html
<style HERE>...</style>
```

These are the main use cases for CSP nonces but there are some other contexts we could consider.

  *  [`<img>`](https://www.w3.org/TR/CSP/#directive-img-src) elements, and
  *  [media elements](https://www.w3.org/TR/CSP/#media-src) (`<audio>`, `<track>`, `<video>`)
  *  `<link rel="favicon">` (modulo [bug](https://bugzilla.mozilla.org/show_bug.cgi?id=1167259))

load content, but not into the same origin.

Others are riskier

  *  [`<iframe>`](https://www.w3.org/TR/CSP/#directive-frame-src) can affect the current page in
     many ways if not strictly sandboxed,
  *  A `<link>` with a *rel* attribute with value in (*import*, *manifest*, *script*, *stylesheet*)
     can load code directly into the same origin.

It is unsafe to inject the nonce if the `src`/`href` is dynamic and not a *TrustedResourceUrl*.  *safehtml/template*
ensures this property but *html/template* does not.


## Whence nonces?

Generating a strongly unpredictable, properly scoped nonce will be left to frameworks.

When one template calls another though, it can pass a portion of the input, so the callee may not receive the caller's nonce.

We use the implicitly defined `$` variable to reach a nonce at the top level.
This means that every top-level template input that produces CSP-compatible output needs to have a nonce.

We can ease this by providing

```go
struct {
    CSPNonce Nonce
}
```

that can be mixed into an input struct via an anonymous field.



## Alternative Solutions

To avoid tight coupling between the code that generates CSP policy headers,
and the html/template, a template could use a
custom function.

```html
<script src="{{.scriptSrc | addToCspWhitelist}}">...</script>
```

The function could callback to CSP policy generating code while returning its value unchanged.

This requires the response body be rendered before headers are written
and could suffer from the same lack of type-safety.
