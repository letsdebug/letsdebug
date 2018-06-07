{{ define "head" }}
{{ .WorkerCount }}
<style>
form, form input, form select {
  font-size: 1rem;
  min-width: auto;
}
input, select {
  padding: 0.5rem;
}
.fieldset {
  display: flex;
  flex-wrap: wrap;
  flex-direction: row;
  border: none;
  padding: 0;
}
.domain {
  flex-grow: 1;
}
.submit {
  display: block;
  margin: 1rem 0;
}
</style>
{{ end }}
{{ define "body" }}
<div class="container">
  <h1 class="title">Let's Debug</h1>
  
  <section class="description">
    <p>Let's Debug is a diagnostic tool/website to help figure out why you might not be able to issue a certificate for 
      <a href="http://letsencrypt.org/" target="_blank" rel="noopener noreferrer">Let's Encrypt™</a>.</p>
    <p>Using a set of tests designed specifically for Let's Encrypt, it can identify 
      <a href="https://github.com/letsdebug/letsdebug/#problems-detected" target="_blank" rel="noopener noreferrer">
      a variety of issues</a>, including:
     problems with basic DNS setup,
     problems with nameservers,
     rate limiting,
     networking issues,
     CA policy issues and
     common website misconfigurations.</p>
  </section>

  {{ if .Error }}
  <section class="error">{{ .Error }}</section>
  {{ end }}

  <section class="form">
    <p>Enter the domain and validation method you are having trouble issuing a certificate with. <small>(Choose HTTP-01 if unsure)</small>.</p>
    <form action="/" method="POST">
      <div class="fieldset">
        <input type="text" autofocus tabindex="1" class="domain" name="domain" placeholder="example.org" required>
        <select name="method" tabindex="2" class="validation-method">
          <option value="http-01">HTTP-01</option>
          <option value="dns-01">DNS-01</option>
          <option value="tls-alpn-01">TLS-ALPN-01</option>
          <option value="tls-sni-01">TLS-SNI-01</option>
          <option value="tls-sni-02">TLS-SNI-02</option>
        </select>    
      </div>
      <input class="submit" tabindex="3" type="submit" value="Run Test">
    </form>
  </section>
</div>
{{ end }}
{{ template "base" . }}