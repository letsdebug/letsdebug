{{ define "head" }}
{{ end }}
{{ define "body" }}
<div class="container">
  <h1>Let's Debug</h1>

  {{ if .Error }}
  <section class="error">{{ .Error }}</section>
  <section class="description">
    <p><a href="/">Go back to the start.</a></p>
  </section>
  {{ else }}

  <h2>Test results for {{ .Test.Domain }}</h2>
  {{ if ne .Test.Status "Complete"}}
  <section class="description">
    The test is {{ .Test.Status }} ... please wait.
  </section>
  {{ else }}
  <section class="results">
    {{ .Test.Result }}
  </section>
  {{ end }}
  {{ end }}
</div>
{{ end }}
{{ template "base" . }}