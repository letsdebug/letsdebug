{{ define "head" }}
<style>
.results {
  padding: 1rem 0;
}
.tests {
  width: 100%;
}
.tests td {
  padding: 1rem;
  vertical-align: middle;
}
tr.test:nth-child(odd) {
  background: whitesmoke;
}
.severity-Warning {
  color: rgba(255, 166, 0, 0.657);
}
.severity-Error {
  color: rgb(155, 41, 0);
}
.severity-Fatal {
  color: darkred;
}
.severity-OK {
  color: rgb(0, 77, 0);
}

</style>
{{ end }}
{{ define "body" }}
<div class="container">
  <a href="/"><h1>Let's Debug</h1></a>

  {{ if .Error }}
  <section class="error">{{ .Error }}</section>
  <section class="description">
    <p><a href="/">Go back to the start.</a></p>
  </section>
  {{ else }}

  <h2>Previous tests for {{ .Domain }}</h2>
  <section class="results">
    <table class="tests">
      {{ range $index, $test := .Tests }}
      <tr class="test">
        <td style="width: 10%" class="test-id"><a href="/{{ .Domain }}/{{ $test.ID }}">#{{ $test.ID }} ({{ $test.Method }})</a></td>
        <td style="width: 20%" class="test-date"><abbr title="{{ $test.CreatedTimestamp }}">{{ $test.SubmitTime }}</abbr></td>
        <td style="width: 20%" class="test-severity severity-{{ $test.Severity }}">{{ $test.Severity }}</td>
        <td style="width: 50%" class="test-summary">{{ $test.Summary }}</td>
      </tr>
      {{ end }}
    </table>
  </section>
  {{ end }}
</div>
{{ end }}
{{ template "base" . }}