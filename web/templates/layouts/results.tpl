{{ define "head" }}
<style>
.problem {
  padding: 1rem;
  margin: 1rem 0;
}
.problem-Warning {
  color: black;
  background: rgba(255, 166, 0, 0.657);
}
.problem-Error {
  color: #eee;
  background: rgb(155, 41, 0);
}
.problem-Fatal {
  color: darkred;
  background-color: rgba(255,0,0,0.25);
}
.problem-OK {
  color: #eee;
  background: rgb(0, 77, 0);
}
.problem-OK a, .problem-OK a:visited {
  color: #eee;
  text-decoration: underline;
}
.problem-header {
  display: flex;
  flex-direction: row;
  justify-content: space-between;
}
.problem-name {
  font-weight: bold;
}
.problem-description {
  margin: 1rem 0;
  font-size: 1.05rem;
}
.problem-detail {
  font-size: 0.9rem;  
}
.problem-severity {
  text-transform: uppercase;
  font-size: 0.8em;
}
.times {
  font-size: 0.75rem;
  color: #333;
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

  <h2>Test results for <a href="/{{ .Test.Domain}}">{{ .Test.Domain }}</a></h2>
  {{ if eq .Test.Status "Cancelled" }}
  <section class="error">
    This test was cancelled by the server, sorry! You may try again. <a href="/">Go back to the start.</a>
  </section>
  {{ else if ne .Test.Status "Complete"}}
  <section class="description">
    The test is currently {{ .Test.Status }} ... please wait, this page will refresh automatically ...
  </section>
  {{ else if .Test.Result.Error }}
  <section class="results">
    <p>Unfortunately something went wrong when running the test.</p>
    <div class="error">{{ .Test.Result.Error }}</div>
  </section>
  {{ else if not .Test.Result.Problems }}
  <section class="results">
    <div class="problem problem-OK">
      <div class="problem-header">
        <div class="problem-name">All OK!</div>
        <div class="problem-severity">OK</div>
      </div>
      <div class="problem-description">
        <p>No issues were found with {{ .Test.Domain }}. If you are having problems with creating an SSL certificate,
          please visit the <a href="https://community.letsencrypt.org/" target="_blank" rel="noopener noreferrer">
          Let's Encrypt Community forums</a> and post a question there.
        </p>
      </div>
    </div>
  </section>
  {{ else }}
  <section class="results">
    {{ range $index, $problem := .Test.Result.Problems }}
    <div class="problem problem-{{ $problem.Severity }}">
      <div class="problem-header">
          <div class="problem-name">{{ $problem.Name }} </div>
          <div class="problem-severity">{{ $problem.Severity }}</div>    
      </div>
      <div class="problem-description">{{ $problem.Explanation }} </div>
      <div class="problem-detail">
        {{ range $dIndex, $detail := $problem.DetailLines }}{{ $detail }} <br/>{{ end }}
      </div>
    </div>
    {{ end }}
  </section>
  {{ end }}
  <section class="description">
    <p class="times">Submitted <abbr title="{{ .Test.CreatedAt }}">{{ .Test.SubmitTime }} ago</abbr>.
    {{ if .Test.QueueDuration }}Sat in queue for {{ .Test.QueueDuration }}.{{ end }}
    {{ if .Test.TestDuration }}Completed in {{ .Test.TestDuration }}.{{ end }}</p>
  </section>        
  {{ end }}
</div>
{{ end }}
{{ template "base" . }}