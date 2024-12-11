{{ define "base" }}
<!DOCTYPE html>
<html xmlns:og="http://ogp.me/ns#">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Let's Debug</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    html {
      font-family: sans-serif;
      font-size: 16px;
    }
    a, a:visited {
      color: #2c3c69;
      text-decoration: none;
      transition: color .25s linear;
    }
    a:hover {
      color: #666;
    }
    .container, footer {
      max-width: 990px;
      margin: 0 auto;
    }
    section {
      margin: 2rem 0;
    }
    footer {
      font-size: 0.9rem;
    }
    h1  {
      font-size: 3rem;
      color: #2c3c69;
    }
    .error {
      background-color: rgba(255, 0, 0, 0.25);
      color: darkred;
      border-radius: 4px;
      padding: 1rem;
    }
    .warning {
      color: black;
      background: rgba(255, 166, 0, 0.657);
      border-radius: 4px;
      padding: 1rem;
      margin: 1rem 0;
    }
    footer {
      font-size: 0.8rem;
    }
  </style>
  {{ template "head" . }}
</head>
<body>
  {{ template "body" . }}
  <footer>
    <p>We also have open-source
      <a href="https://github.com/letsdebug/letsdebug" target="_blank" rel="noopener noreferrer">API and CLI tools</a>,
      as well as
      <a href="https://tools.letsdebug.net/cert-search" target="_blank" rel="noopener noreferrer">web-based certificate search</a>
      and
      <a href="https://tools.letsdebug.net/cert-revoke" target="_blank" rel="noopener noreferrer">certificate revocation.</a>
    </p>
    <p>Let's Encrypt™ is a trademark of the Internet Security Research Group (ISRG).</p>
    <p>Let's Debug is not affiliated with, or sponsored or endorsed by, ISRG.</p>
  </footer>
</body>
</html>
{{ end }}
