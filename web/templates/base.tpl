{{ define "base" }}
<!DOCTYPE html>
<html>
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
  </style>
  {{ template "head" . }}
</head>
<body>
  {{ template "body" . }}

  <footer>
    <a href="https://github.com/letsdebug/letsdebug" target="_blank" rel="noopener noreferrer">Find us at github.com/letsdebug -
      we have an API and command line tool as well.</a>
    Let's Encrypt™ is a trademark of the Internet Security Research Group. 
  </footer>
</body>
</html>
{{ end }}