document.body.innerHTML = `
<nav class="navbar navbar-expand-lg fixed-top navbar-light bg-light">
  <div class="container">
    <a class="navbar-brand" href="https://mfkdf.com"><img src="https://mfkdf.com/navlogo.png" alt="MFKDF" height="30"></a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarSupportedContent">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="https://mfkdf.com/docs">Docs</a></li>
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" id="tutorials" role="button" data-bs-toggle="dropdown" aria-expanded="false">
            Tutorials
          </a>
          <ul class="dropdown-menu" aria-labelledby="tutorials">
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-01quickstart.html">Getting Started</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-02mfkdf.html">Multi-Factor Key Derivation</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-03threshold.html">Threshold-based Key Derivation</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-04stacking.html">Key Stacking</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-05policy.html">Policy-based Key Derivation</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-06entropy.html">Entropy Estimation</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-08persistence.html">Factor Persistence</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-07reconstitution.html">Recovery & Reconstitution</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-09crypto.html">Cryptographic Operations</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-10enveloping.html">Enveloped Secrets</a></li>
            <li><a class="dropdown-item" href="https://mfkdf.com/docs/tutorial-11auth.html">Authentication using MFKDF</a></li>
          </ul>
        </li>
        <li class="nav-item"><a class="nav-link" href="https://mfkdf.com/tests">Testing</a></li>
        <li class="nav-item"><a class="nav-link" href="https://mfkdf.com/coverage">Coverage</a></li>
        <li class="nav-item"><a class="nav-link" href="https://mfkdf.com/demo">Demo</a></li>
        <li class="nav-item"><a class="nav-link" href="https://mfkdf.com/videos">Videos</a></li>
      </ul>
      <form class="d-flex"><a class="btn btn-outline-success my-2 my-sm-0" href="https://github.com/multifactor/MFKDF">Get Started</a></form>
    </div>
  </div>
</nav>
` + document.body.innerHTML;
