package slowredirect

import (
	"bytes"
	"html/template"

	"canary-token-generator/backend/internal/core"
)

const fallbackTarget = "https://www.google.com"

// La pagina se genera con html/template: los valores inyectados en el contexto JavaScript reciben el
// escape correcto (antes se usaba html.EscapeString dentro de un literal JS, que es el contexto
// equivocado: no neutraliza "\" ni saltos de linea, y permitia targets "javascript:").
var pageTmpl = template.Must(template.New("interstitial").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Redirecting…</title>
<style{{if .Nonce}} nonce="{{.Nonce}}"{{end}}>
  body{margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif}
  .box{text-align:center}
  .spin{width:36px;height:36px;margin:0 auto 16px;border:3px solid #334155;border-top-color:#38bdf8;border-radius:50%;animation:s 1s linear infinite}
  @keyframes s{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="box"><div class="spin"></div><p>Please wait while we redirect you…</p></div>
<script{{if .Nonce}} nonce="{{.Nonce}}"{{end}}>
(function () {
  var target = {{.Target}};
  var beacon = {{.Beacon}};
  var done = false;
  function go() { if (done) return; done = true; window.location.replace(target); }

  function toHex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join(''); }
  function sha256(str) {
    if (window.crypto && crypto.subtle && window.TextEncoder) {
      return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(toHex);
    }
    var h = 5381; for (var i = 0; i < str.length; i++) { h = ((h << 5) + h + str.charCodeAt(i)) | 0; }
    return Promise.resolve('weak-' + (h >>> 0).toString(16));
  }
  function canvasData() {
    try {
      var c = document.createElement('canvas'); c.width = 240; c.height = 60;
      var x = c.getContext('2d'); x.textBaseline = 'top'; x.font = '14px Arial';
      x.fillStyle = '#f60'; x.fillRect(100, 1, 62, 20); x.fillStyle = '#069';
      x.fillText('Cwm fjordbank glyphs vext quiz, \u{1F603}', 2, 15);
      return c.toDataURL();
    } catch (e) { return ''; }
  }
  function webgl() {
    try {
      var gl = document.createElement('canvas').getContext('webgl'); if (!gl) return {};
      var ext = gl.getExtension('WEBGL_debug_renderer_info'); if (!ext) return {};
      return { webglVendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL), webglRenderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) };
    } catch (e) { return {}; }
  }

  sha256(canvasData()).then(function (canvasHash) {
    var fp = {
      screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth, availWidth: screen.availWidth, availHeight: screen.availHeight },
      timezone: (Intl.DateTimeFormat().resolvedOptions() || {}).timeZone || '',
      timezoneOffset: new Date().getTimezoneOffset(),
      platform: navigator.platform || '',
      languages: Array.prototype.slice.call(navigator.languages || []),
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      deviceMemory: navigator.deviceMemory || 0,
      touchPoints: navigator.maxTouchPoints || 0,
      doNotTrack: navigator.doNotTrack || '',
      canvasHash: canvasHash
    };
    var w = webgl(); fp.webglVendor = w.webglVendor || ''; fp.webglRenderer = w.webglRenderer || '';
    // text/plain + no-cors: peticion "simple" sin preflight, funciona aunque esta pagina se aloje en otro dominio.
    // keepalive evita que la navegacion cancele el envio.
    return fetch(beacon, { method: 'POST', mode: 'no-cors', keepalive: true, headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify(fp) });
  }).catch(function () {}).then(function () { setTimeout(go, 150); });

  setTimeout(go, 2500);
})();
</script>
<noscript><meta http-equiv="refresh" content="0;url={{.Target}}"></noscript>
</body>
</html>`))

type pageData struct {
	Target, Beacon, Nonce string
}

// RenderInterstitialHTML genera la pagina intermedia. targetURL se revalida SIEMPRE aqui (defensa en
// profundidad frente a filas antiguas de la BD con valores peligrosos). beaconURL debe ser absoluta
// para que el artefacto funcione tambien si se descarga y se aloja en otro dominio.
func RenderInterstitialHTML(tokenID, targetURL, beaconURL, nonce string) string {
	target, err := core.ValidateTargetURL(targetURL)
	if err != nil || target == "" {
		target = fallbackTarget
	}
	if beaconURL == "" {
		beaconURL = "/f/" + tokenID
	}
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, pageData{Target: target, Beacon: beaconURL, Nonce: nonce}); err != nil {
		return "<!DOCTYPE html><title>Redirecting</title>"
	}
	return buf.String()
}
