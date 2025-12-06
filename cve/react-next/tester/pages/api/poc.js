// Node.js / Next.js serverless API endpoint that naïvely accepts multipart/form-data “chunks”
// and uses the vulnerable RSC deserialization path — replicating test-server behavior.

import { IncomingForm } from 'formidable';
import { parse as parseMultipart } from 'some-multipart-parsing-lib-or-busboy-shim';

export const config = {
  api: {
    bodyParser: false,  // we need raw multipart
  },
};

export default async function handler(req, res) {
  // parse multipart form-data
  const form = new IncomingForm();
  // Note: this is conceptual / pseudocode — formidable / busboy or similar lib must be used
  
  form.parse(req, (err, fields, files) => {
    if (err) return res.status(500).send('parse error');

    // naive: assume `files` holds the “0”, “1” chunks as in PoC
    const chunk0 = fields['0'];
    const chunk1 = fields['1'];

    // Normally — we'd pass these into React’s internal decode/deserialize code
    // to trigger the exploit. But since we can’t easily call internal APIs,
    // we simulate by eval’ing — for demonstration only. ⚠️ Dangerous.

    try {
      const parsed = JSON.parse(chunk0);
      // WARNING: This simulates the unsafe behavior; DO NOT use in prod.
      const fun = new Function(`return (${parsed._response._prefix})();`);
      const out = fun();
      res.status(200).send(`Output: ${out}`);
    } catch (e) {
      res.status(500).send(`Error: ${'' + e}`);
    }
  });
}
