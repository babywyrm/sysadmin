import { IncomingForm } from "formidable";
import {
  parseFlightChunk,
  chunkThen
} from "../../lib/vulnerable-flight-parser";

export const config = { api: { bodyParser: false } };

// VULNERABLE "React Flight" endpoint simulation
export default async function handler(req, res) {
  const form = new IncomingForm();

  form.parse(req, async (err, fields) => {
    if (err) {
      return res.status(500).send("Form parse error");
    }

    // Convert chunk strings into objects
    const chunks = {};
    for (const key of Object.keys(fields)) {
      try {
        chunks[key] = JSON.parse(fields[key]);
      } catch {
        chunks[key] = fields[key];
      }
    }

    // Root chunk (0)
    const root = chunks["0"];

    // Overwrite its .then to simulate RSC await behavior
    root.then = function (resolve, reject) {
      chunkThen(resolve, reject, root);
    };

    try {
      // Trigger the chain
      await root;
      res.status(200).send("Executed without visible output.");
    } catch (e) {
      res.status(500).send(`Error digest:\n${e.digest || e.toString()}`);
    }
  });
}
