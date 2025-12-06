// ⚠️ INTENTIONALLY UNSAFE FOR RESEARCH ONLY
// Minimal reimplementation of the vulnerable React Flight deserialization chain

export function parseFlightChunk(name, value, allChunks) {
  // Resolve $ references
  if (typeof value === "string" && value.startsWith("$")) {
    const parts = value.slice(1).split(":");

    let obj = allChunks[parts[0]];
    for (let i = 1; i < parts.length; i++) {
      obj = obj[parts[i]];
    }
    return obj;
  }
  return value;
}

// Simulated Chunk.then behavior used by RSC
export function chunkThen(resolve, reject, chunk) {
  try {
    const parsed = JSON.parse(chunk.value);
    const revived = reviveModel(chunk._response, { "": parsed }, "");
    resolve(revived);
  } catch (e) {
    reject(e);
  }
}

function reviveModel(response, parent, key) {
  const raw = parent[key];

  if (typeof raw === "string" && raw.startsWith("$B")) {
    const idx = raw.slice(2);
    const prefix = response._prefix;
    const getter = parseFlightChunk("get", response._formData.get, response);
    return getter(prefix + idx);
  }

  return raw;
}
