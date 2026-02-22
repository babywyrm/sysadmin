
# Ollama Model Comparison: 16GB RAM, CPU-Only NUC

## The Hard Constraints

- **Usable RAM for model:** ~12–13GB after OS overhead
- **Inference backend:** CPU only (llama.cpp under the hood)
- **Bottleneck:** Memory bandwidth, not compute. Your CPU cores are mostly waiting on RAM reads
- **Quantization sweet spot:** Q4_K_M — best quality-to-size tradeoff at this tier

---

## Model Size vs. RAM Usage at Q4_K_M

| Model | VRAM/RAM @ Q4_K_M | Fits? | Context (default) |
|---|---|---|---|
| Llama 3.2 3B | ~2.0 GB | ✅ Comfortably | 128k |
| Phi-4 mini 3.8B | ~2.5 GB | ✅ Comfortably | 128k |
| Llama 3.1 8B | ~4.9 GB | ✅ Comfortably | 128k |
| Gemma 3 9B | ~5.8 GB | ✅ Fine | 128k |
| Qwen 2.5 7B | ~4.4 GB | ✅ Comfortably | 128k |
| Qwen 2.5 Coder 7B | ~4.4 GB | ✅ Comfortably | 128k |
| Mistral 7B v0.3 | ~4.1 GB | ✅ Comfortably | 32k |
| Llama 3.1 70B | ~40 GB | ❌ No | 128k |
| Gemma 3 12B | ~7.8 GB | ✅ Tight but ok | 128k |
| Phi-4 14B | ~9.0 GB | ⚠️ Very tight | 16k |

---

## Technical Performance Expectations (CPU-only, ~8–12 tok/s realistic)

| Model | Est. Tokens/sec | Quality Tier | Best Use Case |
|---|---|---|---|
| Llama 3.2 3B | 25–40 tok/s | ⭐⭐⭐ | Fast chat, simple tasks |
| Phi-4 mini 3.8B | 20–35 tok/s | ⭐⭐⭐⭐ | Reasoning, punches above weight |
| Mistral 7B | 10–18 tok/s | ⭐⭐⭐⭐ | General purpose, instruction following |
| Llama 3.1 8B | 8–15 tok/s | ⭐⭐⭐⭐ | Best general 8B, strong reasoning |
| Qwen 2.5 7B | 10–16 tok/s | ⭐⭐⭐⭐ | Multilingual, strong benchmarks |
| Qwen 2.5 Coder 7B | 10–16 tok/s | ⭐⭐⭐⭐⭐ | Code generation, best-in-class at 7B |
| Gemma 3 9B | 7–13 tok/s | ⭐⭐⭐⭐ | Vision tasks (if multimodal needed) |
| Gemma 3 12B | 5–9 tok/s | ⭐⭐⭐⭐⭐ | Best quality you can run, slower |

---

## Key Technical Tradeoffs to Know

**Quantization levels explained:**
- `Q2_K` — Smallest, fastest, noticeable quality degradation. Avoid unless RAM-critical
- `Q4_K_M` — **Recommended default.** Best balance of size, speed, quality
- `Q5_K_M` — ~15% larger than Q4, marginal quality gain, usually not worth it on CPU
- `Q8_0` — Near fp16 quality, nearly 2x the RAM of Q4. Only viable for 3B–4B models on your setup

**Context window warning:**
- Models advertise 128k context but **each additional token in context costs RAM and dramatically slows inference** on CPU
- Realistically keep context under **4k–8k** tokens for usable speed on a NUC

**Memory bandwidth is your real ceiling:**
- A typical NUC has DDR4-3200 (~51 GB/s) or DDR5-4800 (~76 GB/s)
- Tokens/sec scales almost linearly with bandwidth — this is why a 3B model at Q4 is 3x faster than an 8B at Q4, not just proportionally faster

---

## My Recommendations by Use Case

| Use Case | Recommended Model |
|---|---|
| General chat / assistant | `llama3.1:8b` |
| Coding assistant | `qwen2.5-coder:7b` |
| Fast responses, low latency | `phi4-mini:3.8b` |
| Best quality (patient user) | `gemma3:12b` |
| Multilingual tasks | `qwen2.5:7b` |
| Lightweight + smart | `phi4-mini:3.8b` |

---

# Ollama Model & Quantization Guide: 16GB RAM, CPU-Only NUC

## The Hard Constraints

- **Usable RAM for model:** ~12–13GB after OS overhead
- **Inference backend:** CPU only (llama.cpp under the hood)
- **Bottleneck:** Memory bandwidth, not compute
- **Key insight:** Quantization is your primary tuning lever on this hardware

---

## Quantization Deep Dive

### What Quantization Actually Does

Quantization reduces the bit-width used to store each model weight:

| Format | Bits per weight | Description |
|---|---|---|
| `fp16` | 16 bits | Full precision, baseline quality |
| `Q8_0` | 8 bits | ~1% quality loss vs fp16 |
| `Q6_K` | 6 bits | ~1–2% quality loss |
| `Q5_K_M` | 5 bits | ~2–3% quality loss |
| `Q4_K_M` | 4 bits | ~3–5% quality loss — **sweet spot** |
| `Q4_K_S` | 4 bits | Slightly smaller/faster than K_M, slightly lower quality |
| `Q3_K_M` | 3 bits | ~8–10% quality loss, getting noticeable |
| `Q2_K` | 2 bits | Significant degradation, last resort |

### The `_K` and `_M` / `_S` Suffixes Explained

These are **k-quant** variants from llama.cpp — they're smarter than naive quantization:

- **`_K`** — Uses a mixed strategy: quantizes weights in blocks, stores block scales at higher precision. Preserves more information than naive rounding
- **`_M` (Medium)** — Some layers kept at higher precision (attention layers, embeddings). Better quality than `_S`
- **`_S` (Small)** — More aggressive compression across all layers. Smaller file, slightly worse quality
- **`_L` (Large)** — Fewer layers compressed, highest quality in the K family

> **Rule of thumb:** Always prefer `Q4_K_M` over `Q4_0` — same size, meaningfully better quality due to the k-quant block scaling

---

## RAM Usage by Model + Quantization

### Llama 3.1 8B

| Quant | RAM Usage | Tokens/sec (est.) | Quality vs fp16 | Fits? |
|---|---|---|---|---|
| `fp16` | ~16.0 GB | 3–5 tok/s | Baseline | ⚠️ Barely / OOM risk |
| `Q8_0` | ~8.5 GB | 6–9 tok/s | ~99% | ✅ |
| `Q6_K` | ~6.6 GB | 8–12 tok/s | ~98% | ✅ |
| `Q5_K_M` | ~5.7 GB | 9–13 tok/s | ~97% | ✅ |
| `Q4_K_M` | ~4.9 GB | 10–15 tok/s | ~95% | ✅ **Recommended** |
| `Q4_K_S` | ~4.6 GB | 11–16 tok/s | ~94% | ✅ |
| `Q3_K_M` | ~3.9 GB | 13–18 tok/s | ~90% | ✅ |
| `Q2_K` | ~2.9 GB | 18–25 tok/s | ~80% | ✅ Avoid |

### Gemma 3 12B

| Quant | RAM Usage | Tokens/sec (est.) | Quality vs fp16 | Fits? |
|---|---|---|---|---|
| `fp16` | ~24.0 GB | — | Baseline | ❌ |
| `Q8_0` | ~12.8 GB | 4–6 tok/s | ~99% | ⚠️ Very tight |
| `Q6_K` | ~9.9 GB | 5–8 tok/s | ~98% | ✅ |
| `Q5_K_M` | ~8.6 GB | 6–9 tok/s | ~97% | ✅ |
| `Q4_K_M` | ~7.8 GB | 7–10 tok/s | ~95% | ✅ **Recommended** |
| `Q4_K_S` | ~7.4 GB | 8–11 tok/s | ~94% | ✅ |
| `Q3_K_M` | ~6.2 GB | 9–13 tok/s | ~90% | ✅ |
| `Q2_K` | ~4.8 GB | 13–18 tok/s | ~78% | ✅ Avoid |

### Phi-4 Mini 3.8B

| Quant | RAM Usage | Tokens/sec (est.) | Quality vs fp16 | Fits? |
|---|---|---|---|---|
| `fp16` | ~7.6 GB | 8–12 tok/s | Baseline | ✅ |
| `Q8_0` | ~4.1 GB | 15–22 tok/s | ~99% | ✅ |
| `Q6_K` | ~3.2 GB | 18–28 tok/s | ~98% | ✅ |
| `Q5_K_M` | ~2.8 GB | 20–32 tok/s | ~97% | ✅ |
| `Q4_K_M` | ~2.5 GB | 22–35 tok/s | ~95% | ✅ **Recommended** |
| `Q3_K_M` | ~2.0 GB | 28–42 tok/s | ~91% | ✅ |
| `Q2_K` | ~1.5 GB | 35–50 tok/s | ~82% | ✅ Avoid |

### Qwen 2.5 Coder 7B

| Quant | RAM Usage | Tokens/sec (est.) | Quality vs fp16 | Fits? |
|---|---|---|---|---|
| `fp16` | ~14.0 GB | 4–6 tok/s | Baseline | ⚠️ Tight |
| `Q8_0` | ~7.5 GB | 8–12 tok/s | ~99% | ✅ |
| `Q6_K` | ~5.8 GB | 10–15 tok/s | ~98% | ✅ |
| `Q5_K_M` | ~5.1 GB | 11–16 tok/s | ~97% | ✅ |
| `Q4_K_M` | ~4.4 GB | 12–18 tok/s | ~95% | ✅ **Recommended** |
| `Q3_K_M` | ~3.5 GB | 15–22 tok/s | ~91% | ✅ |
| `Q2_K` | ~2.7 GB | 20–30 tok/s | ~79% | ✅ Avoid |

### Llama 3.2 3B

| Quant | RAM Usage | Tokens/sec (est.) | Quality vs fp16 | Fits? |
|---|---|---|---|---|
| `fp16` | ~6.0 GB | 12–18 tok/s | Baseline | ✅ |
| `Q8_0` | ~3.2 GB | 22–35 tok/s | ~99% | ✅ |
| `Q6_K` | ~2.5 GB | 28–42 tok/s | ~98% | ✅ |
| `Q4_K_M` | ~2.0 GB | 32–50 tok/s | ~95% | ✅ **Recommended** |
| `Q3_K_M` | ~1.6 GB | 38–58 tok/s | ~91% | ✅ |
| `Q2_K` | ~1.2 GB | 48–70 tok/s | ~81% | ✅ Avoid |

---

## Quantization vs. Context Window: The Hidden RAM Cost

This is **critical and often overlooked.** The KV cache (key-value attention cache) consumes RAM that scales with context length:

$$\text{KV Cache RAM} = 2 \times \text{layers} \times \text{heads} \times \text{head\_dim} \times \text{context\_len} \times \text{bytes\_per\_element}$$

### Practical KV Cache RAM at fp16 (Ollama default)

| Model | 2k ctx | 4k ctx | 8k ctx | 16k ctx | 32k ctx |
|---|---|---|---|---|---|
| Llama 3.2 3B | ~0.1 GB | ~0.2 GB | ~0.4 GB | ~0.8 GB | ~1.6 GB |
| Llama 3.1 8B | ~0.3 GB | ~0.5 GB | ~1.0 GB | ~2.1 GB | ~4.2 GB |
| Qwen 2.5 7B | ~0.2 GB | ~0.4 GB | ~0.8 GB | ~1.6 GB | ~3.2 GB |
| Gemma 3 12B | ~0.4 GB | ~0.8 GB | ~1.6 GB | ~3.2 GB | ~6.4 GB |

> ⚠️ **Real example:** Llama 3.1 8B at Q4_K_M (~4.9 GB) + 32k context KV cache (~4.2 GB) = **~9.1 GB total** — still fine, but 128k context would be ~16 GB on its own, which is a hard no

### Controlling Context in Ollama

```bash
# Set context window at runtime
ollama run llama3.1:8b --ctx-size 4096

# Or in a Modelfile
FROM llama3.1:8b
PARAMETER num_ctx 4096
```

---

## Ollama-Specific Quantization: How to Pull Specific Quants

Ollama hosts multiple quantization variants on their registry. The tag format is:

```bash
# Default pull (usually Q4_K_M)
ollama pull llama3.1:8b

# Explicit quantization tags
ollama pull llama3.1:8b-instruct-q4_K_M
ollama pull llama3.1:8b-instruct-q5_K_M
ollama pull llama3.1:8b-instruct-q8_0
ollama pull llama3.1:8b-instruct-fp16

# List all available tags for a model
# Check https://ollama.com/library/llama3.1/tags
```

### Check What You Have Locally

```bash
# List models and their sizes on disk
ollama list

# Inspect a model's metadata including quantization
ollama show llama3.1:8b --modelinfo
```

### Using a Custom GGUF (e.g., from HuggingFace)

If Ollama doesn't carry the exact quant you want, you can import a GGUF directly:

```bash
# Create a Modelfile pointing to your GGUF
cat > Modelfile <<EOF
FROM /path/to/your/model-q5_k_m.gguf
PARAMETER num_ctx 4096
EOF

ollama create mymodel:q5km -f Modelfile
ollama run mymodel:q5km
```

---

## Ollama Runtime Tuning Parameters

These go in your `Modelfile` or as `--parameter` flags and directly affect performance on your NUC:

```bash
FROM llama3.1:8b-instruct-q4_K_M

# Context window — keep low for speed
PARAMETER num_ctx 4096

# CPU threads — set to your physical core count
PARAMETER num_thread 8

# Number of layers to offload to GPU (0 = CPU only on your NUC)
PARAMETER num_gpu 0

# Batch size for prompt processing — higher = faster prompt ingestion
PARAMETER num_batch 512

# Keep model in RAM between requests (critical for server use)
PARAMETER keep_alive -1
```

### Finding Your Physical Core Count

```bash
# Linux
lscpu | grep "Core(s) per socket"

# or
nproc --all
```

---

## Decision Matrix: Which Quant for Which Scenario?

| Scenario | Recommended Quant | Reasoning |
|---|---|---|
| Best quality, RAM available | `Q6_K` | Near fp16 quality, still fast |
| Daily driver balance | `Q4_K_M` | Sweet spot — **start here** |
| Speed critical (chat latency) | `Q4_K_S` or `Q3_K_M` | Faster at cost of some quality |
| RAM very tight (many services running) | `Q3_K_M` | Acceptable quality floor |
| Absolute last resort | `Q2_K` | Noticeable degradation, avoid |
| Small model (3B–4B), best quality | `Q8_0` | Small models have headroom |

---

## Final Recommendations for Your NUC

| Use Case | Model | Quant | Expected Speed | RAM Used |
|---|---|---|---|---|
| General chat | `llama3.1:8b` | `Q4_K_M` | 10–15 tok/s | ~4.9 GB |
| Coding | `qwen2.5-coder:7b` | `Q4_K_M` | 12–18 tok/s | ~4.4 GB |
| Fast / low latency | `phi4-mini:3.8b` | `Q4_K_M` | 22–35 tok/s | ~2.5 GB |
| Best quality possible | `gemma3:12b` | `Q4_K_M` | 7–10 tok/s | ~7.8 GB |
| Fast + smart tradeoff | `llama3.2:3b` | `Q6_K` | 28–42 tok/s | ~2.5 GB |
| Two models loaded at once | Any two 3B–4B | `Q4_K_M` | Varies | ~5–6 GB total |

---

##
##
