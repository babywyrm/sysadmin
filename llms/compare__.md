
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

