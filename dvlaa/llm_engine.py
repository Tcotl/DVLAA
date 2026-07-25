"""DVLAA 本地 Transformers 推理引擎。"""

import logging
import threading
import os
import time
from pathlib import Path
import torch
from transformers import (
    AutoConfig,
    AutoModelForCausalLM,
    AutoModelForImageTextToText,
    AutoProcessor,
    AutoTokenizer,
)

logger = logging.getLogger(__name__)

os.environ.setdefault("HF_ENDPOINT", "https://hf-mirror.com")

try:
    _torch_threads = int(os.environ.get("DVLAA_TORCH_THREADS") or os.environ.get("OMP_NUM_THREADS") or "4")
    if _torch_threads > 0:
        torch.set_num_threads(_torch_threads)
        try:
            torch.set_num_interop_threads(max(1, min(2, _torch_threads)))
        except RuntimeError:
            pass
        logger.info("[DVLAA] PyTorch CPU threads: %s", _torch_threads)
except Exception as exc:
    logger.debug("[DVLAA] PyTorch thread tuning skipped: %s", exc)

try:
    import accelerate as _accelerate
    _ACCELERATE_AVAILABLE = True
except ImportError:
    _ACCELERATE_AVAILABLE = False


class LLMEngine:
    """按本地模型目录实例化的推理引擎。"""

    def __init__(self, model_name: str = "/app/qwen-model", device: str = "cpu"):
        # 兼容本地路径
        if not os.path.exists(model_name) and os.path.exists("./qwen-model"):
            model_name = "./qwen-model"
        self.model_name = model_name
        self.device = device
        self.model = None
        self.tokenizer = None
        self.processor = None
        self.is_image_text_model = False
        self._load_lock = threading.Lock()

    def load(self):
        """加载模型 (bfloat16/float32 优化)"""
        if self.model is not None:
            return
        with self._load_lock:
            if self.model is not None:
                return
            started = time.perf_counter()
            logger.info(f"[DVLAA] Loading {self.model_name} on {self.device}...")
            config = AutoConfig.from_pretrained(self.model_name, trust_remote_code=False)
            self.is_image_text_model = config.model_type in {"qwen3_5", "qwen3_5_moe", "mistral3"}
            if self.is_image_text_model:
                self.processor = AutoProcessor.from_pretrained(
                    self.model_name, trust_remote_code=False
                )
                self.tokenizer = self.processor.tokenizer
                model_class = AutoModelForImageTextToText
            else:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    self.model_name, trust_remote_code=False
                )
                model_class = AutoModelForCausalLM
            
            # ARM64 原生支持 bfloat16 加速与低内存占用
            dtype = torch.bfloat16 if hasattr(torch, "bfloat16") else torch.float32
            load_kwargs = {
                "trust_remote_code": False,
                "torch_dtype": dtype,
            }
            if _ACCELERATE_AVAILABLE:
                load_kwargs["low_cpu_mem_usage"] = True

            try:
                self.model = model_class.from_pretrained(
                    self.model_name, **load_kwargs
                )
            except Exception:
                # 回退 float32
                load_kwargs["torch_dtype"] = torch.float32
                self.model = model_class.from_pretrained(
                    self.model_name, **load_kwargs
                )

            self.model.to(self.device)
            self.model.eval()
            logger.info(
                "[DVLAA] Local model loaded successfully in memory-optimized mode (%.2fs).",
                time.perf_counter() - started,
            )

    def _prepare_inputs(self, messages: list):
        template_handler = self.processor if self.is_image_text_model else self.tokenizer
        text = template_handler.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        if self.is_image_text_model:
            return self.processor(text=[text], return_tensors="pt", padding=True).to(self.device)
        return self.tokenizer(text, return_tensors="pt").to(self.device)

    def _decode_response(self, outputs, input_len: int) -> str:
        generated_ids = outputs[0][input_len:]
        decoder = self.processor if self.is_image_text_model else self.tokenizer
        return decoder.decode(generated_ids, skip_special_tokens=True).strip()

    def generate(self, prompt: str, max_new_tokens: int = 120, temperature: float = 0.7,
                 top_p: float = 0.9, do_sample: bool = True) -> str:
        if self.model is None:
            self.load()

        messages = self._parse_prompt_to_messages(prompt)
        inputs = self._prepare_inputs(messages)

        started = time.perf_counter()
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                top_p=top_p,
                do_sample=do_sample,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        input_len = inputs.input_ids.shape[1]
        generated = max(0, outputs.shape[1] - input_len)
        elapsed = time.perf_counter() - started
        if elapsed >= 2:
            logger.info(
                "[DVLAA] generate: input_tokens=%s output_tokens=%s time=%.2fs speed=%.2f tok/s",
                input_len, generated, elapsed, generated / elapsed if elapsed else 0.0,
            )
        return self._decode_response(outputs, input_len)

    def generate_chat(self, system_prompt: str, user_input: str,
                      history: list = None, max_new_tokens: int = 150,
                      temperature: float = 0.7) -> str:
        if self.model is None:
            self.load()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        if history:
            for msg in history:
                messages.append({"role": msg["role"], "content": msg["content"]})

        messages.append({"role": "user", "content": user_input})

        inputs = self._prepare_inputs(messages)

        started = time.perf_counter()
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                top_p=0.9,
                do_sample=(temperature > 0),
                pad_token_id=self.tokenizer.eos_token_id,
            )

        input_len = inputs.input_ids.shape[1]
        generated = max(0, outputs.shape[1] - input_len)
        elapsed = time.perf_counter() - started
        if elapsed >= 2:
            logger.info(
                "[DVLAA] chat: input_tokens=%s output_tokens=%s time=%.2fs speed=%.2f tok/s",
                input_len, generated, elapsed, generated / elapsed if elapsed else 0.0,
            )
        return self._decode_response(outputs, input_len)

    def _parse_prompt_to_messages(self, prompt: str) -> list:
        messages = []
        lines = prompt.strip().split("\n")
        current_role = "user"
        current_content = []

        for line in lines:
            if line.startswith("System:") or line.startswith("system:"):
                if current_content:
                    messages.append({"role": current_role, "content": "\n".join(current_content).strip()})
                    current_content = []
                current_role = "system"
                current_content.append(line.split(":", 1)[1].strip())
            elif line.startswith("User:") or line.startswith("user:"):
                if current_content:
                    messages.append({"role": current_role, "content": "\n".join(current_content).strip()})
                    current_content = []
                current_role = "user"
                current_content.append(line.split(":", 1)[1].strip())
            elif line.startswith("Assistant:") or line.startswith("assistant:"):
                if current_content:
                    messages.append({"role": current_role, "content": "\n".join(current_content).strip()})
                    current_content = []
                current_role = "assistant"
                current_content.append(line.split(":", 1)[1].strip())
            else:
                current_content.append(line)

        if current_content:
            messages.append({"role": current_role, "content": "\n".join(current_content).strip()})

        if not messages:
            messages = [{"role": "user", "content": prompt}]

        return messages

_engine_cache = {}
_engine_cache_lock = threading.Lock()

def get_engine(model_name: str = "/app/qwen-model", device: str = "cpu"):
    cache_key = (str(Path(model_name).resolve()), device)
    with _engine_cache_lock:
        engine = _engine_cache.get(cache_key)
        if engine is None:
            engine = LLMEngine(model_name=model_name, device=device)
            _engine_cache[cache_key] = engine
    engine.load()
    return engine
