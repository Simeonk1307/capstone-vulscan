import onnxruntime as ort
import numpy as np
import os
from transformers import DistilBertTokenizerFast

class ScanEngine:
    def __init__(self, model_path, tokenizer_path, classes_path):
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        # Execution on CPU is faster for small batch BERT models than GPU overhead
        self.session = ort.InferenceSession(model_path, sess_options=opts, providers=['CPUExecutionProvider'])
        self.tokenizer = DistilBertTokenizerFast.from_pretrained(tokenizer_path)
        self.classes = np.load(classes_path, allow_pickle=True)

    def _process_file(self, file_path):
        vuls = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Pre-filter lines to save AI cycles
                lines = [(i + 1, line.strip()) for i, line in enumerate(f) 
                         if len(line.strip()) > 4 and not line.strip().startswith(('#', '//', '/*', '*'))]
            
            if not lines: return file_path, []

            for line_num, clean_text in lines:
                inputs = self.tokenizer(clean_text, padding='max_length', truncation=True, 
                                        max_length=256, return_tensors="np")
                
                logits = self.session.run(None, {
                    "input_ids": inputs["input_ids"].astype(np.int64),
                    "attention_mask": inputs["attention_mask"].astype(np.int64)
                })[0]
                
                if self.classes[np.argmax(logits, axis=1)[0]] != '0':
                    vuls.append({"line": line_num, "cwe": self.classes[np.argmax(logits, axis=1)[0]], "code": clean_text})
        except Exception: pass
        return file_path, vuls

    def scan_project(self, dir_path, progress_callback=None):
        target_exts = ('.c', '.cpp', '.h', '.hpp', '.cc', '.ino')
        files = [os.path.join(r, f) for r, _, fs in os.walk(dir_path) for f in fs if f.lower().endswith(target_exts)]
        
        results = {}
        total = len(files)
        for i, f_path in enumerate(files):
            _, file_vuls = self._process_file(f_path)
            if file_vuls: results[f_path] = file_vuls
            if progress_callback: progress_callback((i + 1) / total)
        return results