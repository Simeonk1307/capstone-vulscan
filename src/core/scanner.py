import onnxruntime as ort
import numpy as np
import os
import re
from transformers import DistilBertTokenizerFast


_KEYWORDS_TO_EXCLUDE = {'else', '#endif', '#else'}

_C_KEYWORDS = {
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
    'inline', 'int', 'long', 'register', 'restrict', 'return', 'short',
    'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef', 'union',
    'unsigned', 'void', 'volatile', 'while', '_Alignas', '_Alignof',
    '_Atomic', '_Bool', '_Complex', '_Generic', '_Imaginary', '_Noreturn',
    '_Static_assert', '_Thread_local'
}

_PREPROCESSOR_RE = re.compile(
    r'^#\s*(include|define|pragma|ifdef|ifndef|endif|undef|if|elif|else)'
)

_BENIGN_KEYWORD_RE = re.compile(
    r'^(?:' + '|'.join(_C_KEYWORDS) + r')\s*;$'
)

_COMMENT_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'"
    r'|(?P<block>/\*.*?\*/)' 
    r'|(?P<line>//.*)',
    re.DOTALL
)

_TARGET_EXTS = ('.c', '.cpp', '.h', '.hpp', '.cc', '.ino')


def _remove_comments(content):
    def replacer(m):
        if m.group('block'):
            return '\n' * m.group('block').count('\n')
        if m.group('line'):
            return ''
        return m.group(0)

    return _COMMENT_RE.sub(replacer, content)


def _is_benign(line):
    if len(line) <= 1:                                          return True
    if line in ('{', '}'):                                      return True
    if _PREPROCESSOR_RE.match(line):                            return True
    if any(kw in line.split() for kw in _KEYWORDS_TO_EXCLUDE): return True
    if _BENIGN_KEYWORD_RE.fullmatch(line):                      return True
    return False


def _extract_lines(content):
    for i, raw in enumerate(content.splitlines(), start=1):
        clean = raw.replace('\t', '').strip()
        if not _is_benign(clean):
            yield i, clean


def _normalize(text):
    return text.replace(' ', '').lower()


class ScanEngine:
    def __init__(self, model_path, tokenizer_path, classes_path):
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

        self.session   = ort.InferenceSession(model_path, sess_options=opts, providers=['CPUExecutionProvider'])
        self.tokenizer = DistilBertTokenizerFast.from_pretrained(tokenizer_path)
        self.classes   = np.load(classes_path, allow_pickle=True)

    def _process_file(self, file_path, cancel_flag=None):
        vuls = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            content = _remove_comments(content)
            lines   = list(_extract_lines(content))

            if not lines:
                return file_path, []

            line_nums  = [ln  for ln, _   in lines]
            orig_texts = [txt for _,  txt in lines]
            normed     = [_normalize(t) for t in orig_texts]

            for line_num, original, norm in zip(line_nums, orig_texts, normed):
                if cancel_flag and cancel_flag():
                    return file_path, vuls

                inputs = self.tokenizer(
                    norm,
                    padding='max_length',
                    truncation=True,
                    max_length=256,
                    return_tensors='np'
                )

                logits = self.session.run(None, {
                    'input_ids':      inputs['input_ids'].astype(np.int64),
                    'attention_mask': inputs['attention_mask'].astype(np.int64)
                })[0]

                label = self.classes[np.argmax(logits)]
                if label != '0':
                    vuls.append({'line': line_num, 'cwe': str(label), 'code': original})

        except Exception as e:
            raise RuntimeError(f"[ScanEngine] {os.path.basename(file_path)}: {e}") from e

        return file_path, vuls

    def scan_file(self, file_path, cancel_flag=None):
        return self._process_file(file_path, cancel_flag=cancel_flag)

    def scan_dir(self, dir_path, on_file=None, cancel_flag=None):
        """
        on_file(filename, current, total) — called before each file is scanned.
        cancel_flag()                     — return True to abort.
        """
        files = [
            os.path.join(root, f)
            for root, _, fs in os.walk(dir_path)
            for f in fs
            if f.lower().endswith(_TARGET_EXTS)
        ]

        results = {}
        total   = len(files)

        for i, f_path in enumerate(files):
            if cancel_flag and cancel_flag():
                break

            if on_file:
                on_file(os.path.basename(f_path), i + 1, total)

            _, vuls = self._process_file(f_path, cancel_flag=cancel_flag)
            if vuls:
                results[f_path] = vuls

        return results