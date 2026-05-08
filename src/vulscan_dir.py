# -*- coding: utf-8 -*-
"""
VulScan: A Deep Learning-based Vulnerability Scanning Tool for IoT OS source code files (C/C++).

This file operates over multiple files in a specified directory
"""

import numpy as np
import pandas as pd
import os
import sys
import torch
import re
from pathlib import Path
from transformers import DistilBertTokenizer, DistilBertModel, PretrainedConfig
from torch.utils.data import DataLoader, Dataset
from sklearn.preprocessing import LabelEncoder
from reportlab.pdfgen import canvas
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
import logging

logging.getLogger("transformers").setLevel(logging.ERROR)

# Fetch the device type (CPU/GPU)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Determine base_path for resources
try:
    base_path = sys.argv[2]
except IndexError:
    # Fallback to the directory where this script resides
    base_path = os.path.dirname(os.path.abspath(__file__))

def resource_path(relative_path):
    return os.path.join(base_path, relative_path)

def remove_comments(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='iso-8859-1') as file:
            content = file.read()

    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    content = re.sub(r'//.*', '', content)

    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

def extract_lines(input_file, output_file):
    keywords_to_exclude = {'else', '#endif', '#else'}
    c_keywords = [
        'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do', 'double',
        'else', 'enum', 'extern', 'float', 'for', 'goto', 'if', 'inline', 'int', 'long',
        'register', 'restrict', 'return', 'short', 'signed', 'sizeof', 'static', 'struct',
        'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile', 'while', '_Alignas',
        '_Alignof', '_Atomic', '_Bool', '_Complex', '_Generic', '_Imaginary', '_Noreturn',
        '_Static_assert', '_Thread_local'
    ]

    try:
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
            for line in infile:
                cleaned_line = line.replace('\t', '').strip()
                if cleaned_line == '' or cleaned_line in ('{', '}'):
                    continue
                if any(keyword in cleaned_line.split() for keyword in keywords_to_exclude):
                    continue
                if cleaned_line.startswith('#include'):
                    continue
                if any(re.match(rf'\b{keyword}\s*;', cleaned_line) for keyword in c_keywords):
                    continue
                outfile.write(cleaned_line + '\n')
    except Exception as e:
        print(f'An error occurred during extraction: {e}')

def remove_comments_from_files(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.c', '.cpp', '.h', '.nc')):
                remove_comments(os.path.join(root, file))

def extract_lines_from_files(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.c', '.cpp', '.h', '.nc')):
                file_path = os.path.join(root, file)
                output_filename = os.path.splitext(file_path)[0] + '.txt'
                extract_lines(file_path, output_filename)

# Global Config
dir_name = sys.argv[1]
remove_comments_from_files(dir_name)
extract_lines_from_files(dir_name)

print("Scanning for vulnerabilities...")

tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
batch_size = 32

class VulnerabilityDataset(Dataset):
    def __init__(self, texts):
        self.texts = texts

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        encoding = tokenizer(
            text,
            add_special_tokens=True,
            return_token_type_ids=False,
            padding="max_length",
            truncation=True,
            max_length=256,
            return_tensors="pt",
        )
        return {
            "input_ids": encoding["input_ids"].flatten(),
            "attention_mask": encoding["attention_mask"].flatten(),
        }

class DistilBertConfig(PretrainedConfig):
    model_type = "distilbert"
    attribute_map = {"hidden_size": "dim", "num_attention_heads": "n_heads", "num_hidden_layers": "n_layers"}
    def __init__(self, vocab_size=30522, max_position_embeddings=512, sinusoidal_pos_embds=False,
                 n_layers=1, n_heads=12, dim=768, hidden_dim=4 * 768, dropout=0.3,
                 attention_dropout=0.1, activation="gelu", initializer_range=0.02,
                 qa_dropout=0.1, seq_classif_dropout=0.2, pad_token_id=0, **kwargs):
        self.vocab_size = vocab_size
        self.max_position_embeddings = max_position_embeddings
        self.sinusoidal_pos_embds = sinusoidal_pos_embds
        self.n_layers = n_layers
        self.n_heads = n_heads
        self.dim = dim
        self.hidden_dim = hidden_dim
        self.dropout = dropout
        self.attention_dropout = attention_dropout
        self.activation = activation
        self.initializer_range = initializer_range
        self.qa_dropout = qa_dropout
        self.seq_classif_dropout = seq_classif_dropout
        super().__init__(**kwargs, pad_token_id=pad_token_id)

# Initialize Model
configuration = DistilBertConfig()
base_model = DistilBertModel(configuration)

classes_path = resource_path('classes.npy')
le = LabelEncoder()
le.classes_ = np.load(classes_path, allow_pickle=True)

class DistillBERTClass(torch.nn.Module):
    def __init__(self):
        super(DistillBERTClass, self).__init__()
        self.l1 = base_model
        self.pre_classifier = torch.nn.Linear(768, 768)
        self.dropout = torch.nn.Dropout(0.3)
        self.classifier = torch.nn.Linear(768, le.classes_.size)

    def forward(self, input_ids, attention_mask):
        output_1 = self.l1(input_ids=input_ids, attention_mask=attention_mask)
        hidden_state = output_1[0]
        pooler = hidden_state[:, 0]
        pooler = self.pre_classifier(pooler)
        pooler = torch.nn.ReLU()(pooler)
        pooler = self.dropout(pooler)
        output = self.classifier(pooler)
        return output

output_model_file = resource_path('CWE_Model_1lyr_12hd_GPU2CPU.pt')
loaded_model = DistillBERTClass()
loaded_model.to(device)

if torch.cuda.is_available():
    loaded_model.load_state_dict(torch.load(output_model_file))
else:
    loaded_model.load_state_dict(torch.load(output_model_file, map_location=device))
loaded_model.eval()

def valid(model, testing_loader, current_df):
    model.eval()
    vuls = {}
    with torch.no_grad():
        for _, data in enumerate(testing_loader, 0):
            ids = data['input_ids'].to(device, dtype=torch.long)
            mask = data['attention_mask'].to(device, dtype=torch.long)
            outputs = model(ids, mask)
            _, big_idx = torch.max(outputs.data, dim=1)

            pred_out = big_idx.detach().cpu().numpy()
            decoded_labels = le.inverse_transform(pred_out)
            ids_list = ids.tolist()
            texts = [tokenizer.decode(seq, skip_special_tokens=True, clean_up_tokenization_spaces=True) for seq in ids_list]

            for index in range(len(pred_out)):
                if decoded_labels[index] != '0':
                    clean_text = texts[index].replace(' ', '')
                    idx_matches = current_df[current_df['code'] == clean_text].index
                    line_num = str(idx_matches[0] + 1) if not idx_matches.empty else "N/A"
                    vuls[decoded_labels[index]] = f"Line {line_num}: {texts[index]}"
    return vuls

def generate_vuln_report(vuls, report_dir, input_name, txt_file_path):
    url = "https://cwe.mitre.org/data/definitions/"
    fileName = os.path.join(report_dir, f'vulscan_report_{input_name}.pdf')
    
    pdf = canvas.Canvas(fileName, pagesize=A4)
    width, height = A4
    max_width = width - 80

    # Font handling
    current_font = "Helvetica-Bold"
    try:
        font_path = resource_path('SakBunderan.ttf')
        pdfmetrics.registerFont(TTFont('abc', font_path))
        pdf.setFont('abc', 34)
        current_font = 'abc'
    except:
        pdf.setFont(current_font, 34)

    title = 'VulScan Vulnerability Results'
    title_width = pdf.stringWidth(title, current_font, 34)
    pdf.drawString((width - title_width) / 2, height - 80, title)

    # Subtitle
    pdf.setFillColor(colors.blue)
    pdf.setFont("Courier", 12)
    pdf.drawString(40, height - 120, f"File Name: {input_name}.c")
    
    pdf.setStrokeColor(colors.black)
    pdf.line(40, height - 130, width - 40, height - 130)

    text_y = height - 150
    pdf.setFillColor(colors.black)
    
    if not vuls:
        pdf.drawString(40, text_y, "No vulnerabilities detected.")
    else:
        intro = "Vulnerable lines identified. Red lines refer to the formatted reference below."
        pdf.drawString(40, text_y, intro)
        text_y -= 30

        for cwe, line_info in vuls.items():
            if text_y < 100:
                pdf.showPage()
                text_y = height - 50
            
            pdf.setFont("Courier-Bold", 12)
            pdf.drawString(40, text_y, f"CWE: {cwe}")
            text_y -= 15
            pdf.setFont("Courier", 12)
            pdf.setFillColor(colors.red)
            pdf.drawString(40, text_y, line_info[:80])
            pdf.setFillColor(colors.black)
            text_y -= 25

    pdf.showPage()
    # Reference Page
    pdf.setFont("Courier", 10)
    text_y = height - 50
    pdf.drawString(40, text_y, "Formatted Code Reference:")
    text_y -= 20
    
    if os.path.exists(txt_file_path):
        with open(txt_file_path, 'r') as f:
            for i, line in enumerate(f, 1):
                if text_y < 50:
                    pdf.showPage()
                    text_y = height - 50
                pdf.drawString(40, text_y, f"{i}. {line.strip()[:90]}")
                text_y -= 12

    pdf.save()
    return True

# Main Execution Loop
status = False
for root, _, files in os.walk(dir_name):
    for file in files:
        if file.endswith('.txt'):
            file_path = os.path.join(root, file)
            
            # Vectorized cleaning to avoid ChainedAssignmentError
            df = pd.read_table(file_path, names=['code'])
            df['code'] = df['code'].astype(str).str.replace(' ', '', regex=False).str.lower()
            
            testing_set = VulnerabilityDataset(df["code"])
            test_loader = DataLoader(testing_set, batch_size=batch_size, shuffle=False)

            found_vuls = valid(loaded_model, test_loader, df)
            
            # Use original dir for report placement
            report_status = generate_vuln_report(found_vuls, dir_name, Path(file).stem, file_path)
            if report_status:
                status = True

if status:
    print(f"Vulnerability reports generated in directory: {dir_name}")