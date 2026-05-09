from pathlib import Path
import shutil
import sys
import numpy as np
import torch
from transformers import DistilBertConfig, DistilBertModel, DistilBertTokenizerFast

PROJECT_ROOT = Path(__file__).resolve().parent

MODELS_DIR   = PROJECT_ROOT / "src" / "models"
TOKENIZER_DIR = MODELS_DIR / "tokenizer_fast"

SEARCH_DIRS = [
    PROJECT_ROOT / "old_src" / "VulScan" / "vulscan_deliverables",
    PROJECT_ROOT,
]


def find_file(filename):
    for directory in SEARCH_DIRS:
        path = directory / filename
        if path.exists():
            return path

    print(f"Error: Could not find '{filename}'")
    print("\nSearched in:")
    for directory in SEARCH_DIRS:
        print(f" - {directory}")
    sys.exit(1)


CLASSES_SOURCE = find_file("classes.npy")
WEIGHTS_SOURCE = find_file("CWE_Model_1lyr_12hd_GPU2CPU.pt")

CLASSES_DEST = MODELS_DIR / "classes.npy"
ONNX_DEST    = MODELS_DIR / "model.onnx"


class DistillBERTClass(torch.nn.Module):
    def __init__(self, num_classes):
        super().__init__()

        config = DistilBertConfig(
            n_layers=1,
            n_heads=12,
            dim=768,
            hidden_dim=3072,
            dropout=0.3,
        )

        self.l1             = DistilBertModel(config)
        self.pre_classifier = torch.nn.Linear(768, 768)
        self.dropout        = torch.nn.Dropout(0.3)
        self.classifier     = torch.nn.Linear(768, num_classes)

    def forward(self, input_ids, attention_mask):
        hidden_state = self.l1(input_ids=input_ids, attention_mask=attention_mask)[0]
        pooler = hidden_state[:, 0]
        pooler = self.pre_classifier(pooler)
        pooler = torch.nn.ReLU()(pooler)
        pooler = self.dropout(pooler)
        return self.classifier(pooler)


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Using classes: {CLASSES_SOURCE}")
    print(f"Using weights: {WEIGHTS_SOURCE}")

    classes = np.load(CLASSES_SOURCE, allow_pickle=True)
    shutil.copy2(CLASSES_SOURCE, CLASSES_DEST)

    model = DistillBERTClass(len(classes))
    model.load_state_dict(torch.load(WEIGHTS_SOURCE, map_location="cpu"))
    model.eval()

    dummy_input = torch.ones(1, 256, dtype=torch.long)
    dummy_mask  = torch.ones(1, 256, dtype=torch.long)

    torch.onnx.export(
        model,
        (dummy_input, dummy_mask),
        str(ONNX_DEST),
        export_params=True,
        opset_version=14,          # bumped from 12 for better BERT op support
        do_constant_folding=True,
        input_names=["input_ids", "attention_mask"],
        output_names=["output"],
        dynamic_axes={
            "input_ids":      {0: "batch_size"},
            "attention_mask": {0: "batch_size"},
            "output":         {0: "batch_size"},
        },
    )

    # Save fast tokenizer to match DistilBertTokenizerFast in scanner
    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    tokenizer.save_pretrained(TOKENIZER_DIR)

    print("\nConversion complete")


if __name__ == "__main__":
    main()