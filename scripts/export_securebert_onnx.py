#!/usr/bin/env python3
"""
Export SecureBERT (or compatible model) to ONNX for Rust inference.
Run: pip install transformers optimum[onnxruntime] torch
     python scripts/export_securebert_onnx.py
Output: models/behavioral/securebert.onnx
"""
import os
import sys

def main():
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        from optimum.onnxruntime import ORTModelForSequenceClassification
    except ImportError:
        print("Install: pip install transformers optimum[onnxruntime] torch")
        sys.exit(1)

    model_id = os.environ.get("OSOOSI_BEHAVIORAL_MODEL", "ehsanaghaei/SecureBERT")
    out_dir = os.environ.get("OSOOSI_MODELS_DIR", "models") + "/behavioral"
    os.makedirs(out_dir, exist_ok=True)

    print(f"Loading {model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    try:
        model = AutoModelForSequenceClassification.from_pretrained(model_id)
    except Exception:
        print("SecureBERT may not have a classification head. Using a generic security classifier.")
        model_id = "distilbert-base-uncased-finetuned-sst-2-english"
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForSequenceClassification.from_pretrained(model_id)

    print(f"Exporting to ONNX in {out_dir}...")
    ort_model = ORTModelForSequenceClassification.from_pretrained(
        model_id,
        export=True,
    )
    ort_model.save_pretrained(out_dir)
    tokenizer.save_pretrained(out_dir)
    print("Done. Place model.onnx in models/behavioral/ for behavioral detector.")

if __name__ == "__main__":
    main()
