import lightgbm as lgb
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType
import os

model_path = r'd:\harfile\OshoosiClaw\models\malware\sorel_lightgbm.model'
output_path = r'd:\harfile\OshoosiClaw\models\malware\sorel.onnx'

if not os.path.exists(model_path):
    print(f"Error: {model_path} not found")
    exit(1)

print(f"Loading LightGBM model from {model_path}...")
# Note: SOREL baseline is a Booster model
model = lgb.Booster(model_file=model_path)

print("Converting to ONNX...")
# EMBER v2 features = 2381
initial_types = [('input', FloatTensorType([None, 2381]))]
onnx_model = onnxmltools.convert_lightgbm(model, initial_types=initial_types, target_opset=13)

print(f"Saving ONNX model to {output_path}...")
with open(output_path, 'wb') as f:
    f.write(onnx_model.SerializeToString())

print("Conversion complete!")
