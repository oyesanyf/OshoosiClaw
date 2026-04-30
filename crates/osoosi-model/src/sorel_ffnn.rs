use candle_core::{DType, Device, Result, Tensor};
use candle_nn::{Linear, Module, VarBuilder};

pub struct SorelFFNN {
    layers: Vec<Linear>,
}

impl SorelFFNN {
    pub fn new(vb: VarBuilder) -> Result<Self> {
        let mut layers = Vec::new();
        // SOREL-20M FFNN has 5 layers of 512 units
        // Note: The actual layer names in the .pt file might be "layers.0", "layers.2", etc.
        // since Sequential adds them with indices.
        
        let hidden_size = 512;
        let input_size = 2381;
        
        // Layer 0: Linear(2381, 512)
        layers.push(candle_nn::linear(input_size, hidden_size, vb.pp("layers.0"))?);
        // Layer 1: ReLU (not a parameter layer)
        // Layer 2: Linear(512, 512)
        layers.push(candle_nn::linear(hidden_size, hidden_size, vb.pp("layers.2"))?);
        // Layer 4: Linear(512, 512)
        layers.push(candle_nn::linear(hidden_size, hidden_size, vb.pp("layers.4"))?);
        // Layer 6: Linear(512, 512)
        layers.push(candle_nn::linear(hidden_size, hidden_size, vb.pp("layers.6"))?);
        // Layer 8: Linear(512, 512)
        layers.push(candle_nn::linear(hidden_size, hidden_size, vb.pp("layers.8"))?);
        // Layer 10: Linear(512, 1)
        layers.push(candle_nn::linear(hidden_size, 1, vb.pp("layers.10"))?);

        Ok(Self { layers })
    }

    pub fn load<P: AsRef<std::path::Path>>(path: P, device: &Device) -> anyhow::Result<Self> {
        let tensors = candle_core::pickle::read_all(path)?;
        let mut map = std::collections::HashMap::new();
        for (name, tensor) in tensors {
            map.insert(name, tensor.to_device(device)?);
        }
        let vb = VarBuilder::from_tensors(map, DType::F32, device);
        Ok(Self::new(vb)?)
    }
}

impl Module for SorelFFNN {
    fn forward(&self, xs: &Tensor) -> Result<Tensor> {
        let mut x = xs.clone();
        for (i, layer) in self.layers.iter().enumerate() {
            x = layer.forward(&x)?;
            if i < self.layers.len() - 1 {
                x = x.relu()?;
            }
        }
        // Final output is a single logit. Apply sigmoid for probability.
        Ok(x)
    }
}
