# ML Model Artifact Inventory Iteration

Date: 2026-06-26
Branch: `feat/ml-model-artifact-inventory`
Base: `beta`

## Goal

Expand Rikune's static analysis breadth into AI/ML model artifacts while keeping the default gateway small and passive. The new capability should help analysts triage model supply-chain and loader risks before any framework load or runtime execution.

## Scope

- Add a built-in static plugin: `ml-model`
- Add one tool: `ml.model.inventory`
- Cover first-pass passive parsing for:
  - SafeTensors
  - GGUF/GGML
  - ONNX
  - TFLite
  - PyTorch/pickle checkpoints
  - NumPy NPY/NPZ
- Route file profiles through `SURFACE_FILE_TYPE_TAGS` and `workflow.search`.
- Update sample finalization, docs, Docker plugin allowlists, and tests.

## Safety Boundary

- No `pickle.load`, `torch.load`, or `numpy.load(... allow_pickle=True)`.
- No ONNX Runtime, TensorFlow, PyTorch, TFLite delegate, or inference runtime.
- No model hub or network access.
- No archive extraction to disk.
- No tensor payload parsing beyond bounded metadata and offset checks.
- No mutation of samples or generated artifacts other than the JSON inventory artifact.

## Primary References

- ONNX ModelProto and external data documentation.
- Hugging Face SafeTensors format and metadata parsing documentation.
- PyTorch `torch.load` warning and `weights_only` behavior documentation.
- GGUF specification from ggml/llama.cpp ecosystem.
- TensorFlow Lite FlatBuffer `TFL3` identifier.
- NumPy NPY/NPZ format documentation.

## Implementation Notes

- Tool-level runtime policy is intentionally omitted. The plugin is static/passive and should not make `workflow.search` mark it as runtime opt-in required.
- Runtime/model loading can be a future opt-in workflow, but not part of this iteration.
- The tool emits `evidence_summary`, `workflow_handoff`, and `quality_gates` to match recent inventory plugins.
