pub mod adapter;
pub mod context;
pub mod mining;
pub mod wasm;

use adapter::ExecutionAdapter;
use context::RuntimeContext;
use lattice_protocol::WorkloadKind;

pub fn select_adapter(ctx: &RuntimeContext) -> Result<ExecutionAdapter, String> {
    match &ctx.descriptor.workload_kind {
        WorkloadKind::Mining => {
            if ctx.descriptor.runtime_id == "xmrig" || ctx.descriptor.runtime_id == "lattice-miner"
            {
                Ok(ExecutionAdapter::Mining(mining::MiningAdapter::new()))
            } else {
                Err(format!(
                    "unsupported runtime '{}' for Mining workload",
                    ctx.descriptor.runtime_id
                ))
            }
        }
        WorkloadKind::Research | WorkloadKind::Generic => {
            if ctx.descriptor.runtime_id == "lattice-wasm" || ctx.descriptor.runtime_id == "wasm" {
                Ok(ExecutionAdapter::Wasm(wasm::WasmAdapter::new()))
            } else {
                Err(format!(
                    "unsupported runtime '{}' for kind {:?}",
                    ctx.descriptor.runtime_id, ctx.descriptor.workload_kind
                ))
            }
        }
        other => Err(format!(
            "no adapter available for workload kind {:?}",
            other
        )),
    }
}
