use crate::state::AppState;
use tauri::State;

#[tauri::command]
pub fn merge_mesh_crdt_state(
    incoming_value: String,
    incoming_node_id: String,
    incoming_timestamp: u64,
    state: State<'_, std::sync::Arc<AppState>>,
) -> Result<bool, String> {
    let remote_crdt = core_crypto::crypto::LwwRegisterCRDT::new(
        incoming_value,
        incoming_node_id.clone(),
        incoming_timestamp,
    );

    let updated = state.merge_mesh_crdt(remote_crdt);
    if updated {
        state.add_log(format!("[CRDT Mesh] Converged state from node {incoming_node_id} (timestamp = {incoming_timestamp})"));
    }
    Ok(updated)
}
