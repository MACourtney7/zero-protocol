//! WASM bindings for `MeshTopology` exposing multi-peer state broadcast, direct transmission,
//! and chat signaling to JavaScript.

use wasm_bindgen::prelude::*;

use crate::mesh::MeshTopology;
use crate::webrtc::WasmWebRtcEngine;

/// JS-exported WASM wrapper for `MeshTopology`.
#[wasm_bindgen]
pub struct WasmMeshTopology {
    topology: MeshTopology,
}

#[wasm_bindgen]
impl WasmMeshTopology {
    /// Creates a new `WasmMeshTopology` instance with local peer ID and 32-byte X25519 private key.
    #[wasm_bindgen(constructor)]
    pub fn new(local_peer_id: &str, local_private_key: &[u8]) -> Result<WasmMeshTopology, JsValue> {
        if local_private_key.len() != 32 {
            return Err(JsValue::from_str(
                "Invalid private key length: expected 32 bytes",
            ));
        }
        let mut priv_arr = [0u8; 32];
        priv_arr.copy_from_slice(local_private_key);
        Ok(Self {
            topology: MeshTopology::new(local_peer_id, priv_arr),
        })
    }

    /// Returns the local peer identifier.
    pub fn local_peer_id(&self) -> String {
        self.topology.local_peer_id()
    }

    /// Returns the 32-byte local public key.
    pub fn local_public_key(&self) -> Vec<u8> {
        self.topology.local_public_key().to_vec()
    }

    /// Registers a peer with its public key and `WasmWebRtcEngine` instance.
    pub fn register_peer(
        &self,
        peer_id: &str,
        public_key: &[u8],
        engine: &WasmWebRtcEngine,
    ) -> Result<(), JsValue> {
        if public_key.len() != 32 {
            return Err(JsValue::from_str(
                "Invalid public key length: expected 32 bytes",
            ));
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(public_key);
        self.topology
            .register_peer(peer_id, pk_arr, engine.peer())
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the count of connected peers.
    pub fn peer_count(&self) -> usize {
        self.topology.peer_count()
    }

    /// Returns whether a peer exists in the mesh.
    pub fn has_peer(&self, peer_id: &str) -> bool {
        self.topology.has_peer(peer_id)
    }

    /// Removes a peer from the mesh topology and closes its channel.
    pub fn remove_peer(&self, peer_id: &str) -> Result<(), JsValue> {
        self.topology
            .remove_peer(peer_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Disconnects a peer from the mesh topology and closes its channel.
    pub fn disconnect_peer(&self, peer_id: &str) -> Result<(), JsValue> {
        self.topology
            .disconnect_peer(peer_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Broadcasts a chat message across all connected peers.
    pub fn broadcast_chat(&self, plaintext: &str) -> Result<String, JsValue> {
        self.topology
            .broadcast_chat(plaintext)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Broadcasts application state or binary event payload across all connected peers.
    pub fn broadcast_state(&self, topic: &str, payload: &[u8], ttl: u8) -> Result<String, JsValue> {
        self.topology
            .broadcast_state(topic, payload, ttl)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Transmits application state or binary event payload directly to a target peer.
    pub fn send_direct_state(
        &self,
        target_peer_id: &str,
        topic: &str,
        payload: &[u8],
    ) -> Result<String, JsValue> {
        self.topology
            .send_direct_state(target_peer_id, topic, payload)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Registers a callback `(sender_id: string, text: string) => void` for incoming chat messages.
    pub fn set_on_message(&self, callback: js_sys::Function) {
        self.topology.on_message(move |sender_id, text| {
            let _ = callback.call2(
                &JsValue::NULL,
                &JsValue::from_str(sender_id),
                &JsValue::from_str(text),
            );
        });
    }

    /// Registers a callback `(origin_peer_id: string, topic: string, payload: Uint8Array) => void`
    /// for incoming application state or binary payloads.
    pub fn set_on_state(&self, callback: js_sys::Function) {
        self.topology
            .on_state(move |origin_peer_id, topic, payload| {
                let uint8 = js_sys::Uint8Array::from(payload);
                let _ = callback.call3(
                    &JsValue::NULL,
                    &JsValue::from_str(origin_peer_id),
                    &JsValue::from_str(topic),
                    &JsValue::from(uint8),
                );
            });
    }

    /// Registers a callback `(peer_id: string) => void` for peer join events.
    pub fn set_on_peer_joined(&self, callback: js_sys::Function) {
        self.topology.on_peer_joined(move |peer_id| {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(peer_id));
        });
    }

    /// Registers a callback `(peer_id: string) => void` for peer departure events.
    pub fn set_on_peer_left(&self, callback: js_sys::Function) {
        self.topology.on_peer_left(move |peer_id| {
            let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(peer_id));
        });
    }

    /// Broadcasts leave and burn signal across all peers.
    pub fn broadcast_leave_and_burn(&self) -> Result<(), JsValue> {
        self.topology
            .broadcast_leave_and_burn()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Broadcasts global burn session across all peers.
    pub fn broadcast_global_burn(&self) -> Result<(), JsValue> {
        self.topology
            .broadcast_global_burn()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
