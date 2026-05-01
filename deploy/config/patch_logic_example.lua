// Example patch_logic.lua for osoosi hex-patch (Rhai syntax - Lua/JS-like)
// Usage: osoosi hex-patch --script patch_logic.lua target_binary.exe
//
// Option 1: Define patches() returning array of #{offset, hex}
// fn patches() {
//   [
//     #{ offset: 0x1234, hex: "90 90" },
//     #{ offset: 0x5678, hex: "B8 01 00 00 00" }
//   ]
// }
//
// Option 2: Define apply() to patch in-place (buffer is global)
// fn apply() {
//   buffer.set_bytes(0x1234, "90 90");
//   let off = buffer.find("74 0E");
//   if off != () { buffer.set_bytes(off, "EB 0E"); }
// }

// This example: find-and-replace pattern (je -> jmp)
fn apply() {
  let offsets = buffer.find_all("74 0E");
  for off in offsets {
    buffer.set_bytes(off, "EB 0E");
  }
}
