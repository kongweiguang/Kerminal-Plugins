import { applyTheme, connect, PluginError } from "./sdk.js";

const note = document.querySelector("#note");
const save = document.querySelector("#save");
const confirm = document.querySelector("#confirm");
const recover = document.querySelector("#recover");
const status = document.querySelector("#status");
let client;
let dirty = false;
let writeUnknown = false;
let saving = false;

/** Transport and explicit host uncertainty both require readback; neither means that a write was rejected. */
function unknownWrite(error) {
  return error instanceof PluginError && ["receipt_unknown", "outcome_unknown", "transport", "view_closed"].includes(error.code);
}

/** Errors stay in a reserved inline region; a missing bridge never falls back to an untrusted localhost server. */
function showError(error) {
  status.textContent = unknownWrite(error)
    ? "The save result is unknown. Check the saved note before retrying."
    : error instanceof Error ? error.message : "The operation failed.";
}

/** A lost write acknowledgement disables repetition until state has been read back from the host. */
async function saveNote() {
  if (writeUnknown || saving) return;
  saving = true;
  save.disabled = true;
  const submitted = note.value;
  try {
    await client.saveState({ message: submitted });
    dirty = note.value !== submitted;
    save.disabled = !dirty;
    status.textContent = dirty ? "Previous note saved. You have newer changes." : "Note saved.";
  } catch (error) {
    writeUnknown = unknownWrite(error);
    recover.disabled = !writeUnknown;
    save.disabled = writeUnknown;
    showError(error);
  } finally { saving = false; }
}

/** Readback preserves the local draft and requires an explicit save if the stored state differs. */
async function checkSave() {
  recover.disabled = true;
  try {
    const state = await client.readState();
    writeUnknown = false;
    dirty = state?.message !== note.value;
    save.disabled = !dirty;
    status.textContent = dirty ? "The stored note differs. Your draft is preserved; review it before saving again." : "Your note was saved.";
  } catch (error) { recover.disabled = false; showError(error); }
}

/** Confirmation is delegated to the host so modal ownership and focus restoration remain native. */
async function showConfirmation() {
  confirm.disabled = true;
  try { const result = await client.confirm({ id: "demo-confirm", title: "Example confirmation", message: "The host owns this dialog. Continue?" }); status.textContent = result?.confirmed ? "Confirmed." : "Cancelled."; }
  catch (error) { showError(error); }
  finally { confirm.disabled = false; }
}

/** State and subscriptions belong to this instance; closing detaches UI listeners without claiming backend cancellation. */
async function initialize() {
  try {
    client = connect();
    client.on("theme", applyTheme);
    const state = await client.readState();
    note.value = typeof state?.message === "string" ? state.message : "";
    note.disabled = false;
    confirm.disabled = false;
    status.textContent = "";
    note.addEventListener("input", () => { dirty = true; save.disabled = writeUnknown || saving; });
    save.addEventListener("click", saveNote);
    recover.addEventListener("click", checkSave);
    confirm.addEventListener("click", showConfirmation);
    globalThis.addEventListener("pagehide", () => client.dispose(), { once: true });
    globalThis.addEventListener("beforeunload", event => { if (dirty) { event.preventDefault(); event.returnValue = ""; } });
  } catch (error) { showError(error); }
}

initialize();
