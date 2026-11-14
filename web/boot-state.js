const DISCONNECTED = "Boot not confirmed. Connect serial after install.";

export function createBootState() {
  let connected = false;
  let replaying = true;
  let selectedBoard = "";

  return {
    connect(board) {
      connected = true;
      replaying = true;
      selectedBoard = board;
      return "Saved events are history. Reset the device after replay to confirm this boot.";
    },
    replayComplete() {
      replaying = false;
      return "Saved events loaded. Press the device reset button to confirm a live boot.";
    },
    event(event) {
      if (!connected || replaying || event.event !== "boot") return null;
      return event.board === selectedBoard
        ? `Boot confirmed: ${event.board}, firmware ${event.firmware}`
        : `Board mismatch: selected ${selectedBoard}, device reports ${event.board}`;
    },
    boardChanged(board) {
      selectedBoard = board;
      return connected
        ? "Boot not confirmed for the selected board. Reset the device after replay."
        : DISCONNECTED;
    },
    disconnect() {
      connected = false;
      replaying = true;
      return DISCONNECTED;
    }
  };
}
