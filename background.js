// background.js
// Service worker "nhẹ": KHÔNG chạy nền liên tục. Chrome chỉ đánh thức file này
// khi có sự kiện (cài đặt extension, click context menu) rồi giải phóng bộ nhớ
// ngay sau đó. Không giữ biến toàn cục lâu dài — mọi dữ liệu cần truyền cho
// popup được lưu qua chrome.storage.session (bộ nhớ tạm, tự xóa khi đóng trình
// duyệt, không ghi ra đĩa).

const MENU_ID = 'ioc-radar-scan-selection';

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: 'Quét "%s" bằng IOC Radar',
    contexts: ['selection']
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== MENU_ID || !info.selectionText) return;
  await chrome.storage.session.set({ pendingIOC: info.selectionText.trim() });
  try {
    await chrome.action.openPopup();
  } catch (e) {
    // Nếu Chrome chặn openPopup ở ngữ cảnh này, dữ liệu vẫn nằm trong
    // storage.session và popup sẽ tự đọc khi người dùng bấm icon extension.
  }
});
