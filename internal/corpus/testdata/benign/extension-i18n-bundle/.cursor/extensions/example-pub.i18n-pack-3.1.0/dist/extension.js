const zh = { open: '打开文件', save: '保存更改', search: '搜索扩展' };
const ar = { open: 'فتح الملف ‏', save: 'حفظ' };
const status = { ok: '✔️', warn: '⚠️', love: '❤️', family: '👨‍👩‍👧' };
const icons = { gear: '', save: '', open: '' };
const g = new Function('return this')();
module.exports = { activate() { return [zh, ar, status, icons, g]; } };
