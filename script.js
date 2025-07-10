const btnEncrypt = document.getElementById('btnEncrypt');
const btnDecrypt = document.getElementById('btnDecrypt');
const modeSelect = document.getElementById('mode');
const paddingSelect = document.getElementById('padding');
const paddingContainer = document.getElementById('paddingContainer');
const tagLengthContainer = document.getElementById('tagLengthContainer');
const logTime = document.getElementById('logTime');  // Elemen untuk log waktu proses

function updateUIForMode() {
  const selectedMode = modeSelect.value;
  if (selectedMode === "GCM") {
    paddingContainer.style.display = "none";
    tagLengthContainer.style.display = "block";
    paddingSelect.disabled = true;
    paddingSelect.style.opacity = 0.5;
  } else {
    paddingContainer.style.display = "block";
    tagLengthContainer.style.display = "none";
    paddingSelect.disabled = false;
    paddingSelect.style.opacity = 1;
  }
}

updateUIForMode();
modeSelect.addEventListener("change", updateUIForMode);

btnEncrypt.addEventListener('click', () => handleAES(true));
btnDecrypt.addEventListener('click', () => handleAES(false));

async function handleAES(isEncrypt = true) {
  const action = isEncrypt ? "ENKRIPSI" : "DEKRIPSI";
  const startTime = performance.now();  // Mulai hitung waktu dengan lebih presisi

  const input = document.getElementById('input').value.trim();
  const keyText = document.getElementById('key').value.trim();
  const ivText = document.getElementById('iv').value.trim();
  const keySize = parseInt(document.getElementById('keySize').value);
  const mode = modeSelect.value;
  const padding = paddingSelect.value;
  const format = document.querySelector('input[name="format"]:checked').value;
  const outputField = document.getElementById("output");

  if (!input || !keyText) {
    alert("Teks dan kunci harus diisi!");
    return;
  }

  if ((keySize === 128 && keyText.length !== 16) ||
    (keySize === 192 && keyText.length !== 24) ||
    (keySize === 256 && keyText.length !== 32)) {
    alert(`Kunci harus ${keySize / 8} karakter untuk AES-${keySize}.`);
    return;
  }

  if (mode !== 'ECB' && ivText.length !== 16) {
    alert("IV harus 16 karakter (atau 12 byte untuk GCM).");
    return;
  }

  try {
    let result;
    if (mode === 'GCM') {
      const tagLength = parseInt(document.getElementById('tagLength').value);
      result = isEncrypt
        ? await encryptGCM(input, keyText, ivText, tagLength)
        : await decryptGCM(input, keyText, ivText, tagLength);
    } else {
      result = isEncrypt
        ? encryptClassic(input, keyText, ivText, mode, padding, format)
        : decryptClassic(input, keyText, ivText, mode, padding, format);
    }

    outputField.value = result;

    // Menghitung durasi dan menampilkannya dengan lebih detail
    const endTime = performance.now();  // Waktu selesai
    const duration = (endTime - startTime);  // Waktu dalam milidetik
    logTime.textContent = `Waktu Proses: ${duration.toFixed(3)} ms`;  // Menampilkan waktu dengan 3 angka desimal
  } catch (err) {
    outputField.value = `[ERROR] ${err.message}`;
    logTime.textContent = "Waktu Proses: Gagal";  // Menampilkan error jika ada
  }
}

// ========== GCM ==========

async function encryptGCM(plaintext, keyText, ivText, tagLength = 128) {
  const enc = new TextEncoder();
  const keyData = enc.encode(keyText);
  const iv = enc.encode(ivText);
  const data = enc.encode(plaintext);

  const key = await crypto.subtle.importKey("raw", keyData, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength }, key, data);

  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function decryptGCM(ciphertextB64, keyText, ivText, tagLength = 128) {
  const enc = new TextEncoder();
  const keyData = enc.encode(keyText);
  const iv = enc.encode(ivText);
  const ciphertext = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey("raw", keyData, "AES-GCM", false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength }, key, ciphertext);

  return new TextDecoder().decode(decrypted);
}

// ========== MODE LAIN ==========

function encryptClassic(plaintext, keyText, ivText, mode, padding, format) {
  const key = CryptoJS.enc.Utf8.parse(keyText);
  const iv = CryptoJS.enc.Utf8.parse(ivText);

  const options = {
    mode: CryptoJS.mode[mode],
    padding: CryptoJS.pad[padding]
  };
  if (mode !== "ECB") options.iv = iv;

  const encrypted = CryptoJS.AES.encrypt(plaintext, key, options);

  return format === "Hex"
    ? encrypted.ciphertext.toString(CryptoJS.enc.Hex)
    : encrypted.toString();
}

function decryptClassic(ciphertext, keyText, ivText, mode, padding, format) {
  const key = CryptoJS.enc.Utf8.parse(keyText);
  const iv = CryptoJS.enc.Utf8.parse(ivText);

  const options = {
    mode: CryptoJS.mode[mode],
    padding: CryptoJS.pad[padding]
  };
  if (mode !== "ECB") options.iv = iv;

  let encryptedData;
  if (format === "Hex") {
    encryptedData = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Hex.parse(ciphertext)
    });
  } else {
    encryptedData = ciphertext;
  }

  const decrypted = CryptoJS.AES.decrypt(encryptedData, key, options);
  return decrypted.toString(CryptoJS.enc.Utf8) || "[DEKRIPSI GAGAL atau format salah]";
}
