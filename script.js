// 1. Vigenère Standard
function vigenereEncrypt(plain, key) {
  const P = normalizeText(plain);
  const K = normalizeText(key);
  let C = '';
  for (let i = 0; i < P.length; i++) {
    const pi = P.charCodeAt(i) - 65;
    const ki = K.charCodeAt(i % K.length) - 65;
    C += String.fromCharCode(((pi + ki) % 26) + 65);
  }
  return C;
}

function vigenereDecrypt(cipher, key) {
  const C = normalizeText(cipher);
  const K = normalizeText(key);
  let P = '';
  for (let i = 0; i < C.length; i++) {
    const ci = C.charCodeAt(i) - 65;
    const ki = K.charCodeAt(i % K.length) - 65;
    P += String.fromCharCode(((ci - ki + 26) % 26) + 65);
  }
  return P;
}

// 2. Auto‑Key Vigenère
function autoKeyEncrypt(plain, key) {
  const P = normalizeText(plain);
  let K = normalizeText(key) + P;
  let C = '';
  for (let i = 0; i < P.length; i++) {
    const pi = P.charCodeAt(i) - 65;
    const ki = K.charCodeAt(i) - 65;
    C += String.fromCharCode(((pi + ki) % 26) + 65);
  }
  return C;
}

function autoKeyDecrypt(cipher, key) {
  const C = normalizeText(cipher);
  let K = normalizeText(key);
  let P = '';
  for (let i = 0; i < C.length; i++) {
    const ci = C.charCodeAt(i) - 65;
    const ki = K.charCodeAt(i) - 65;
    const pi = (ci - ki + 26) % 26;
    P += String.fromCharCode(pi + 65);
    K += String.fromCharCode(pi + 65);
  }
  return P;
}

// 3. Extended Vigenère (byte‑wise)
function extendedVigenereEncrypt(inputBytes, key) {
  let keyBytes = Array.from(key).map(c => c.charCodeAt(0));
  let output = new Uint8Array(inputBytes.length);
  for (let i = 0; i < inputBytes.length; i++) {
    output[i] = (inputBytes[i] + keyBytes[i % keyBytes.length]) % 256;
  }
  return output;
}

function extendedVigenereDecrypt(inputBytes, key) {
  let keyBytes = Array.from(key).map(c => c.charCodeAt(0));
  let output = new Uint8Array(inputBytes.length);
  for (let i = 0; i < inputBytes.length; i++) {
    output[i] = (inputBytes[i] - keyBytes[i % keyBytes.length] + 256) % 256;
  }
  return output;
}

// 4. Affine Cipher (a,b)
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x;
  return null;
}

function affineEncrypt(plain, a, b) {
  const P = normalizeText(plain);
  let C = '';
  for (let ch of P) {
    const x = ch.charCodeAt(0) - 65;
    C += String.fromCharCode(((a * x + b) % 26) + 65);
  }
  return C;
}

function affineDecrypt(cipher, a, b) {
  const C = normalizeText(cipher);
  const invA = modInverse(a, 26);
  if (invA === null) throw new Error('Affine a has no inverse mod 26');
  let P = '';
  for (let ch of C) {
    const y = ch.charCodeAt(0) - 65;
    P += String.fromCharCode(((invA * (y - b + 26)) % 26) + 65);
  }
  return P;
}

// 5. Playfair Cipher (5×5 square, I/J merged)
function generatePlayfairSquare(key) {
  key = normalizeText(key).replace(/J/g, 'I');
  const used = new Set();
  const square = [];
  for (let ch of key + "ABCDEFGHIKLMNOPQRSTUVWXYZ") {
    if (!used.has(ch)) {
      used.add(ch);
      square.push(ch);
    }
  }
  // into 5×5
  return Array.from({ length: 5 }, (_, i) => square.slice(i*5, i*5+5));
}

function findInSquare(square, ch) {
  for (let r = 0; r < 5; r++) {
    for (let c = 0; c < 5; c++) {
      if (square[r][c] === ch) return [r, c];
    }
  }
}

function playfairPrepare(text, encrypt=true) {
  text = normalizeText(text).replace(/J/g, 'I');
  const pairs = [];
  let i = 0;
  while (i < text.length) {
    let a = text[i];
    let b = text[i+1] || (encrypt ? 'X' : '');
    if (encrypt && a === b) {
      b = 'X';
      i++;
    } else {
      i += 2;
    }
    pairs.push([a, b]);
  }
  return pairs;
}

function playfairEncrypt(plain, key) {
  const square = generatePlayfairSquare(key);
  const pairs = playfairPrepare(plain, true);
  let C = '';
  for (let [a, b] of pairs) {
    let [r1,c1] = findInSquare(square, a);
    let [r2,c2] = findInSquare(square, b);
    if (r1 === r2) {
      C += square[r1][(c1+1)%5];
      C += square[r2][(c2+1)%5];
    } else if (c1 === c2) {
      C += square[(r1+1)%5][c1];
      C += square[(r2+1)%5][c2];
    } else {
      C += square[r1][c2];
      C += square[r2][c1];
    }
  }
  return C;
}

function playfairDecrypt(cipher, key) {
  const square = generatePlayfairSquare(key);
  const pairs = playfairPrepare(cipher, false);
  let P = '';
  for (let [a, b] of pairs) {
    let [r1,c1] = findInSquare(square, a);
    let [r2,c2] = findInSquare(square, b);
    if (r1 === r2) {
      P += square[r1][(c1+4)%5];
      P += square[r2][(c2+4)%5];
    } else if (c1 === c2) {
      P += square[(r1+4)%5][c1];
      P += square[(r2+4)%5][c2];
    } else {
      P += square[r1][c2];
      P += square[r2][c1];
    }
  }
  return P;
}

// 6. Hill Cipher (2×2)
function hillEncrypt(plain, matrix) {
  const P = normalizeText(plain);
  let C = '';
  for (let i = 0; i < P.length; i += 2) {
    const x1 = P.charCodeAt(i) - 65;
    const x2 = P.charCodeAt(i+1 || i) - 65;
    const y1 = (matrix[0]*x1 + matrix[1]*x2) % 26;
    const y2 = (matrix[2]*x1 + matrix[3]*x2) % 26;
    C += String.fromCharCode(y1+65) + String.fromCharCode(y2+65);
  }
  return C;
}

function hillDecrypt(cipher, matrix) {
  const C = normalizeText(cipher);
  const det = matrix[0]*matrix[3] - matrix[1]*matrix[2];
  const invDet = modInverse(det, 26);
  if (invDet === null) throw new Error('Hill matrix not invertible mod 26');
  // adjugate
  const invMatrix = [
    ( matrix[3]*invDet) %26,
    ((-matrix[1]+26)*invDet) %26,
    ((-matrix[2]+26)*invDet) %26,
    ( matrix[0]*invDet) %26
  ];
  let P = '';
  for (let i = 0; i < C.length; i += 2) {
    const y1 = C.charCodeAt(i) - 65;
    const y2 = C.charCodeAt(i+1 || i) - 65;
    const x1 = (invMatrix[0]*y1 + invMatrix[1]*y2) % 26;
    const x2 = (invMatrix[2]*y1 + invMatrix[3]*y2) % 26;
    P += String.fromCharCode(x1+65) + String.fromCharCode(x2+65);
  }
  return P;
}

// === Helper Functions ===

function normalizeText(text) {
  return text.toUpperCase().replace(/[^A-Z]/g, '');
}

function formatInGroups(text) {
  return text.match(/.{1,5}/g)?.join(' ') || text;
}

// === File Handling ===

function processFileInput() {
  const fileInput = document.getElementById("fileInput");
  const file = fileInput.files[0];
  if (!file) {
    alert("Pilih file untuk diunggah.");
    return;
  }

  const reader = new FileReader();
  reader.onload = function (e) {
    const content = e.target.result; // Read file content as text
    document.getElementById("textInput").value = content; // Display content in the text box
    fileInput.setAttribute("data-filename", file.name); // Store the file name in a custom attribute
  };
  reader.readAsText(file); // Read file as text
}

// Clear file name when text is edited
document.getElementById("textInput").addEventListener("input", function () {
  const fileInput = document.getElementById("fileInput");
  if (fileInput.getAttribute("data-filename")) {
    fileInput.removeAttribute("data-filename"); // Clear the stored file name
    fileInput.value = ""; // Reset the file input field
  }
});

// === Encryption and Decryption ===

function processEncryption() {
  const cipherType = document.getElementById("cipherSelect").value;
  const keyInput = document.getElementById("keyInput").value;
  const text = document.getElementById("textInput").value.trim(); // Get text from the text box
  const formatOpt = document.getElementById("cipherTextFormat").value;
  let result = '';

  if (!text) {
    alert("Masukkan teks atau unggah file terlebih dahulu.");
    return;
  }

  switch (cipherType) {
    case "vigenere":
      result = vigenereEncrypt(text, keyInput);
      break;
    case "autokey":
      result = autoKeyEncrypt(text, keyInput);
      break;
    case "extended":
      const bytes = new Uint8Array(Array.from(text).map(c => c.charCodeAt(0)));
      const encBytes = extendedVigenereEncrypt(bytes, keyInput);
      result = Array.from(encBytes).map(b => String.fromCharCode(b)).join('');
      break;
    case "affine":
      const [a, b] = keyInput.split(',').map(n => parseInt(n.trim()));
      result = affineEncrypt(text, a, b);
      break;
    case "playfair":
      result = playfairEncrypt(text, keyInput);
      break;
    case "hill":
      const mat = keyInput.split(',').map(n => parseInt(n.trim()));
      result = hillEncrypt(text, mat);
      break;
  }

  if (formatOpt === "group5") result = formatInGroups(result);
  document.getElementById("outputArea").value = result;
}

function processDecryption() {
  const cipherType = document.getElementById("cipherSelect").value;
  const keyInput = document.getElementById("keyInput").value;
  const text = document.getElementById("textInput").value.trim(); // Get text from the text box
  let result = '';

  if (!text) {
    alert("Masukkan teks atau unggah file terlebih dahulu.");
    return;
  }

  switch (cipherType) {
    case "vigenere":
      result = vigenereDecrypt(text, keyInput);
      break;
    case "autokey":
      result = autoKeyDecrypt(text, keyInput);
      break;
    case "extended":
      const bytes = new Uint8Array(Array.from(text).map(c => c.charCodeAt(0)));
      const decBytes = extendedVigenereDecrypt(bytes, keyInput);
      result = Array.from(decBytes).map(b => String.fromCharCode(b)).join('');
      break;
    case "affine":
      const [a2, b2] = keyInput.split(',').map(n => parseInt(n.trim()));
      result = affineDecrypt(text, a2, b2);
      break;
    case "playfair":
      result = playfairDecrypt(text, keyInput);
      break;
    case "hill":
      const mat2 = keyInput.split(',').map(n => parseInt(n.trim()));
      result = hillDecrypt(text, mat2);
      break;
  }

  document.getElementById("outputArea").value = result;
}

function downloadText() {
  const output = document.getElementById("outputArea").value;
  const blob = new Blob([output], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "hasil_cipher.txt";
  a.click();
  URL.revokeObjectURL(url);
}