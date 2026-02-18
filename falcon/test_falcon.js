const fs = require('fs');
const Module = require('./falcon.js');
Module().then((falcon) => {
  const pkLen = 1025;
  const skLen = 1281;
  const sigMaxLen = 1067;
  const message = Buffer.from("hello from ZKNOX!");

  // Create a 32-byte seed
  const seed = Buffer.from("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "hex");
  console.log("🌱 Seed (hex):", seed.toString("hex"));

  // Allocate memory
  const pkPtr = falcon._malloc(pkLen);
  const skPtr = falcon._malloc(skLen);
  const seedPtr = falcon._malloc(seed.length);
  const msgPtr = falcon._malloc(message.length);
  falcon.HEAPU8.set(message, msgPtr);
  falcon.HEAPU8.set(seed, seedPtr);

  // Generate keypair from seed
  const keygenRet = falcon._zknox_crypto_sign_keypair_from_seed(pkPtr, skPtr, seedPtr, seed.length);
  if (keygenRet !== 0) {
    console.error("❌ Keygen failed.");
    return;
  }

  const publicKey = Buffer.from(falcon.HEAPU8.subarray(pkPtr, pkPtr + pkLen));
  console.log("🔑 Public Key (hex):", publicKey.toString("hex"));

  // Generate again from same seed — should be identical
  const pkPtr2 = falcon._malloc(pkLen);
  const skPtr2 = falcon._malloc(skLen);
  falcon._zknox_crypto_sign_keypair_from_seed(pkPtr2, skPtr2, seedPtr, seed.length);
  const publicKey2 = Buffer.from(falcon.HEAPU8.subarray(pkPtr2, pkPtr2 + pkLen));
  console.log("🔁 Deterministic check:", publicKey.equals(publicKey2) ? "✅ PASS" : "❌ FAIL");

  // Sign the message
  const signedMsgMaxLen = 2 + 40 + message.length + sigMaxLen;
  const signedMsgPtr = falcon._malloc(signedMsgMaxLen);
  const signedMsgLenPtr = falcon._malloc(8);
  const signRet = falcon._zknox_crypto_sign(
    signedMsgPtr,
    signedMsgLenPtr,
    msgPtr,
    BigInt(message.length),
    skPtr
  );
  if (signRet !== 0) {
    console.error("❌ Signing failed.");
    return;
  }

  function readUint64(ptr) {
    const low = falcon.HEAPU32[ptr >> 2];
    const high = falcon.HEAPU32[(ptr >> 2) + 1];
    return BigInt(high) << 32n | BigInt(low);
  }

  const sigLen = Number(readUint64(signedMsgLenPtr));
  const signedMessage = Buffer.from(falcon.HEAPU8.subarray(signedMsgPtr, signedMsgPtr + sigLen));
  console.log("✅ Signature generated.");
  console.log("🔐 Sig+Msg (hex):", signedMessage.toString("hex"));

  // Verify the message
  const recoveredMsgPtr = falcon._malloc(sigLen);
  const recoveredLenPtr = falcon._malloc(8);
  const verifyRet = falcon._zknox_crypto_sign_open(
    recoveredMsgPtr,
    recoveredLenPtr,
    signedMsgPtr,
    BigInt(sigLen),
    pkPtr
  );
  if (verifyRet === 0) {
    const recLen = Number(readUint64(recoveredLenPtr));
    const recoveredMessage = Buffer.from(falcon.HEAPU8.subarray(recoveredMsgPtr, recoveredMsgPtr + recLen));
    console.log("✅ Verification success.");
    console.log("📦 Recovered message:", recoveredMessage.toString());
    console.log("🧪 Match:", message.equals(recoveredMessage));
  } else {
    console.error("❌ Signature verification failed.");
  }

  // Free memory
  [pkPtr, skPtr, pkPtr2, skPtr2, seedPtr, msgPtr, signedMsgPtr, signedMsgLenPtr, recoveredMsgPtr, recoveredLenPtr]
    .forEach(ptr => falcon._free(ptr));
});