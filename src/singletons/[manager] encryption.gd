extends Node

func aes_encrypt(key: PackedByteArray, iv: PackedByteArray, plaintext: PackedByteArray) -> PackedByteArray:
	var aes := AESContext.new()
	if not aes.start(AESContext.MODE_CBC_ENCRYPT, key, iv):
		push_error("Failed to start AES encryption")
		return PackedByteArray()
	var encrypted := aes.update(plaintext)
	aes.finish()
	return encrypted

func aes_decrypt(key: PackedByteArray, iv: PackedByteArray, ciphertext: PackedByteArray) -> PackedByteArray:
	var aes := AESContext.new()
	if not aes.start(AESContext.MODE_CBC_DECRYPT, key, iv):
		push_error("Failed to start AES decryption")
		return PackedByteArray()
	var decrypted := aes.update(ciphertext)
	aes.finish()
	return decrypted
