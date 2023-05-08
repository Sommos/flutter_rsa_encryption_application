import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';

// function to generate an RSA key pair
FortunaRandom getSecureRandom() {
  // initialize a secure random number generator
  final secureRandom = FortunaRandom();
  // generate a random seed for the generator
  final randomSeed = Uint8List(32);
  // generate a random seed for the generator
  final random = Random.secure();
  // generate a random seed for the generator
  for (var i = 0; i < randomSeed.length; i++) {
    randomSeed[i] = random.nextInt(255);
  } 
  // seed the generator with the random seed
  secureRandom.seed(KeyParameter(randomSeed));
  // return the secure random number generator
  return secureRandom;  
}

// generates an RSA key pair with the given `keyLength` using the given `secureRandom` number generator.
AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRSAKeyPair(
  SecureRandom secureRandom,
  int keyLength,
) {
  // initialize a key generator.
  final rsaKeyGenerator = RSAKeyGenerator()..init(ParametersWithRandom(
      RSAKeyGeneratorParameters(
        BigInt.from(65537), 
        keyLength, 
        64,
      ),
      secureRandom,
    ));
  // generate an RSA key pair.
  final rsaKeyPair = rsaKeyGenerator.generateKeyPair();
  final publicKey = rsaKeyPair.publicKey as RSAPublicKey;
  final privateKey = rsaKeyPair.privateKey as RSAPrivateKey;
  // return the RSA key pair.
  return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(publicKey, privateKey);
}

// encrypts the given `message` using the given `publicKey`.
String rsaEncrypt(String message, RSAPublicKey publicKey) {
  // convert the message to a list of bytes.
  final messageBytes = Uint8List.fromList(message.codeUnits);
  // initialize an RSA encryptor.
  final rsaEncryptor = RSAEngine()..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
  // encrypt the message.
  final encryptedMessageBytes = rsaEncryptor.process(messageBytes);
  // convert the encrypted message to a string.
  final encryptedMessage = String.fromCharCodes(encryptedMessageBytes.toList());
  // return the encrypted message.
  return encryptedMessage;
}

// decrypts the given `encryptedMessage` using the given `privateKey`.
String rsaDecrypt(String encryptedMessage, RSAPrivateKey privateKey) {
  // convert the encrypted message to a list of bytes.
  final encryptedMessageBytes = Uint8List.fromList(encryptedMessage.codeUnits);
  // initialize an RSA decryptor.
  final rsaDecryptor = RSAEngine()..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
  // decrypt the message.
  final decryptedMessageBytes = rsaDecryptor.process(encryptedMessageBytes);
  // convert the decrypted message to a string.
  final decryptedMessage = String.fromCharCodes(decryptedMessageBytes.toList());
  // return the decrypted message.
  return decryptedMessage;
}