import 'package:flutter/material.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';

import '../models/encrypt.dart';
import '../components/text_field.dart';

void main() {
  // run app
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    // build app
    return const MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Home(),
    );
  }
}

class Home extends StatefulWidget {
  const Home({super.key});

  @override
  _HomeState createState() => _HomeState();
}

class _HomeState extends State<Home> {
  @override
  Widget build(BuildContext context) {
    encryptMessage(TextEditingController controller) {
      // initialize a secure random number generator
      final secureRandom = getSecureRandom();
      // generate an RSA key pair
      AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> rsaKeyPair = generateRSAKeyPair(secureRandom, 256);
      // encrypt the message and return it as a string
      return rsaEncrypt(controller.text, rsaKeyPair.publicKey);
    }

    // text field controller
    TextEditingController controller = TextEditingController();
    encryptMessage(controller);

    // build ui
    return Scaffold(
      backgroundColor: Colors.grey[300],
      appBar: AppBar(
        title: const Text('Flutter RSA Encryption Application'),
        centerTitle: true,
      ),
      body: SingleChildScrollView(
        child: SafeArea(
          child: Center(
            child: Column(
              mainAxisSize: MainAxisSize.max,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const SizedBox(height: 25.0),

                const Text(
                  'Enter a message to encrypt:',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                  ),
                ),

                const SizedBox(height: 25.0),

                MyTextField(
                  controller: controller,
                  hintText: "Message",
                  obscureText: false,
                ),
                
                Text(encryptMessage(controller)),
              ],
            ),
          ),
        ),
      ),
    );
  }
}