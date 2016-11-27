package com.baxauli.byz;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.io.IOUtils;

/**
 *
 * Nó representando um nó Lieutenant. <br>
 * A ideia é que este nó seja executado de maneira autônoma em seu próprio
 * processo e se comunique com os nós lieutenant e com o Nó General por meio de
 * mensagens de rede.
 *
 * A estratégia para resolução do problema dos Generais Bizantinos será
 * utilizando mensagens assinadas digitalmente.
 *
 * Para a geração de keypairs para a assinatura digital, pode ser utilizada o
 * programa autonomo KeyGenerator.
 *
 * O nó general assina sua mensagem com sua private key e os nós Lieutenant
 * podem verificar se a mensagem veio realmente do general de forma intacta
 * através da sua public key. Todos os nós possuem as public keys de todos os
 * outros nós, mas cada nó só tem acesso a sua private key.
 *
 * Ao repassar a mensagem do general para o nó Lieutenant adjacente, este
 * primeiro nó precisará manter a mensagem e assinatura recebida do General e
 * repassar a mesma mensagem para o nó adjacente. Desta forma podemos
 * identificar a fonte que originou informações erradas e identificar o traidor,
 * mesmo se ele for o próprio general.
 *
 * @author Marcelo Baxauli <mlb122@hotmail.com>
 *
 */
public class LieutenantNodeMain {

    private static final String NODES_URL_FILENAME = "url_nodes" + File.separator + "url_nodes.properties";
    private static final int NUMBER_OF_LIEUTENANT = 5; // tem que bater com o número de nós no arquivo

    private List<LieutenantAddress> lieutenantAddress = new ArrayList<LieutenantAddress>();

    private PrivateKey privateKey = null;
    private Map<String, PublicKey> publicKeys = new HashMap<String, PublicKey>();
    private HonestyState honestyState = HonestyState.HONEST; // padrão

    private ServerSocket serverSocket;

    private String nodeName;

    private int portNumber;

    private List<LieutenantAddress> others = new ArrayList<LieutenantAddress>(); // O outro Lieutenant, os Lieutenant precisam trocar mensagens entre sí também.
    // A ideia é que este other possa ser extendido para uma lista de 'others' em um esquema
    // com mais Lieutenants.

    private Map<String, SignedOrder> orderTable = new HashMap<String, SignedOrder>();

    private List<String> dishonestNodes = new ArrayList<String>();

    public LieutenantNodeMain(String privateKeyFileName, String nodeName, String honesty) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.nodeName = nodeName;

        if (privateKeyFileName == null || privateKeyFileName.isEmpty()) {
            throw new IllegalArgumentException("Invalid private key");
        }

        if (nodeName == null || nodeName.isEmpty()) {
            throw new IllegalArgumentException("Invalid node name");
        }

        honesty = honesty.toLowerCase();
        if (honesty == null || honesty.isEmpty() || (!honesty.equals("honest") && !honesty.equals("dishonest"))) {
            throw new IllegalArgumentException("Invalid honesty argument");
        }

        FileInputStream privateKeyFile = new FileInputStream(privateKeyFileName);
        byte[] privateKeyBytes = new byte[privateKeyFile.available()];
        privateKeyFile.read(privateKeyBytes);
        privateKeyFile.close();

        KeyFactory keyFactory = KeyFactory.getInstance("DSA");

        this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        if (honesty.equals("honest")) {
            this.honestyState = HonestyState.HONEST;
        } else {
            this.honestyState = HonestyState.DISHONEST;
        }

        System.out.println("node name: " + nodeName);
        System.out.println("private key bytes: " + Arrays.toString(privateKeyBytes));
        System.out.println("honesty: " + honestyState);
    }

    public void init() throws Exception {
        loadNodesUrl();
        createOrderTable();
        loadPublicKeys();
        serverSocket = new ServerSocket(portNumber);
    }

    private void loadNodesUrl() throws Exception {

        Properties urlsProperties = new Properties();
        InputStream in = LieutenantNodeMain.class.getClassLoader().getResourceAsStream(NODES_URL_FILENAME);
        urlsProperties.load(in);

        LieutenantAddress lieutenantAddress;
        String lieutenant;
        String url;
        String port;
        for (int i = 1; i <= NUMBER_OF_LIEUTENANT; i++) {

            lieutenant = urlsProperties.getProperty("lieutenant" + i);
            url = lieutenant.split(":")[0];
            port = lieutenant.split(":")[1];

            lieutenantAddress = new LieutenantAddress(url, port, "lieutenant" + i);
            this.lieutenantAddress.add(lieutenantAddress);

            if (nodeName.equals("lieutenant" + i)) {
                this.portNumber = lieutenantAddress.getPort();
            } else {
                this.others.add(lieutenantAddress); // neste contexto temos apenas 2 nós lieutenant. Mas o modelo
                // pode ser expandido para mais nós.
            }

        }

    }

    private void createOrderTable() {

        orderTable.put("general", null);

        for (LieutenantAddress lieutenantAddress : lieutenantAddress) {
            orderTable.put(lieutenantAddress.getNodeName(), null);
        }
    }

    private void loadPublicKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        InputStream generalPublicKeyStream = LieutenantNodeMain.class
                .getClassLoader().getResourceAsStream("public_keys" + File.separator + "general");
        InputStream lieutenant1PublicKeyStream = LieutenantNodeMain.class
                .getClassLoader().getResourceAsStream("public_keys" + File.separator + "lieutenant1");
        InputStream lieutenant2PublicKeyStream = LieutenantNodeMain.class
                .getClassLoader().getResourceAsStream("public_keys" + File.separator + "lieutenant2");
        InputStream lieutenant3PublicKeyStream = LieutenantNodeMain.class
                .getClassLoader().getResourceAsStream("public_keys" + File.separator + "lieutenant3");
        InputStream lieutenant4PublicKeyStream = LieutenantNodeMain.class
                .getClassLoader().getResourceAsStream("public_keys" + File.separator + "lieutenant4");
        InputStream lieutenant5PublicKeyStream = LieutenantNodeMain.class
                .getClassLoader().getResourceAsStream("public_keys" + File.separator + "lieutenant5");

        byte[] generalPublickKeyBytes = IOUtils.toByteArray(generalPublicKeyStream);
        byte[] lieutenant1PublickKeyBytes = IOUtils.toByteArray(lieutenant1PublicKeyStream);
        byte[] lieutenant2PublickKeyBytes = IOUtils.toByteArray(lieutenant2PublicKeyStream);
        byte[] lieutenant3PublickKeyBytes = IOUtils.toByteArray(lieutenant3PublicKeyStream);
        byte[] lieutenant4PublickKeyBytes = IOUtils.toByteArray(lieutenant4PublicKeyStream);
        byte[] lieutenant5PublickKeyBytes = IOUtils.toByteArray(lieutenant5PublicKeyStream);

        KeyFactory keyFactory = KeyFactory.getInstance("DSA");

        PublicKey generatePublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(generalPublickKeyBytes));
        PublicKey lieutenant1PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(lieutenant1PublickKeyBytes));
        PublicKey lieutenant2PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(lieutenant2PublickKeyBytes));
        PublicKey lieutenant3PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(lieutenant3PublickKeyBytes));
        PublicKey lieutenant4PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(lieutenant4PublickKeyBytes));
        PublicKey lieutenant5PublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(lieutenant5PublickKeyBytes));

        publicKeys.put("general", generatePublicKey);
        publicKeys.put("lieutenant1", lieutenant1PublicKey);
        publicKeys.put("lieutenant2", lieutenant2PublicKey);
        publicKeys.put("lieutenant3", lieutenant3PublicKey);
        publicKeys.put("lieutenant4", lieutenant4PublicKey);
        publicKeys.put("lieutenant5", lieutenant5PublicKey);

    }

    private void run() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Sobe nó e espera comando do general e dos outros lieutenants, após receber o comando do general repassa
        // a ordem para os outros nós lieutenants.

        int attackCounter;
        int retreatCounter;
        while (true) {

            attackCounter = 0;
            retreatCounter = 0;

            System.out.println(String.format("%s is up and is %s.", nodeName, honestyState));
            System.out.println(String.format("Waiting connection on localhost:%d...", portNumber));

            Socket socket = null;
            InputStream in = null;
            OutputStream out = null;
            try {
                serverSocket.setSoTimeout(0);
                socket = serverSocket.accept();

                in = socket.getInputStream();
                out = socket.getOutputStream();

                PrintWriter writer = new PrintWriter(out);
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));

                String receivedMessage = reader.readLine();

                // Se for uma mensagem de teste responde um ack pra sinalizar que este
                // nó está up.
                if (receivedMessage.equals("test")) {
                    writer.println("ack");
                    writer.flush();
                } else if (receivedMessage.startsWith("attack") || receivedMessage.startsWith("retreat")) {
                    // mensagem real

                    System.out.println("Received message: " + receivedMessage);

                    // NUMBER OF LIEUTENANT: Número máximo de mensagens que virão par essa sessão (corresponde ao número de nós lieutenant na rede).
                    // Considerando que o General participa desta contagem, o meu nó não e a mensagem de um dos nós acabou de ser recebida.
                    for (int i = 1; i <= NUMBER_OF_LIEUTENANT; i++) {

                        socket.setSoTimeout(3000); // Timeout de 3 segundos para o recebimento das demais ordens após o recebimento da primeira ordem

                        if (receivedMessage.split(",").length > 1) {
                            // lieuntent
                            // Essa mensagem é composta pois possui a mensagem do general
                            // mais o repasse dos outros lientent. Essas duas ordens precisam ser iguais, caso
                            // contrário o lientent que repassou está mentindo.

                            String[] messages = receivedMessage.split(",");

                            String commonOrder = null;
                            System.out.println("Processing each message...");
                            // Percorre esse chain de ordens a partir da ordem mais "antiga" (que corresponde a primeira ordem do general)
                            for (int j = messages.length - 1; j >= 0; j--) {

                                String message = messages[j];

                                System.out.println("part: " + message);

                                String[] split = message.split(":");
                                String rcvdOrder = split[0];
                                String sender = split[1];
                                String signatureBase64 = split[2];
                                SignedOrder signedOrder = new SignedOrder(rcvdOrder, signatureBase64);

                                // checa assinatura
                                boolean verify = checkSignature(rcvdOrder, sender, signatureBase64);

                                if (verify == false) {
                                    throw new IllegalStateException("Error: received signature and"
                                            + " locally computed signature do not match, message has been tempered. Aborting");
                                }

                                // verifica se esse chain de ordens recebidas contém todos a mesma ordem (attack ou retreat), caso contrário o nó que difere
                                // é desonesto
                                if (commonOrder == null) {
                                    commonOrder = rcvdOrder;

                                    // confere se a ordem do nó já foi registrada anteriormente e se confere com a ordem
                                    // que ele está mandando agora.
                                    if (orderTable.get(sender) != null) {
                                        if (!orderTable.get(sender).equals(signedOrder)) {
                                            // signature válida mas voto incosistente, esse nó é desonesto
                                            dishonestNodes.add(sender);
                                        }
                                    } else {
                                        orderTable.put(sender, signedOrder);
                                    }

                                } else {
                                    if (commonOrder.equals(rcvdOrder)) {
                                        // Ordem consistente

                                        if (orderTable.get(sender) != null) {
                                            if (!orderTable.get(sender).equals(signedOrder)) {
                                                // signature válida mas voto incosistente, esse nó é desonesto
                                                dishonestNodes.add(sender);
                                            }
                                        } else {
                                            orderTable.put(sender, signedOrder);
                                        }

                                    } else {
                                        // Ordem difere do resto do chain, sender é desonesto

                                        dishonestNodes.add(sender);

                                    }
                                }
                            }

                        } else {
                            // general

                            String[] split = receivedMessage.split(":");
                            String order = split[0];
                            String sender = split[1];
                            String signatureBase64 = split[2];
                            SignedOrder signedOrder = new SignedOrder(order, signatureBase64);

                            if (!sender.equals("general")) {
                                // alguma coisa errada
                                throw new IllegalStateException("Inconsistent message, single order but not from general: " + receivedMessage);
                            }

                            boolean verify = checkSignature(order, sender, signatureBase64);

                            if (verify == false) {
                                throw new IllegalStateException("Error: received signature and"
                                        + " locally computed signature do not match, message has been tempered. Aborting");
                            }

                            // Registrar a ordem do general na tabela de votos,
                            // verificando antes se a ordem deste general já foi registrado anteriormente
                            // e se bate com esta.
                            if (orderTable.get(sender) != null) {
                                if (!orderTable.get(sender).equals(signedOrder)) {
                                    // signature válida mas voto incosistente, esse nó é desonesto
                                    dishonestNodes.add(sender);
                                }
                            } else {
                                orderTable.put(sender, signedOrder);
                            }

                            // agora tenho que repassar essa ordem do general pros outros nós Lieutenants
                            sendReceivedOrderToPeers(order, receivedMessage);
                        }

                        if (i != NUMBER_OF_LIEUTENANT) {

                            try {
                                serverSocket.setSoTimeout(3000); // Timeout de 3 segundos pra esperar as mensagens dos outros Lieutenants.
                                socket = serverSocket.accept();

                                reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                            } catch (SocketTimeoutException e) {
                                throw new SocketTimeoutException("One or more nodes did not sent messages");
                            }

                            receivedMessage = reader.readLine();

                            System.out.println("Received message: " + receivedMessage);
                        }
                    }

                }

            } catch (SocketTimeoutException e) {

                System.out.println("Error: " + e.getMessage());

            } finally {

                if (socket != null) {
                    socket.close();
                }

            }

            // Ao final do recebimento das mensagens eu percorro o map de registro de ordens.
            // Eu preciso contar o número de votos e decidir qual é a ordem mais "sugerida",
            // descartando as sugestões dos nós desonestos.
            // Se o próprio general for desonesto eu mantenho a "decisao" padrão de 'retreat'
            if (dishonestNodes.contains("general")) {
                System.out.println("general is dishonest.");
                System.out.println("Retreat!");
            } else {

                for (Entry<String, SignedOrder> entry : orderTable.entrySet()) {

                    String entryNodeName = entry.getKey();
                    SignedOrder entryOrder = entry.getValue();

                    if (entryOrder != null && !dishonestNodes.contains(entryNodeName)) {
                        if (entryOrder.getOrder().equals("attack")) {
                            attackCounter++;
                        } else if (entryOrder.getOrder().equals("retreat")) {
                            retreatCounter++;
                        }
                    }

                }

                for (String dishonestNodeName : dishonestNodes) {
                    System.out.println(dishonestNodeName + " is dishonest.");
                }

                if (this.honestyState == HonestyState.DISHONEST) {
                    System.out.println("Plan: Whatever, I'm a traitor.");
                } else {
                    if (attackCounter > retreatCounter) {
                        System.out.println("Plan: Attack!");
                    } else {
                        System.out.println("Plan: Retreat!");
                    }
                }

                this.orderTable.clear();
                this.dishonestNodes.clear();

            }

        }

    }

    public static void main(String[] args) throws Exception {

        boolean argumentError = false;
        // Usuário passa a private key deste nó (nome e path do arquivo) 
        // por command line argument
        if (args.length < 1) {
            System.out.println("Error: Private key file is missing from argument 1.");
            argumentError = true;
        }

        if (args.length < 2) {
            System.out.println("Error: Node name is missing from argument 2.");
            argumentError = true;
        }

        if (args.length < 3) {
            System.out.println("Error: Honesty is missing from argument 3.");
            argumentError = true;
        }

        if (argumentError) {
            throw new IllegalArgumentException("Usage: java -jar [path]/liuetenant-node-exec-[$version].jar [private-key-file-name] "
                    + "[node-name:{general,lieuterant1,lieuterant2...}] [node-honesty:{honest,dishonest}]");
        }

        // ignorando exceptions...
        LieutenantNodeMain generalNode = new LieutenantNodeMain(args[0], args[1], args[2]);
        generalNode.init();
        generalNode.run();
    }

    private void sendMessage(String message, List<LieutenantAddress> targets) throws IOException {

        Socket socket = null;

        for (LieutenantAddress target : targets) {
            try {
                if (!target.getNodeName().equals(this.nodeName)) {
                    socket = new Socket(target.getUrl(), target.getPort());

                    PrintWriter writer = new PrintWriter(socket.getOutputStream());

                    System.out.printf("Sending message %s to %s\n", message, target);
                    writer.println(message);
                    writer.flush();

                    writer.close();
                }

            } catch (Exception e) {

                System.out.printf("Error sending message to %s: [%s]\n", target, e.getMessage());

            } finally {
                if (socket != null) {
                    socket.close();
                }
            }

        }

    }

    private boolean checkSignature(String rcvdOrder, String sender, String signatureBase64) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        byte[] receivedSignatureBytes = DatatypeConverter.parseBase64Binary(signatureBase64);

        // Recupera a chave pública do nó que enviou a mensagem
        PublicKey publicKey = publicKeys.get(sender);
        if (publicKey == null) {
            throw new IllegalArgumentException("Invalid sender: " + sender);
        }

        Signature localSignature = Signature.getInstance("DSA");

        localSignature.initVerify(publicKey);
        localSignature.update(rcvdOrder.getBytes());

        // Confere se assinatura digital bate
        boolean verify = localSignature.verify(receivedSignatureBytes);

        return verify;

    }

    public void sendReceivedOrderToPeers(String order, String originalMessage) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

        String orderToSend;
        if (this.honestyState == HonestyState.HONEST) {
            // Se honesto vai enviar exatamente a ordem que recebeu do general para os outros
            // Lieutenants.

            orderToSend = order;

        } else {
            // Caso contrário vai enviar o oposto da ordem que recebeu do general para os outros
            // Lieutenants.

            orderToSend = (order.equals("attack")) ? "retreat" : "attack";

        }

        // Assina a mensagem
        Signature signatureHelper = Signature.getInstance("DSA");
        signatureHelper.initSign(this.privateKey);

        signatureHelper.update(orderToSend.getBytes());
        byte[] signature = signatureHelper.sign();

        System.out.println("signature: " + Arrays.toString(signature));

        // passa a assinatura pra Base64 pra concatenar ao final da mensagem como texto.
        String newSignatureBase64 = DatatypeConverter.printBase64Binary(signature);

        String message = String.format("%s:%s:%s", orderToSend, this.nodeName, newSignatureBase64);

        // Adiciona a mensagem anterior do general na íntegra ao final desta mensagem
        message += "," + originalMessage;

        // manda a mensagem para os outros lieutenants
        sendMessage(message, this.others);

    }

}
