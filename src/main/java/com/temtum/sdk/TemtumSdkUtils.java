package com.temtum.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Date;

public class TemtumSdkUtils {
    private static final String SECP256K1 = "secp256k1";
    private static final String SHA256 = "SHA-256";
    private static final ECNamedCurveParameterSpec SPEC = ECNamedCurveTable.getParameterSpec(SECP256K1);

    private static final String TRANSACTION_TYPE_REGULAR = "regular";

    public static String generatePublic(String privateKey) throws TemtumSdkException {
        if (privateKey == null) {
            throw new TemtumSdkException("Private key is not provided.");
        }
        byte[] publicKeyBytes = getPublicKeyBytes(privateKey);
        try {
            return Hex.toHexString(publicKeyBytes);
        } catch (Exception e) {
            throw new TemtumSdkException(e);
        }
    }

    public static String signTransaction(TxIn[] txIns, TxOut[] txOuts, String privateKey) throws TemtumSdkException {
        if (privateKey == null) {
            throw new TemtumSdkException("Private key is not provided.");
        }
        if (txIns == null || txIns.length == 0) {
            throw new TemtumSdkException("In transactions are not provided.");
        }
        if (txOuts == null) {
            throw new TemtumSdkException("Out transactions are not provided.");
        }
        try {
            // address validation
            String address = txIns[0].getAddress();
            String publicKey = generatePublic(privateKey);
            if (!address.equals(publicKey)) {
                throw new TemtumSdkException("Address validation failed.");
            }

            long timestamp = new Date().getTime() / 1000;

            // generate id
            String id = generateHex(txIns, txOuts, timestamp, null);

            // sign txIns
            for (TxIn txIn : txIns) {
                sign(txIn, id, privateKey);
            }

            // generate hex
            return generateHex(txIns, txOuts, timestamp, id);
        } catch (Exception e) {
            throw new TemtumSdkException(e);
        }
    }

    private static byte[] getPublicKeyBytes(String privateKey) throws TemtumSdkException {
        try {
            byte[] privateKeyBytes = Hex.decode(privateKey);
            ECPoint pointQ = SPEC.getG().multiply(new BigInteger(1, privateKeyBytes));
            return pointQ.getEncoded(true);
        } catch (Exception e) {
            throw new TemtumSdkException(e);
        }
    }

    private static String generateHex(TxIn[] txIns, TxOut[] txOuts, long timestamp, String id) throws TemtumSdkException {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA256);
            ObjectMapper mapper = new ObjectMapper();
            String txInsString = mapper.writeValueAsString(txIns);
            String txOutsString = mapper.writeValueAsString(txOuts);
            String gen = TRANSACTION_TYPE_REGULAR + timestamp + txInsString + txOutsString;
            if (id != null) {
                gen = gen + id;
            }
            byte[] idHash = digest.digest(gen.getBytes(StandardCharsets.UTF_8));
            return new String(Hex.encode(idHash));
        } catch (Exception e) {
            throw new TemtumSdkException(e);
        }
    }

    private static void sign(TxIn txIn, String id, String privateKey) throws TemtumSdkException {
        try {
            String key = getKey(txIn, id);
            BigInteger priv = new BigInteger(privateKey, 16);
            BigInteger pubKey = Sign.publicKeyFromPrivate(priv);
            ECKeyPair keyPair = new ECKeyPair(priv, pubKey);
            Sign.SignatureData signature = Sign.signMessage(Hex.decode(key), keyPair, false);
            String r = Hex.toHexString(signature.getR());
            String s = Hex.toHexString(signature.getS());
            String signatureHexString = r + s;
            txIn.setSignature(signatureHexString);
        } catch (Exception e) {
            throw new TemtumSdkException(e);
        }
    }

    private static String getKey(TxIn txIn, String id) throws TemtumSdkException {
        if (txIn == null) {
            throw new TemtumSdkException("In transaction is not provided.");
        }
        if (id == null) {
            throw new TemtumSdkException("Id is not provided.");
        }
        try {
            Integer txOutIndex = txIn.getTxOutIndex();
            String txOutId = txIn.getTxOutId(), address = txIn.getAddress();
            Long amount = txIn.getAmount();
            StringBuffer sb = new StringBuffer(id);
            if (txOutIndex != null) {
                sb.append(txOutIndex);
            }
            if (txOutId != null) {
                sb.append(txOutId);
            }
            if (amount != null) {
                sb.append(amount);
            }
            if (address != null) {
                sb.append(address);
            }
            String key = sb.toString();
            MessageDigest digest = MessageDigest.getInstance(SHA256);
            byte[] keyHash = digest.digest(key.getBytes(StandardCharsets.UTF_8));
            return new String(Hex.encode(keyHash));
        } catch (Exception e) {
            throw new TemtumSdkException(e);
        }
    }
}
