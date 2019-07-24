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
        validate(txIns, txOuts);
        try {
            // address validation
            String address = txIns[0].getAddress();
            String publicKey = generatePublic(privateKey);
            if (!address.equals(publicKey)) {
                throw new TemtumSdkException("Address validation failed.");
            }

            long timestamp = new Date().getTime() / 1000;

            // generate id
            String id = generateId(txIns, txOuts, timestamp);

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

    private static void validate(TxIn[] txIns, TxOut[] txOuts) throws TemtumSdkException {
        if (txIns == null || txIns.length != 1) {
            throw new TemtumSdkException("Wrong input transactions count. Should be 1.");
        }
        if (txOuts == null || txOuts.length == 0 || txOuts.length > 2) {
            throw new TemtumSdkException("Wrong output transactions count. Should be at least 1, max 2.");
        }

        TxIn txIn = txIns[0];
        if (txIn == null) {
            throw new TemtumSdkException("Input is empty.");
        }
        Long inAmount = txIn.getAmount();
        if (inAmount == null || inAmount <= 0) {
            throw new TemtumSdkException("Wrong input amount.");
        }
        String inAddress = txIns[0].getAddress();
        if (inAddress == null || inAddress.isEmpty()) {
            throw new TemtumSdkException("Input address is not not provided.");
        }

        Long outAmount;
        if (txOuts.length != 1) {
            Long totalOutAmount = 0L;
            boolean matches = false;
            for (TxOut txOut : txOuts) {
                if (txOut == null) {
                    throw new TemtumSdkException("Output is empty.");
                }
                String outAddress = txOut.getAddress();
                if (outAddress == null || outAddress.isEmpty()) {
                    throw new TemtumSdkException("Output address is not not provided.");
                }
                boolean currentAddressMatchesInput = inAddress.equals(outAddress);
                if (!matches) {
                    matches = currentAddressMatchesInput;
                } else if (currentAddressMatchesInput) {
                    throw new TemtumSdkException("Only one of output addresses should match input address.");
                }
                Long amount = txOut.getAmount();
                if (amount == null || amount < 0) {
                    throw new TemtumSdkException("Wrong output amount.");
                }
                totalOutAmount = totalOutAmount + amount;
            }
            if (!matches) {
                throw new TemtumSdkException("One of output addresses should match input address.");
            }
            outAmount = totalOutAmount;
        } else {
            TxOut txOut = txOuts[0];
            if (txOut == null) {
                throw new TemtumSdkException("Output is empty.");
            }
            String outAddress = txOut.getAddress();
            if (outAddress == null || outAddress.isEmpty()) {
                throw new TemtumSdkException("Output address is not not provided.");
            }
            if (inAddress.equals(outAddress)) {
                throw new TemtumSdkException("Input and output addresses should be different.");
            }
            outAmount = txOut.getAmount();
            if (outAmount == null || outAmount < 0) {
                throw new TemtumSdkException("Wrong output amount.");
            }
        }

        if (!inAmount.equals(outAmount)) {
            throw new TemtumSdkException("Inputs don't match outputs.");
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

    private static String generateId(TxIn[] txIns, TxOut[] txOuts, long timestamp) throws TemtumSdkException {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA256);
            ObjectMapper mapper = new ObjectMapper();
            String txInsString = mapper.writeValueAsString(txIns);
            String txOutsString = mapper.writeValueAsString(txOuts);
            String gen = TRANSACTION_TYPE_REGULAR + timestamp + txInsString + txOutsString;
            byte[] idHash = digest.digest(gen.getBytes(StandardCharsets.UTF_8));
            return new String(Hex.encode(idHash));
        } catch (Exception e) {
            throw new TemtumSdkException(e);
        }
    }

    private static String generateHex(TxIn[] txIns, TxOut[] txOuts, long timestamp, String id) throws TemtumSdkException {
        try {
            Transaction transaction = new Transaction();
            transaction.setId(id);
            transaction.setTimestamp(timestamp);
            transaction.setTxIns(txIns);
            transaction.setTxOuts(txOuts);
            transaction.setType(TRANSACTION_TYPE_REGULAR);

            ObjectMapper mapper = new ObjectMapper();
            String transactionString = mapper.writeValueAsString(transaction);

            return new String(Hex.encode(transactionString.getBytes(StandardCharsets.UTF_8)));
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
