package org.example;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class C_ECDSA {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    // 椭圆曲线参数
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256r1");
    private static final ECDomainParameters EC_PARAMS = new ECDomainParameters(
            CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    private static final BigInteger n = EC_PARAMS.getN();
    private static final ECPoint G = EC_PARAMS.getG();

    //===================== ECDSA实现 =====================
    static class ECDSAKeyPair {
        private BigInteger privateKey;
        private ECPoint publicKey;

        void generateKeyPair() {
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(EC_PARAMS, new SecureRandom());
            generator.init(keyGenParams);
            AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

            org.bouncycastle.crypto.params.ECPrivateKeyParameters privParams =
                    (org.bouncycastle.crypto.params.ECPrivateKeyParameters) keyPair.getPrivate();
            org.bouncycastle.crypto.params.ECPublicKeyParameters pubParams =
                    (org.bouncycastle.crypto.params.ECPublicKeyParameters) keyPair.getPublic();

            privateKey = privParams.getD();
            publicKey = pubParams.getQ();
        }

        BigInteger getPrivateKey() {
            return privateKey;
        }

        ECPoint getPublicKey() {
            return publicKey;
        }
    }

    static class ECDSASignature {
        private BigInteger r;
        private BigInteger s;

        ECDSASignature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        BigInteger getR() {
            return r;
        }

        BigInteger getS() {
            return s;
        }
    }

    static ECDSASignature sign(String message, ECDSAKeyPair keyPair) throws Exception {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, new org.bouncycastle.crypto.params.ECPrivateKeyParameters(
                keyPair.getPrivateKey(), EC_PARAMS));

        BigInteger e = hashMessage(message);
        BigInteger[] sig = signer.generateSignature(e.toByteArray());
        return new ECDSASignature(sig[0], sig[1]);
    }

    static boolean verify(ECPoint publicKey, String message, ECDSASignature signature) throws Exception {
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new org.bouncycastle.crypto.params.ECPublicKeyParameters(publicKey, EC_PARAMS));
        BigInteger e = hashMessage(message);
        return verifier.verifySignature(e.toByteArray(), signature.getR(), signature.getS());
    }

    //===================== SM3-OTS实现 =====================
    static class SM3OTS {
        private static final int HASH_CHAINS = 48;
        private static final int HASH_ITERATIONS = 255;
        private static final int SM3_DIGEST_SIZE = 32;

        static class KeyPair {
            byte[][] sk = new byte[HASH_CHAINS][SM3_DIGEST_SIZE];
            byte[][] pk = new byte[HASH_CHAINS][SM3_DIGEST_SIZE];

            void generateKeys(SecureRandom random) throws Exception {
                // 生成私钥
                for (int i = 0; i < HASH_CHAINS; i++) {
                    random.nextBytes(sk[i]);
                }
                // 生成公钥（私钥哈希255次）
                for (int i = 0; i < HASH_CHAINS; i++) {
                    byte[] current = sk[i].clone();
                    for (int j = 0; j < HASH_ITERATIONS; j++) {
                        current = SM3OTSSignature.sm3Hash(current);
                    }
                    pk[i] = current;
                }
            }
        }

        static class SM3OTSSignature {
            byte[][] sigBlocks = new byte[HASH_CHAINS][SM3_DIGEST_SIZE];

            static byte[] sign(byte[] message, KeyPair keyPair) throws Exception {
                SM3OTSSignature sig = new SM3OTSSignature();
                byte[] digest = sm3Hash(message);

                // 处理前32条链（二进制索引）
                for (int i = 0; i < 32; i++) {
                    int step = Byte.toUnsignedInt(digest[i]);
                    sig.sigBlocks[i] = hashChain(keyPair.sk[i], step);
                }

                // 处理后16条链（十六进制位置索引）
                String hexDigest = Hex.toHexString(digest);
                for (int i = 0; i < 16; i++) {
                    char targetChar = "0123456789ABCDEF".charAt(i);
                    int sum = 0;
                    for (int pos = 0; pos < hexDigest.length(); pos++) {
                        if (hexDigest.charAt(pos) == targetChar) {
                            sum += (pos + 1);
                        }
                    }
                    int step = sum % HASH_ITERATIONS;
                    int chainIndex = 32 + i;
                    sig.sigBlocks[chainIndex] = hashChain(keyPair.sk[chainIndex], step);
                }

                return flatten(sig.sigBlocks);
            }

            static boolean verify(byte[] message, byte[] signature, KeyPair keyPair) throws Exception {
                byte[][] sigBlocks = unflatten(signature);
                byte[] digest = sm3Hash(message);

                // 重构公钥
                byte[][] reconstructedPk = new byte[HASH_CHAINS][];

                // 验证前32条链
                for (int i = 0; i < 32; i++) {
                    int step = Byte.toUnsignedInt(digest[i]);
                    reconstructedPk[i] = hashChain(sigBlocks[i], HASH_ITERATIONS - step);
                }

                // 验证后16条链
                String hexDigest = Hex.toHexString(digest);
                for (int i = 0; i < 16; i++) {
                    char targetChar = "0123456789ABCDEF".charAt(i);
                    int sum = 0;
                    for (int pos = 0; pos < hexDigest.length(); pos++) {
                        if (hexDigest.charAt(pos) == targetChar) {
                            sum += (pos + 1);
                        }
                    }
                    int step = sum % HASH_ITERATIONS;
                    int chainIndex = 32 + i;
                    reconstructedPk[chainIndex] = hashChain(sigBlocks[chainIndex], HASH_ITERATIONS - step);
                }

                return Arrays.deepEquals(reconstructedPk, keyPair.pk);
            }

            private static byte[] hashChain(byte[] seed, int iterations) throws Exception {
                byte[] current = seed.clone();
                for (int i = 0; i < iterations; i++) {
                    current = sm3Hash(current);
                }
                return current;
            }

            private static byte[] sm3Hash(byte[] input) throws Exception {
                MessageDigest md = MessageDigest.getInstance("SM3", "BC");
                return md.digest(input);
            }

            private static byte[] flatten(byte[][] blocks) {
                byte[] result = new byte[HASH_CHAINS * SM3_DIGEST_SIZE];
                for (int i = 0; i < HASH_CHAINS; i++) {
                    System.arraycopy(blocks[i], 0, result, i * SM3_DIGEST_SIZE, SM3_DIGEST_SIZE);
                }
                return result;
            }

            private static byte[][] unflatten(byte[] data) {
                byte[][] blocks = new byte[HASH_CHAINS][SM3_DIGEST_SIZE];
                for (int i = 0; i < HASH_CHAINS; i++) {
                    System.arraycopy(data, i * SM3_DIGEST_SIZE, blocks[i], 0, SM3_DIGEST_SIZE);
                }
                return blocks;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        //===================== ECDSA流程 =====================
        String message = "Hello C-ECDSA!";
        double stime11 = System.currentTimeMillis();
        ECDSAKeyPair ecdsaKeyPair = new ECDSAKeyPair();
        ecdsaKeyPair.generateKeyPair();
        double etime11 = System.currentTimeMillis();

        double stime12 = System.currentTimeMillis();
        ECDSASignature ecdsaSignature = sign(message, ecdsaKeyPair);
        double etime12 = System.currentTimeMillis();

        double stime13 = System.currentTimeMillis();
        boolean ecdsaValid = verify(ecdsaKeyPair.getPublicKey(), message, ecdsaSignature);
        double etime13 = System.currentTimeMillis();
        System.out.println("ECDSA签名验证结果: " + ecdsaValid);
        
        //===================== SM3-OTS流程 =====================
        double stime21 = System.currentTimeMillis();
        SecureRandom secureRandom = new SecureRandom();
        SM3OTS.KeyPair sm3otsKeyPair = new SM3OTS.KeyPair();
        sm3otsKeyPair.generateKeys(secureRandom);
        double etime21 = System.currentTimeMillis();
        System.out.println("KeyGen运行时间为："+(etime11-stime11+etime21-stime21)+"毫秒");
        double stime22 = System.currentTimeMillis();
        byte[] sm3otsSignature = SM3OTS.SM3OTSSignature.sign(message.getBytes(), sm3otsKeyPair);
        double etime22 = System.currentTimeMillis();
        System.out.println("Sign运行时间为："+(etime12-stime12+etime22-stime22)+"毫秒");
        double stime23 = System.currentTimeMillis();
        boolean sm3otsValid = SM3OTS.SM3OTSSignature.verify(message.getBytes(), sm3otsSignature, sm3otsKeyPair);
        double etime23 = System.currentTimeMillis();
        System.out.println("SM3-OTS签名验证结果: " + sm3otsValid);
        System.out.println("Sign运行时间为："+(etime13-stime13+etime23-stime23)+"毫秒");


    }

    //===================== 工具方法 =====================
    private static BigInteger hashMessage(String message) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message.getBytes());
        return new BigInteger(1, hash).mod(n);
    }
}